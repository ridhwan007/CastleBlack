"""
OPAV (Observe–Plan–Act–Validate) loop.

This is the heartbeat of the platform — the main autonomous engine.
Runs as a blocking iterator inside `aiptt attack run`, cycling until:
  - Scope is exhausted
  - Time limit reached
  - Kill signal received (SIGTERM / SIGINT / admin kill)
"""

from __future__ import annotations

import signal
import time
from dataclasses import dataclass
from typing import Iterator

from aiptt.core.state_manager import SessionState
from aiptt.engine.ai_planner import AIPlannerEngine, AttackTask
from aiptt.guardrail.controller import GuardrailController
from aiptt.poe.capture import PoECapture
from aiptt.audit.logger import AuditLogger
from aiptt.core.event_bus import EventBus


@dataclass
class OPAVResult:
    """Yielded by OPAVLoop.run() for CLI progress reporting."""
    cycle: int
    phase: str           # OBSERVE | PLAN | ACT | VALIDATE
    subtask_id: str
    outcome: str         # SUCCESS | FAILURE | SKIPPED | HALTED
    finding_id: str | None
    elapsed_seconds: float


class OPAVLoop:
    """
    Core Observe–Plan–Act–Validate engine.

    Wires together:
      - SessionState      (scope, pivot tracking, credentials)
      - AIPlannerEngine   (Claude-powered attack planner)
      - GuardrailController (pre-task safety gate)
      - AttackRegistry    (module loader + sandboxed executor)
      - PoECapture        (artefact collection + vault storage)
      - AuditLogger       (HMAC-chained immutable log)
      - EventBus          (pub/sub for CLI output + integrations)
    """

    MAX_SAME_VECTOR_RETRIES = 3    # FR-ATK-01: no more than 3 retries per vector
    MAX_PIVOT_DEPTH         = 3    # FR-AI-03: pivot gate

    def __init__(
        self,
        state: SessionState,
        planner: AIPlannerEngine,
        guardrail: GuardrailController,
        registry,                  # AttackRegistry (imported lazily to avoid circulars)
        poe: PoECapture,
        audit: AuditLogger,
        bus: EventBus,
        max_pivots: int = 3,
    ):
        self.state     = state
        self.planner   = planner
        self.guardrail = guardrail
        self.registry  = registry
        self.poe       = poe
        self.audit     = audit
        self.bus       = bus
        self.max_pivots = max_pivots

        self._killed               = False
        self._retry_counter: dict[str, int] = {}

        # Wire kill-switch UNIX signals
        signal.signal(signal.SIGTERM, self._handle_kill)
        signal.signal(signal.SIGINT,  self._handle_kill)

    # ------------------------------------------------------------------
    # Main run loop
    # ------------------------------------------------------------------

    def run(self) -> Iterator[OPAVResult]:
        """
        Main OPAV loop. Yields OPAVResult after each subtask.
        Caller iterates and updates the CLI display.
        """
        cycle = self.state.cycle  # Restore from checkpoint if resuming

        while not self._killed and not self.state.is_scope_exhausted():

            # ── OBSERVE ──────────────────────────────────────────────
            self.audit.log_intent("OBSERVE_START", cycle=cycle)
            observations = (
                self.state.knowledge_graph.get_unexhausted_targets()
                if self.state.knowledge_graph else []
            )

            if not observations:
                self.bus.emit("zero_subtasks", cycle=cycle)
                break

            # ── PLAN ─────────────────────────────────────────────────
            self.audit.log_intent("PLAN_START", cycle=cycle)
            attack_queue = self.planner.score_and_queue(
                observations=observations,
                compromised=self.state.compromised_hosts,
                credentials=self.state.credential_cache,
                pivot_depth=self.state.pivot_count,
            )

            if not attack_queue:
                # FR-AI-01: zero subtasks → alert and halt
                self.audit.log_event("ZERO_SUBTASKS_ALERT", cycle=cycle)
                self.bus.emit("zero_subtasks", cycle=cycle)
                break

            # Pivot depth gate (FR-AI-03)
            if self.state.pivot_count >= self.max_pivots:
                self.bus.emit("hitl_gate_required",
                              reason="max_pivots_reached",
                              pivot_count=self.state.pivot_count)
                approved = self._wait_for_hitl_approval("MAX_PIVOT_DEPTH")
                if not approved:
                    self._killed = True
                    break
                self.state.reset_pivot_count()

            # ── ACT ──────────────────────────────────────────────────
            for task in attack_queue:
                if self._killed:
                    return

                start = time.time()

                # Pre-task guardrail check (FR-AI-04 — EVERY subtask)
                guardrail_result = self.guardrail.check(task)
                if not guardrail_result.passed:
                    self.audit.log_event(
                        "GUARDRAIL_BLOCKED",
                        task=task.id,
                        reason=guardrail_result.reason,
                        blocker=guardrail_result.blocker,
                    )
                    yield OPAVResult(
                        cycle, "ACT", task.id, "SKIPPED", None,
                        time.time() - start,
                    )
                    continue

                # Retry guard (FR-ATK-01: max 3 retries on same vector)
                retry_key = f"{task.target}:{task.module_id}"
                retries   = self._retry_counter.get(retry_key, 0)
                if retries >= self.MAX_SAME_VECTOR_RETRIES:
                    self.audit.log_event("MAX_RETRIES_SKIP", task=task.id,
                                          vector=retry_key)
                    continue
                self._retry_counter[retry_key] = retries + 1

                # Circular pivot detection (FR-AI-03 edge case)
                if (self.state.knowledge_graph
                        and self.state.knowledge_graph.has_visited_twice(task.target)):
                    self.audit.log_event("CIRCULAR_PIVOT_SKIP",
                                          target=task.target)
                    continue

                # Pre-action intent log (FR-AI-05: log BEFORE execution)
                self.audit.log_intent("EXEC_START", task=task.id,
                                       module=task.module_id,
                                       target=task.target)

                # Execute via AttackRegistry
                result = self.registry.execute(task)

                elapsed = time.time() - start
                self.audit.log_event("EXEC_COMPLETE", task=task.id,
                                      outcome=result.outcome,
                                      elapsed=elapsed)

                # ── VALIDATE ─────────────────────────────────────────
                if result.success:
                    poe_result = self.poe.capture(task, result)
                    finding    = self.state.record_finding(task, result, poe_result)

                    # Update knowledge graph
                    if self.state.knowledge_graph:
                        self.state.knowledge_graph.ingest_finding(finding)

                    # Track compromise
                    if result.gained_access:
                        self.state.add_compromised_host(task.target)
                        self.state.increment_pivot_count()

                    # Store credential refs
                    for cred in result.credentials_captured:
                        if "ref" in cred:
                            self.state.add_credential_ref(
                                cred["ref"], cred)

                    # Emit finding event for SIEM / ticket integrations
                    event_name = (
                        "finding_confirmed"
                        if poe_result.classification == "CONFIRMED"
                        else "finding_unconfirmed"
                    )
                    self.bus.emit(event_name,
                                  finding_id=getattr(finding, "id", None),
                                  severity=getattr(finding, "severity", "INFO"))

                    yield OPAVResult(
                        cycle, "VALIDATE", task.id, "SUCCESS",
                        getattr(finding, "id", None), elapsed,
                    )

                else:
                    # Record failure so planner doesn't re-queue
                    self.planner.record_failure(task)
                    yield OPAVResult(
                        cycle, "VALIDATE", task.id, "FAILURE", None, elapsed,
                    )

            cycle += 1
            self.state.update_cycle(cycle)

        self.audit.log_event("OPAV_COMPLETE", total_cycles=cycle,
                              compromised=len(self.state.compromised_hosts))

    # ------------------------------------------------------------------
    # Kill switch
    # ------------------------------------------------------------------

    def kill(self, reason: str = "manual") -> None:
        """Programmatic kill — used by admin kill command."""
        self.audit.log_event("KILL_SWITCH_ACTIVATED", reason=reason)
        self._killed = True
        self.bus.emit("kill_switch", reason=reason)

    def _handle_kill(self, signum, frame) -> None:
        """SIGTERM / SIGINT handler."""
        self.audit.log_event("KILL_SWITCH_ACTIVATED", signal=signum)
        self._killed = True
        self.bus.emit("kill_switch", signal=signum)

    # ------------------------------------------------------------------
    # Human-in-the-loop gate
    # ------------------------------------------------------------------

    def _wait_for_hitl_approval(self, reason: str) -> bool:
        """
        Block and prompt operator via CLI for HITL gate.
        Returns True (approved) or False (rejected → kill).
        """
        from rich.prompt import Confirm
        from rich import print as rprint

        rprint(f"\n[bold yellow]>>> HUMAN REVIEW REQUIRED: {reason}[/bold yellow]")
        rprint(
            "Review current findings with: "
            "[cyan]aiptt report technical --engagement-id ...[/cyan]"
        )
        try:
            approved = Confirm.ask("Approve continuation?", default=False)
        except (EOFError, KeyboardInterrupt):
            approved = False

        if approved:
            self.audit.log_event("HITL_APPROVED", reason=reason)
        else:
            self.audit.log_event("HITL_REJECTED", reason=reason)

        return approved
