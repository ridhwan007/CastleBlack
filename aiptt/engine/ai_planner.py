"""
LangGraph-based AI attack path planning engine.

FR-AI-01: Score and queue attack subtasks.
FR-AI-02: Maintain persistent state across OPAV cycles.
FR-AI-03: Adaptive re-planning when vectors fail.

Anthropic integration:
  - Uses langchain_anthropic.ChatAnthropic
  - Model: claude-sonnet-4-6 (from config)
  - API key: AIPTT_AI_API_KEY environment variable (passed explicitly)
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any

from aiptt.core.config import get_config
from aiptt.engine.path_scorer import PathScorer
from aiptt.engine.replan_engine import ReplanEngine


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class AttackTask:
    id: str
    target: str
    module_id: str
    technique: str              # MITRE ATT&CK ID (e.g. T1558.003)
    priority_score: float       # Impact × feasibility (0.0–1.0)
    parameters: dict
    depends_on: list[str] = field(default_factory=list)
    is_novel: bool = False      # True = AI-generated, not from library
    destructive: bool = False   # Carries manifest flag for blast radius gate

    def __post_init__(self):
        # Ensure parameters is always a dict
        if not isinstance(self.parameters, dict):
            self.parameters = {}


@dataclass
class PlannerState:
    """Persisted across OPAV cycles (FR-AI-02)."""
    observations: list[dict]
    compromised_hosts: list[str]
    credentials: list[dict]
    pivot_depth: int
    attack_queue: list[AttackTask] = field(default_factory=list)
    reasoning: str = ""
    cycle: int = 0
    failed_vectors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are an expert offensive security AI agent performing an authorised
internal penetration test. Your role is to plan the most efficient
attack path to high-value assets.

Rules you MUST follow:
1. Always prioritise RCE and CRITICAL/HIGH CVEs first (CVSS >= 7.0).
2. Never plan actions outside the provided in-scope IP list.
3. Never plan destructive actions (data deletion, encryption, DoS).
4. Log your reasoning step-by-step before recommending each action.
5. If you detect potential honeypot indicators, flag the host and skip.
6. Maximum {max_pivots} sequential pivots before flagging for human review.
7. Never re-queue vectors listed under "Previously failed attack vectors".

Return a JSON array of AttackTask objects ordered by priority score.
Each object must have these fields:
  id, target, module_id, technique, priority_score, parameters,
  depends_on (list), is_novel (bool)

Example:
[
  {{
    "id": "TASK-001",
    "target": "10.0.1.45",
    "module_id": "NET-RCE-001",
    "technique": "T1190",
    "priority_score": 0.94,
    "parameters": {{"port": 8443, "cve_id": "CVE-2024-1234", "service": "Apache"}},
    "depends_on": [],
    "is_novel": false
  }}
]
"""


# ---------------------------------------------------------------------------
# AI Planner Engine
# ---------------------------------------------------------------------------

class AIPlannerEngine:
    """
    LangGraph-based planning engine backed by Anthropic Claude.

    Maintains PlannerState across OPAV cycles (FR-AI-02).
    Implements adaptive re-planning via ReplanEngine (FR-AI-03).
    """

    def __init__(
        self,
        audit,
        scorer: PathScorer | None = None,
        replanner: ReplanEngine | None = None,
        max_pivots: int = 3,
    ):
        cfg = get_config()

        # Validate API key is present
        api_key_env = cfg.core.ai_api_key_env
        api_key = os.environ.get(api_key_env, "")
        if not api_key:
            raise EnvironmentError(
                f"Environment variable '{api_key_env}' is not set. "
                "Anthropic API key required for AI planning."
            )

        # ── Anthropic via langchain_anthropic ──────────────────────────
        from langchain_anthropic import ChatAnthropic
        self.llm = ChatAnthropic(
            model=cfg.core.ai_model,   # "claude-sonnet-4-6"
            api_key=api_key,           # AIPTT_AI_API_KEY
            max_tokens=4096,
            timeout=120,
        )
        # ──────────────────────────────────────────────────────────────

        self.audit      = audit
        self.scorer     = scorer or PathScorer()
        self.replanner  = replanner or ReplanEngine(audit)
        self.max_pivots = max_pivots
        self._state: PlannerState | None = None   # Persistent (FR-AI-02)

    # ------------------------------------------------------------------
    # Main entry point (called each OPAV PLAN phase)
    # ------------------------------------------------------------------

    def score_and_queue(
        self,
        observations: list[dict],
        compromised: list[str],
        credentials: list[dict],
        pivot_depth: int,
    ) -> list[AttackTask]:
        """
        Plan the next attack queue for the current OPAV cycle.

        Steps:
          1. Restore or initialise persistent state
          2. Build context for Claude
          3. Log intent (FR-AI-05: before acting)
          4. Call Claude API
          5. Log full reasoning (FR-AI-05: after acting)
          6. Parse JSON task list
          7. Score with PathScorer
          8. Filter failed vectors
        """

        # ── Restore / update persistent state (FR-AI-02) ──────────────
        if self._state is None:
            self._state = PlannerState(
                observations=observations,
                compromised_hosts=compromised,
                credentials=credentials,
                pivot_depth=pivot_depth,
            )
        else:
            self._state.observations    = observations
            self._state.compromised_hosts = compromised
            self._state.credentials     = credentials
            self._state.pivot_depth     = pivot_depth
            self._state.cycle          += 1
            # Merge in any new failures from the replanner
            for v in self.replanner.get_failed_vectors():
                if v not in self._state.failed_vectors:
                    self._state.failed_vectors.append(v)

        context = self._build_context(self._state)

        # Pre-action intent log (FR-AI-05)
        self.audit.log_intent(
            "AI_PLAN_REASONING_START",
            cycle=self._state.cycle,
            context_summary=context[:300],
        )

        # ── Call Claude ────────────────────────────────────────────────
        try:
            response = self.llm.invoke([
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT.format(max_pivots=self.max_pivots),
                },
                {
                    "role": "user",
                    "content": context,
                },
            ])
            reasoning = response.content
        except Exception as e:
            self.audit.log_event("AI_PLAN_LLM_ERROR", error=str(e),
                                  cycle=self._state.cycle)
            return []

        # Post-action full reasoning log (FR-AI-05)
        self.audit.log_event(
            "AI_PLAN_REASONING",
            reasoning=reasoning[:2000],   # Truncated in log; full in DB if needed
            cycle=self._state.cycle,
        )

        # ── Parse → score → filter ────────────────────────────────────
        tasks  = self._parse_tasks(reasoning)
        scored = self.scorer.score(tasks, observations)

        # Remove already-failed vectors
        scored = [
            t for t in scored
            if f"{t.target}:{t.module_id}" not in self._state.failed_vectors
        ]

        self._state.attack_queue = scored
        self.audit.log_event(
            "AI_PLAN_COMPLETE",
            tasks=len(scored),
            cycle=self._state.cycle,
        )
        return scored

    # ------------------------------------------------------------------
    # Feedback methods
    # ------------------------------------------------------------------

    def record_failure(self, task: AttackTask) -> None:
        """Called by OPAV loop when a vector fails. Prevents re-queuing."""
        self.replanner.record_failure(task.target, task.module_id)
        if self._state:
            key = f"{task.target}:{task.module_id}"
            if key not in self._state.failed_vectors:
                self._state.failed_vectors.append(key)

    def restore_from_checkpoint(self, checkpoint: dict) -> None:
        """FR-AI-02 edge case: restore state from last valid checkpoint."""
        try:
            self._state = PlannerState(**checkpoint)
            self.audit.log_event("STATE_RESTORED_FROM_CHECKPOINT")
        except (TypeError, KeyError) as e:
            self.audit.log_event("STATE_RESTORE_FAILED", error=str(e))

    # ------------------------------------------------------------------
    # Context builder
    # ------------------------------------------------------------------

    def _build_context(self, state: PlannerState) -> str:
        """Serialise current state into a concise LLM-readable prompt."""
        vulns_summary = "\n".join(
            f"  - {o['ip']}: {len(o.get('vulnerabilities', []))} vulns, "
            f"max_cvss={max((v.get('cvss', 0) for v in o.get('vulnerabilities', [])), default=0):.1f}"
            for o in state.observations[:50]  # cap to 50 targets
        )

        creds_summary = (
            f"{len(state.credentials)} credentials in vault"
            if state.credentials
            else "No credentials yet"
        )

        failed_summary = self.replanner.build_failure_summary()

        return (
            f"=== OPAV Cycle {state.cycle} ===\n"
            f"Pivot depth: {state.pivot_depth}/{self.max_pivots}\n"
            f"Compromised hosts: {state.compromised_hosts or 'None'}\n"
            f"Credentials: {creds_summary}\n\n"
            f"Unexhausted targets (ip: vuln_count, max_cvss):\n"
            f"{vulns_summary or '  (none remaining)'}\n\n"
            f"{failed_summary}"
        )

    # ------------------------------------------------------------------
    # Response parser
    # ------------------------------------------------------------------

    def _parse_tasks(self, llm_output: str) -> list[AttackTask]:
        """
        Extract the JSON array from the LLM response and parse AttackTask objects.
        Handles responses with prose before/after the JSON block.
        """
        # Try to find a JSON array (possibly inside a ```json code fence)
        patterns = [
            r"```json\s*(\[.*?\])\s*```",
            r"```\s*(\[.*?\])\s*```",
            r"(\[.*?\])",
        ]
        for pattern in patterns:
            match = re.search(pattern, llm_output, re.DOTALL)
            if match:
                try:
                    raw = json.loads(match.group(1))
                    tasks = []
                    for item in raw:
                        # Fill required fields with defaults if missing
                        item.setdefault("id", f"TASK-{len(tasks):03d}")
                        item.setdefault("priority_score", 0.5)
                        item.setdefault("depends_on", [])
                        item.setdefault("is_novel", False)
                        item.setdefault("parameters", {})
                        item.setdefault("destructive", False)
                        try:
                            tasks.append(AttackTask(**{
                                k: v for k, v in item.items()
                                if k in AttackTask.__dataclass_fields__
                            }))
                        except (TypeError, KeyError):
                            continue
                    return tasks
                except json.JSONDecodeError:
                    continue

        self.audit.log_event("AI_PLAN_PARSE_FAILED",
                              preview=llm_output[:300])
        return []
