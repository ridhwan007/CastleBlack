"""
Guardrail controller.

FR-AI-04: Runs ALL guardrail checks before EVERY subtask — not just at session start.
Business Rule: Guardrail service unreachable = HALT (fail-closed, not fail-open).
"""

from __future__ import annotations

from dataclasses import dataclass

from aiptt.guardrail.scope_enforcer import ScopeEnforcer
from aiptt.guardrail.rate_limiter import CredentialRateLimiter
from aiptt.guardrail.blast_radius import BlastRadiusGate
from aiptt.guardrail.circuit_breaker import CircuitBreaker


@dataclass
class GuardrailResult:
    passed: bool
    reason: str = ""
    blocker: str = ""   # SCOPE | BLAST | RATE | CIRCUIT | UNREACHABLE


class GuardrailController:
    """
    Chains all four guardrail checks in order:
      1. Scope check (BR-SAFE-02)
      2. Blast radius check (BR-SAFE-03)
      3. Rate limit check (BR-SAFE-05) — credential modules only
      4. Circuit breaker check (Section 7.2)

    Any check failure → task is SKIPPED (not halted unless CIRCUIT trips).
    Guardrail service exception → HALT (fail-closed).
    """

    def __init__(
        self,
        scope: ScopeEnforcer,
        blast: BlastRadiusGate,
        rate: CredentialRateLimiter,
        circuit: CircuitBreaker,
        audit,
    ):
        self.scope   = scope
        self.blast   = blast
        self.rate    = rate
        self.circuit = circuit
        self.audit   = audit

    def check(self, task) -> GuardrailResult:
        try:
            # ── 1. Scope check ─────────────────────────────────────────
            target = getattr(task, "target", "")
            if not self.scope.validate_target_before_action(target):
                return GuardrailResult(
                    False,
                    f"Target {target} is out-of-scope or excluded",
                    "SCOPE",
                )

            # ── 2. Blast radius check ───────────────────────────────────
            blast_result = self.blast.check(task)
            if not blast_result.approved:
                return GuardrailResult(False, blast_result.reason, "BLAST")

            # ── 3. Rate limit check (credential modules only) ───────────
            mid = getattr(task, "module_id", "").lower()
            if "cred" in mid or "spray" in mid or "pass" in mid or "kerb" in mid:
                if not self.rate.can_proceed(target, getattr(task, "parameters", {})):
                    return GuardrailResult(
                        False,
                        "Credential rate limit reached — lockout protection active",
                        "RATE",
                    )

            # ── 4. Circuit breaker check ────────────────────────────────
            if self.circuit.is_tripped:
                return GuardrailResult(
                    False,
                    f"Circuit breaker tripped: {self.circuit.trip_reason}",
                    "CIRCUIT",
                )

            return GuardrailResult(True)

        except Exception as e:
            # Edge case: guardrail service unreachable → HALT (fail-closed)
            self.audit.log_event("GUARDRAIL_SERVICE_UNREACHABLE", error=str(e))
            return GuardrailResult(
                False,
                f"Guardrail service unreachable: {e} — HALTING (fail-closed)",
                "UNREACHABLE",
            )

    def arm(self, config) -> "GuardrailController":
        """Called at engagement init to confirm guardrail is active."""
        self.audit.log_event("GUARDRAIL_ARMED",
                             blast_radius=getattr(config, "blast_radius", "unknown"))
        return self
