"""
Adaptive re-planning engine.

FR-AI-03: When attack vectors fail, the planner injects failure context
into the next planning cycle so Claude does not re-queue the same dead ends.
"""

from __future__ import annotations


class ReplanEngine:
    """
    Maintains a record of failed attack vectors and re-plan triggers.
    Injects failure context into the next AIPlannerEngine call.
    """

    def __init__(self, audit):
        self.audit         = audit
        self._failed: list[str] = []   # "target:module_id" strings
        self._pivot_count  = 0

    def record_failure(self, target: str, module_id: str) -> None:
        """Record a failed vector to prevent re-queuing."""
        key = f"{target}:{module_id}"
        if key not in self._failed:
            self._failed.append(key)
        self.audit.log_event("REPLAN_FAILURE_RECORDED",
                              target=target, module_id=module_id)

    def record_pivot(self) -> None:
        """Track lateral pivot depth."""
        self._pivot_count += 1

    def reset_pivots(self) -> None:
        self._pivot_count = 0

    def get_failed_vectors(self) -> list[str]:
        return list(self._failed)

    def should_replan(self, current_queue_length: int) -> bool:
        """
        True when the queue is exhausted but pivots remain — triggers
        a re-plan with updated observations.
        """
        return current_queue_length == 0 and len(self._failed) > 0

    def build_failure_summary(self) -> str:
        """Human-readable summary of failed vectors for LLM context."""
        if not self._failed:
            return "No failed vectors recorded."
        lines = [f"  - {v}" for v in self._failed[-20:]]  # cap to last 20
        return "Previously failed attack vectors (DO NOT re-queue):\n" + "\n".join(lines)
