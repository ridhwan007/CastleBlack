"""
Blast radius gate.

BR-SAFE-03: Destructive actions require explicit human approval.
Three modes: conservative | standard | aggressive
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class BlastRadiusResult:
    approved: bool
    reason: str = ""


class BlastRadiusGate:
    """
    Gates execution of potentially destructive attack modules.

    conservative — blocks all destructive modules; requires HITL for novel paths
    standard     — allows non-destructive destructive-flagged modules with audit
    aggressive   — allows most actions; still blocks DoS/data-wipe
    """

    # Modules permanently blocked regardless of blast_radius setting
    ALWAYS_BLOCKED = {
        "DOS", "WIPE", "RANSOM", "FORMAT", "ENCRYPT_FILES",
    }

    def __init__(self, blast_radius: str = "conservative"):
        if blast_radius not in ("conservative", "standard", "aggressive"):
            blast_radius = "conservative"
        self.blast_radius = blast_radius

    def check(self, task) -> BlastRadiusResult:
        """
        Check whether the task is permitted under the current blast radius policy.
        Called by GuardrailController before every task execution.
        """
        module_id = getattr(task, "module_id", "").upper()

        # Permanently blocked modules — no override
        if any(blocked in module_id for blocked in self.ALWAYS_BLOCKED):
            return BlastRadiusResult(
                False,
                f"Module '{task.module_id}' matches permanently-blocked category "
                f"(DoS/data-wipe/ransomware).",
            )

        # Check module destructive flag
        # Tasks carry this from the manifest (loaded in AttackRegistry)
        is_destructive = getattr(task, "destructive", False)

        if not is_destructive:
            return BlastRadiusResult(True)

        if self.blast_radius == "conservative":
            return BlastRadiusResult(
                False,
                f"Destructive module '{task.module_id}' blocked — blast_radius=conservative. "
                "Use --blast-radius standard or aggressive, or disable module.",
            )

        if self.blast_radius == "standard":
            # Allow with audit warning; novel AI-generated paths still need HITL
            is_novel = getattr(task, "is_novel", False)
            if is_novel:
                return BlastRadiusResult(
                    False,
                    f"Novel AI-generated destructive path blocked under standard mode. "
                    "Enable --hitl to approve novel paths manually.",
                )
            return BlastRadiusResult(True)

        # aggressive — allow destructive (DoS/wipe still blocked above)
        return BlastRadiusResult(True)

    def approve(self, task) -> bool:
        """Shorthand bool check used by AttackRegistry."""
        return self.check(task).approved
