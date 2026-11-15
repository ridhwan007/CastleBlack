"""
PoE artefact classifier.

FR-PROOF-01: No PoE = THEORETICAL, not CONFIRMED.
Classification rules:
  CONFIRMED    — PoE artefact captured and vault-stored successfully
  UNCONFIRMED  — Attack succeeded but PoE capture failed (retry exhausted)
  THEORETICAL  — Attack was not executed (planned only) or no result
"""

from __future__ import annotations


class PoEClassifier:
    """Classifies a finding based on artefact capture success."""

    @staticmethod
    def classify(attack_succeeded: bool, capture_succeeded: bool) -> str:
        """
        Args:
            attack_succeeded:  True if the attack module returned success=True
            capture_succeeded: True if PoECapture stored an artefact

        Returns:
            "CONFIRMED" | "UNCONFIRMED" | "THEORETICAL"
        """
        if attack_succeeded and capture_succeeded:
            return "CONFIRMED"
        if attack_succeeded and not capture_succeeded:
            return "UNCONFIRMED"
        return "THEORETICAL"
