"""
Proof-of-Exploit artefact capture.

FR-PROOF-01: Captures, classifies, and encrypts PoE artefacts.
FR-PROOF-02: Every finding must have a classification (CONFIRMED / UNCONFIRMED / THEORETICAL).

Edge case: capture failure → retry once → UNCONFIRMED if still failing.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from aiptt.poe.classifier import PoEClassifier


@dataclass
class PoEArtefact:
    finding_id:       str
    artefact_type:    str    # screenshot | credential | command_output | file | none
    vault_ref:        str    # Encrypted vault reference
    classification:   str    # CONFIRMED | UNCONFIRMED | THEORETICAL
    capture_success:  bool
    retry_attempted:  bool = False


class PoECapture:
    """
    Captures and classifies proof-of-exploit artefacts.

    Business Rule: No PoE = THEORETICAL RISK, not CONFIRMED (FR-PROOF-01).
    Edge Case: PoE capture failure → log as UNCONFIRMED, retry once.
    """

    def __init__(self, vault, audit):
        self.vault = vault
        self.audit = audit

    def capture(self, task, result) -> PoEArtefact:
        """Capture PoE for a successful attack result."""
        finding_id = self._generate_finding_id()
        self.audit.log_intent("POE_CAPTURE_START", task=task.id,
                               finding=finding_id)

        # Attempt collection
        artefact_data = self._collect_artefact(result)

        if artefact_data is None:
            # Edge case: capture failed → retry once (FR-PROOF-01)
            self.audit.log_event("POE_CAPTURE_FAILED_RETRYING", task=task.id)
            artefact_data = self._collect_artefact(result)

            if artefact_data is None:
                self.audit.log_event("POE_CAPTURE_FAILED_FINAL", task=task.id)
                return PoEArtefact(
                    finding_id=finding_id,
                    artefact_type="none",
                    vault_ref="",
                    classification="UNCONFIRMED",   # No PoE = UNCONFIRMED
                    capture_success=False,
                    retry_attempted=True,
                )

        # Detect artefact type
        artefact_type = self._detect_type(artefact_data)

        # Encrypt and store in vault (BR-SAFE-06 + NFR-SEC-02)
        try:
            vault_ref = self.vault.store(
                finding_id=finding_id,
                data=artefact_data,
                artefact_type=artefact_type,
            )
            classification = PoEClassifier.classify(
                attack_succeeded=getattr(result, "success", False),
                capture_succeeded=True,
            )
            self.audit.log_event("POE_CAPTURE_SUCCESS",
                                  finding=finding_id, type=artefact_type)
            return PoEArtefact(
                finding_id=finding_id,
                artefact_type=artefact_type,
                vault_ref=vault_ref,
                classification=classification,
                capture_success=True,
            )
        except Exception as e:
            self.audit.log_event("POE_VAULT_STORE_ERROR", task=task.id,
                                  error=str(e))
            return PoEArtefact(
                finding_id=finding_id,
                artefact_type=artefact_type,
                vault_ref="",
                classification="UNCONFIRMED",
                capture_success=False,
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _collect_artefact(self, result) -> bytes | None:
        """
        Collect artefact data from the attack result.
        Priority: credentials > command output > raw output.
        """
        creds = getattr(result, "credentials_captured", [])
        if creds:
            return str(creds).encode("utf-8")

        output = getattr(result, "output", "")
        if output and len(output) > 10:
            return output.encode("utf-8")

        return None

    def _detect_type(self, data: bytes) -> str:
        """Detect artefact type from content."""
        try:
            text = data.decode("utf-8", errors="ignore")
            if "$krb5tgs$" in text or "$krb5asrep$" in text:
                return "kerberos_ticket"
            if "NTLM" in text or "::" in text:
                return "credential"
            if text.strip().startswith("{"):
                return "json_output"
        except Exception:
            pass
        return "command_output"

    @staticmethod
    def _generate_finding_id() -> str:
        return f"FIND-{str(uuid.uuid4())[:8].upper()}"
