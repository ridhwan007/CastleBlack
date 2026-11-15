"""
Unit tests — PoE Capture.

Tests: capture retry logic, CONFIRMED vs UNCONFIRMED classification,
       vault storage, artefact type detection.
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch, call


def _make_result(success=True, output="command output here", creds=None):
    r = MagicMock()
    r.success               = success
    r.output                = output
    r.credentials_captured  = creds or []
    r.cvss_score            = 7.5
    return r


def _make_task(task_id="TASK-001"):
    t = MagicMock()
    t.id = task_id
    return t


def _make_capture(vault_store_ok=True):
    from aiptt.poe.capture import PoECapture

    vault = MagicMock()
    if vault_store_ok:
        vault.store.return_value = "vault://FIND-ABCD1234"
    else:
        vault.store.side_effect = Exception("vault error")

    audit = MagicMock()
    return PoECapture(vault=vault, audit=audit), vault, audit


class TestPoECapture:

    def test_successful_capture_is_confirmed(self):
        capture, vault, _ = _make_capture()
        result   = _make_result(success=True, output="uid=0(root)")
        artefact = capture.capture(_make_task(), result)

        assert artefact.capture_success   is True
        assert artefact.classification    == "CONFIRMED"
        assert artefact.vault_ref         == "vault://FIND-ABCD1234"

    def test_no_output_retries_and_returns_unconfirmed(self):
        capture, vault, audit = _make_capture()
        result = _make_result(success=True, output="")  # triggers None from _collect_artefact

        with patch.object(capture, "_collect_artefact", return_value=None):
            artefact = capture.capture(_make_task(), result)

        assert artefact.capture_success  is False
        assert artefact.classification   == "UNCONFIRMED"
        assert artefact.retry_attempted  is True

    def test_retry_once_on_first_failure(self):
        capture, _, _ = _make_capture()

        call_count = {"n": 0}
        def _collect(r):
            call_count["n"] += 1
            return None if call_count["n"] == 1 else b"data"

        capture._collect_artefact = _collect
        result   = _make_result()
        artefact = capture.capture(_make_task(), result)
        # Second attempt succeeded → should be confirmed
        assert call_count["n"] == 2

    def test_vault_error_returns_unconfirmed(self):
        capture, _, _ = _make_capture(vault_store_ok=False)
        result   = _make_result(success=True, output="some output here that is long enough")
        artefact = capture.capture(_make_task(), result)

        assert artefact.capture_success  is False
        assert artefact.classification   == "UNCONFIRMED"

    def test_credential_output_detected(self):
        capture, _, _ = _make_capture()
        result = _make_result(creds=[("admin", "NTLMhash::domain")])
        artefact = capture.capture(_make_task(), result)
        assert artefact.artefact_type in ("credential", "command_output", "kerberos_ticket")

    def test_kerberos_ticket_type_detected(self):
        from aiptt.poe.capture import PoECapture
        c = PoECapture(vault=MagicMock(), audit=MagicMock())
        data = b"$krb5tgs$23$*svc$DOMAIN.COM$..."
        assert c._detect_type(data) == "kerberos_ticket"

    def test_ntlm_hash_type_detected(self):
        from aiptt.poe.capture import PoECapture
        c = PoECapture(vault=MagicMock(), audit=MagicMock())
        data = b"Administrator::DOMAIN:aad3b435b51404ee"
        assert c._detect_type(data) == "credential"

    def test_json_output_type_detected(self):
        from aiptt.poe.capture import PoECapture
        c = PoECapture(vault=MagicMock(), audit=MagicMock())
        data = b'{"result": "success", "user": "admin"}'
        assert c._detect_type(data) == "json_output"

    def test_finding_id_format(self):
        from aiptt.poe.capture import PoECapture
        c  = PoECapture(vault=MagicMock(), audit=MagicMock())
        fid = c._generate_finding_id()
        assert fid.startswith("FIND-")
        assert len(fid) == 13  # "FIND-" + 8 chars


class TestPoEClassifier:

    def test_confirmed_when_attack_and_capture_succeed(self):
        from aiptt.poe.classifier import PoEClassifier
        assert PoEClassifier.classify(True, True) == "CONFIRMED"

    def test_unconfirmed_when_attack_succeeds_but_capture_fails(self):
        from aiptt.poe.classifier import PoEClassifier
        assert PoEClassifier.classify(True, False) == "UNCONFIRMED"

    def test_theoretical_when_attack_fails(self):
        from aiptt.poe.classifier import PoEClassifier
        assert PoEClassifier.classify(False, False) == "THEORETICAL"
        assert PoEClassifier.classify(False, True)  == "THEORETICAL"
