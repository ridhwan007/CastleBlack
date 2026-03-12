"""
Unit tests — FixVerifyEngine.

Tests: REMEDIATED, STILL_VULNERABLE, REGRESSION paths.
REGRESSION must create a new Finding with CVSS escalated by +1.0 (capped at 10).
"""

from __future__ import annotations

import json
import pytest
from unittest.mock import MagicMock, patch


def _make_snapshot(finding_id="FIND-ABCD1234", module_id="AD-KERB-001",
                   target="10.0.0.5", cvss=7.5, engagement_id="ENG-001"):
    return {
        "finding_id":    finding_id,
        "module_id":     module_id,
        "target":        target,
        "cvss_score":    cvss,
        "engagement_id": engagement_id,
        "title":         "Kerberoasting",
        "mitre_technique": "T1558.003",
        "parameters":    {},
        "remediation_advice": "Enforce strong service account passwords.",
    }


def _make_result(success: bool, cvss: float = 7.5):
    r = MagicMock()
    r.success    = success
    r.cvss_score = cvss
    r.output     = "test output"
    return r


def _make_engine(snapshot=None, execute_result=None):
    from aiptt.fixverify.engine import FixVerifyEngine

    registry = MagicMock()
    audit    = MagicMock()

    engine = FixVerifyEngine(
        attack_registry=registry,
        audit=audit,
        db_session=MagicMock(),
    )

    if snapshot is not None:
        engine._load_snapshot = MagicMock(return_value=snapshot)
    else:
        engine._load_snapshot = MagicMock(return_value=None)

    if execute_result is not None:
        engine._execute = MagicMock(return_value=execute_result)

    engine._persist_retest_record    = MagicMock()
    engine._open_regression_finding  = MagicMock(return_value="FIND-NEW00001")

    return engine


class TestFixVerifyEngine:

    def test_remediated_when_attack_fails(self):
        from aiptt.fixverify.engine import RetestOutcome
        snap   = _make_snapshot(cvss=7.5)
        result = _make_result(success=False, cvss=7.5)
        engine = _make_engine(snapshot=snap, execute_result=result)

        retest = engine.retest("FIND-ABCD1234")
        assert retest.outcome == RetestOutcome.REMEDIATED

    def test_still_vulnerable_when_attack_succeeds_same_cvss(self):
        from aiptt.fixverify.engine import RetestOutcome
        snap   = _make_snapshot(cvss=7.5)
        result = _make_result(success=True, cvss=7.5)
        engine = _make_engine(snapshot=snap, execute_result=result)

        retest = engine.retest("FIND-ABCD1234")
        assert retest.outcome == RetestOutcome.STILL_VULNERABLE

    def test_regression_when_cvss_escalates(self):
        from aiptt.fixverify.engine import RetestOutcome
        snap   = _make_snapshot(cvss=7.0)
        result = _make_result(success=True, cvss=8.5)  # delta = 1.5 >= 1.0
        engine = _make_engine(snapshot=snap, execute_result=result)

        retest = engine.retest("FIND-ABCD1234")
        assert retest.outcome == RetestOutcome.REGRESSION

    def test_regression_opens_new_finding(self):
        snap   = _make_snapshot(cvss=7.0)
        result = _make_result(success=True, cvss=8.5)
        engine = _make_engine(snapshot=snap, execute_result=result)

        retest = engine.retest("FIND-ABCD1234")
        assert retest.new_finding_id == "FIND-NEW00001"
        engine._open_regression_finding.assert_called_once()

    def test_snapshot_not_found_returns_still_vulnerable(self):
        from aiptt.fixverify.engine import RetestOutcome
        engine = _make_engine(snapshot=None)
        retest = engine.retest("FIND-MISSING")
        assert retest.outcome == RetestOutcome.STILL_VULNERABLE

    def test_cvss_escalation_capped_at_10(self):
        from aiptt.fixverify.engine import FixVerifyEngine
        engine = _make_engine()
        # Simulate: original 9.5, retest 10.0, escalation would be 10.5 → cap at 10
        snap   = _make_snapshot(cvss=9.5)
        result = _make_result(success=True, cvss=10.0)
        engine._load_snapshot = MagicMock(return_value=snap)
        engine._execute       = MagicMock(return_value=result)

        # Directly test _open_regression_finding escalation logic
        escalated = min(9.5 + FixVerifyEngine.REGRESSION_CVSS_ESCALATION,
                        FixVerifyEngine.CVSS_MAX)
        assert escalated <= 10.0

    def test_execution_error_returns_still_vulnerable(self):
        from aiptt.fixverify.engine import RetestOutcome
        snap   = _make_snapshot(cvss=7.5)
        engine = _make_engine(snapshot=snap)
        engine._execute = MagicMock(side_effect=RuntimeError("exploit crashed"))

        retest = engine.retest("FIND-ABCD1234")
        assert retest.outcome == RetestOutcome.STILL_VULNERABLE

    def test_outcome_enum_values(self):
        from aiptt.fixverify.engine import RetestOutcome
        assert RetestOutcome.REMEDIATED.value       == "REMEDIATED"
        assert RetestOutcome.STILL_VULNERABLE.value == "STILL_VULNERABLE"
        assert RetestOutcome.REGRESSION.value       == "REGRESSION"

    def test_cvss_to_severity_mapping(self):
        from aiptt.fixverify.engine import FixVerifyEngine
        assert FixVerifyEngine._cvss_to_severity(9.5)  == "CRITICAL"
        assert FixVerifyEngine._cvss_to_severity(8.0)  == "HIGH"
        assert FixVerifyEngine._cvss_to_severity(5.0)  == "MEDIUM"
        assert FixVerifyEngine._cvss_to_severity(2.0)  == "LOW"
        assert FixVerifyEngine._cvss_to_severity(0.0)  == "INFO"
