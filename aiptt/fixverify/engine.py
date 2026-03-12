"""
Fix-Verify Engine.

FR-FIXVERIFY-01: Retest a finding using the exact original attack parameters.
FR-FIXVERIFY-02: Outcomes — REMEDIATED | STILL_VULNERABLE | REGRESSION.
FR-FIXVERIFY-03: REGRESSION escalates severity by +1.0 CVSS (capped at 10.0)
                 and opens a new Finding.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class RetestOutcome(str, Enum):
    REMEDIATED       = "REMEDIATED"
    STILL_VULNERABLE = "STILL_VULNERABLE"
    REGRESSION       = "REGRESSION"


@dataclass
class RetestResult:
    finding_id:       str
    outcome:          RetestOutcome
    original_cvss:    float
    retest_cvss:      float
    new_finding_id:   str | None = None   # Set on REGRESSION
    detail:           str = ""
    retested_at:      str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class FixVerifyEngine:
    """
    Retests a finding by replaying the exact original attack parameters.

    Business Rules:
    - REMEDIATED: attack_succeeded=False on retest
    - STILL_VULNERABLE: attack_succeeded=True, cvss_delta < 1.0
    - REGRESSION: attack_succeeded=True, cvss_delta >= 1.0 (new finding opened)
    """

    REGRESSION_CVSS_ESCALATION = 1.0
    CVSS_MAX = 10.0

    def __init__(self, attack_registry, audit, db_session):
        self.registry   = attack_registry
        self.audit      = audit
        self.db_session = db_session

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def retest(self, finding_id: str) -> RetestResult:
        """
        Retest a finding identified by finding_id.

        Loads the AttackChainSnapshot from DB, re-executes with original params,
        classifies the outcome, and persists the result.
        """
        self.audit.log_intent("FIXVERIFY_RETEST_START", finding=finding_id)

        snapshot = self._load_snapshot(finding_id)
        if snapshot is None:
            self.audit.log_event("FIXVERIFY_SNAPSHOT_NOT_FOUND", finding=finding_id)
            return RetestResult(
                finding_id=finding_id,
                outcome=RetestOutcome.STILL_VULNERABLE,
                original_cvss=0.0,
                retest_cvss=0.0,
                detail="Snapshot not found — cannot retest; treating as STILL_VULNERABLE.",
            )

        original_cvss = snapshot.get("cvss_score", 0.0)
        module_id     = snapshot["module_id"]
        params        = snapshot.get("parameters", {})
        target        = snapshot.get("target", "unknown")

        # Re-execute
        try:
            result = self._execute(module_id, target, params)
        except Exception as exc:
            self.audit.log_event("FIXVERIFY_EXECUTION_ERROR",
                                  finding=finding_id, error=str(exc))
            return RetestResult(
                finding_id=finding_id,
                outcome=RetestOutcome.STILL_VULNERABLE,
                original_cvss=original_cvss,
                retest_cvss=original_cvss,
                detail=f"Execution error during retest: {exc}",
            )

        retest_success = getattr(result, "success", False)
        retest_cvss    = getattr(result, "cvss_score", original_cvss)

        outcome = self._classify_outcome(
            original_cvss=original_cvss,
            retest_cvss=retest_cvss,
            retest_success=retest_success,
        )

        new_finding_id = None
        if outcome == RetestOutcome.REGRESSION:
            new_finding_id = self._open_regression_finding(
                original_snapshot=snapshot,
                result=result,
                original_cvss=original_cvss,
            )

        self._persist_retest_record(
            finding_id=finding_id,
            outcome=outcome,
            retest_cvss=retest_cvss,
            new_finding_id=new_finding_id,
        )

        self.audit.log_event(
            "FIXVERIFY_RETEST_COMPLETE",
            finding=finding_id,
            outcome=outcome.value,
            new_finding=new_finding_id,
        )

        return RetestResult(
            finding_id=finding_id,
            outcome=outcome,
            original_cvss=original_cvss,
            retest_cvss=retest_cvss,
            new_finding_id=new_finding_id,
            detail=self._build_detail(outcome, original_cvss, retest_cvss),
        )

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    def _classify_outcome(
        self, original_cvss: float, retest_cvss: float, retest_success: bool
    ) -> RetestOutcome:
        if not retest_success:
            return RetestOutcome.REMEDIATED

        cvss_delta = retest_cvss - original_cvss
        if cvss_delta >= self.REGRESSION_CVSS_ESCALATION:
            return RetestOutcome.REGRESSION

        return RetestOutcome.STILL_VULNERABLE

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _load_snapshot(self, finding_id: str) -> dict[str, Any] | None:
        """Load the AttackChainSnapshot for the finding from DB."""
        try:
            from aiptt.storage.models import AttackChainSnapshot
            with self.db_session() as session:
                row = (
                    session.query(AttackChainSnapshot)
                    .filter(AttackChainSnapshot.finding_id == finding_id)
                    .first()
                )
                if row is None:
                    return None
                return json.loads(row.snapshot_json)
        except Exception:
            return None

    def _execute(self, module_id: str, target: str, params: dict) -> Any:
        """Re-execute the attack with original parameters."""
        # Build a minimal task-like object
        class _RetestTask:
            def __init__(self, mid: str, tgt: str, p: dict):
                self.id         = f"RETEST-{uuid.uuid4().hex[:6].upper()}"
                self.module_id  = mid
                self.target     = tgt
                self.parameters = p
                self.technique  = p.get("technique", "")
                self.destructive = False

        task = _RetestTask(module_id, target, params)
        return self.registry.execute(task)

    def _open_regression_finding(
        self, original_snapshot: dict, result: Any, original_cvss: float
    ) -> str:
        """Create a new Finding with escalated CVSS for a regression."""
        try:
            from aiptt.storage.models import Finding, AttackChainSnapshot
            new_id = f"FIND-{str(uuid.uuid4())[:8].upper()}"
            escalated_cvss = min(
                original_cvss + self.REGRESSION_CVSS_ESCALATION,
                self.CVSS_MAX,
            )

            with self.db_session() as session:
                finding = Finding(
                    id=new_id,
                    engagement_id=original_snapshot.get("engagement_id", ""),
                    title=f"REGRESSION: {original_snapshot.get('title', 'Finding')}",
                    severity=self._cvss_to_severity(escalated_cvss),
                    cvss_score=escalated_cvss,
                    mitre_technique=original_snapshot.get("mitre_technique", ""),
                    target_host=original_snapshot.get("target", ""),
                    classification="CONFIRMED",
                    status="OPEN",
                    description=(
                        f"Regression detected during fix-verify retest. "
                        f"Original finding: {original_snapshot.get('finding_id')}. "
                        f"CVSS escalated from {original_cvss} to {escalated_cvss}."
                    ),
                    remediation_advice=original_snapshot.get("remediation_advice", ""),
                )
                session.add(finding)

                # Copy snapshot with new finding_id
                new_snapshot = dict(original_snapshot)
                new_snapshot["finding_id"] = new_id
                new_snapshot["regression_source"] = original_snapshot.get("finding_id")
                chain = AttackChainSnapshot(
                    id=str(uuid.uuid4()),
                    finding_id=new_id,
                    engagement_id=original_snapshot.get("engagement_id", ""),
                    snapshot_json=json.dumps(new_snapshot),
                )
                session.add(chain)
                session.commit()

            return new_id
        except Exception as exc:
            self.audit.log_event("FIXVERIFY_REGRESSION_FINDING_ERROR", error=str(exc))
            return f"FIND-ERROR"

    def _persist_retest_record(
        self,
        finding_id: str,
        outcome: RetestOutcome,
        retest_cvss: float,
        new_finding_id: str | None,
    ) -> None:
        """Update the original Finding row with retest outcome."""
        try:
            from aiptt.storage.models import Finding
            with self.db_session() as session:
                finding = session.query(Finding).filter(Finding.id == finding_id).first()
                if finding:
                    finding.status = (
                        "CLOSED" if outcome == RetestOutcome.REMEDIATED else "OPEN"
                    )
                    if hasattr(finding, "retest_outcome"):
                        finding.retest_outcome = outcome.value
                    if hasattr(finding, "retested_at"):
                        finding.retested_at = datetime.now(timezone.utc).isoformat()
                    session.commit()
        except Exception:
            pass  # Non-fatal — result is already logged via audit

    @staticmethod
    def _cvss_to_severity(cvss: float) -> str:
        if cvss >= 9.0:
            return "CRITICAL"
        if cvss >= 7.0:
            return "HIGH"
        if cvss >= 4.0:
            return "MEDIUM"
        if cvss >= 0.1:
            return "LOW"
        return "INFO"

    @staticmethod
    def _build_detail(
        outcome: RetestOutcome, original_cvss: float, retest_cvss: float
    ) -> str:
        if outcome == RetestOutcome.REMEDIATED:
            return "Vulnerability is no longer exploitable. Marking as REMEDIATED."
        if outcome == RetestOutcome.REGRESSION:
            return (
                f"Severity escalated from CVSS {original_cvss:.1f} to {retest_cvss:.1f}. "
                "New finding opened for regression."
            )
        return f"Vulnerability persists at CVSS {retest_cvss:.1f}. Still requires remediation."
