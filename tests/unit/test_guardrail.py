"""
Unit tests — Guardrail System.

Tests: ScopeEnforcer, GuardrailController (fail-closed), CredentialRateLimiter.
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# ScopeEnforcer
# ---------------------------------------------------------------------------

class TestScopeEnforcer:
    def _make(self, allowed=("10.0.0.0/16",), excluded=()):
        from aiptt.guardrail.scope_enforcer import ScopeEnforcer
        return ScopeEnforcer(list(allowed), list(excluded))

    def test_ip_in_scope(self):
        se = self._make()
        assert se.is_in_scope("10.0.1.5") is True

    def test_ip_out_of_scope(self):
        se = self._make()
        assert se.is_in_scope("192.168.1.1") is False

    def test_excluded_ip_not_in_scope(self):
        se = self._make(allowed=["10.0.0.0/8"], excluded=["10.0.0.1"])
        assert se.is_in_scope("10.0.0.1") is False

    def test_multiple_cidrs(self):
        se = self._make(allowed=["10.0.0.0/24", "172.16.0.0/12"])
        assert se.is_in_scope("172.16.5.1") is True
        assert se.is_in_scope("192.168.0.1") is False

    def test_invalid_ip_returns_false(self):
        se = self._make()
        assert se.is_in_scope("not-an-ip") is False

    def test_empty_scope_blocks_everything(self):
        se = self._make(allowed=[])
        assert se.is_in_scope("10.0.0.1") is False


# ---------------------------------------------------------------------------
# BlastRadiusGate
# ---------------------------------------------------------------------------

class TestBlastRadiusGate:
    def _make(self, mode="standard"):
        from aiptt.guardrail.blast_radius import BlastRadiusGate
        return BlastRadiusGate(mode=mode)

    def _task(self, module_id="AD-KERB-001", destructive=False):
        t = MagicMock()
        t.module_id   = module_id
        t.destructive = destructive
        return t

    def test_normal_task_approved_standard(self):
        gate   = self._make("standard")
        result = gate.check(self._task())
        assert result.approved is True

    def test_destructive_blocked_always(self):
        for mode in ("conservative", "standard", "aggressive"):
            gate   = self._make(mode)
            result = gate.check(self._task(module_id="DOS-001", destructive=True))
            assert result.approved is False

    def test_conservative_blocks_any_destructive_flag(self):
        gate   = self._make("conservative")
        result = gate.check(self._task(destructive=True))
        assert result.approved is False

    def test_hardcoded_always_blocked_modules(self):
        gate = self._make("aggressive")
        for mid in ("DOS", "WIPE", "RANSOM", "FORMAT", "ENCRYPT_FILES"):
            result = gate.check(self._task(module_id=mid))
            assert result.approved is False, f"Expected {mid} to be blocked"


# ---------------------------------------------------------------------------
# GuardrailController — fail-closed
# ---------------------------------------------------------------------------

class TestGuardrailController:
    def _make_controller(self, scope_result=True, blast_result=True,
                          rate_result=True, circuit_tripped=False):
        from aiptt.guardrail.controller import GuardrailController

        scope    = MagicMock()
        scope.is_in_scope.return_value = scope_result

        blast    = MagicMock()
        blast_ok = MagicMock(approved=blast_result, reason="ok")
        blast.check.return_value = blast_ok

        rate     = MagicMock()
        rate.can_proceed.return_value = rate_result

        circuit  = MagicMock()
        circuit.is_tripped.return_value = circuit_tripped

        audit    = MagicMock()

        return GuardrailController(
            scope_enforcer=scope,
            blast_radius=blast,
            rate_limiter=rate,
            circuit_breaker=circuit,
            audit=audit,
        )

    def _task(self, target="10.0.0.5", module_id="AD-KERB-001"):
        t = MagicMock()
        t.target     = target
        t.module_id  = module_id
        t.destructive = False
        t.parameters = {}
        return t

    def test_all_pass_returns_approved(self):
        ctrl   = self._make_controller()
        result = ctrl.check(self._task())
        assert result.approved is True

    def test_out_of_scope_rejected(self):
        ctrl   = self._make_controller(scope_result=False)
        result = ctrl.check(self._task())
        assert result.approved is False
        assert "scope" in result.reason.lower()

    def test_blast_rejected(self):
        ctrl   = self._make_controller(blast_result=False)
        result = ctrl.check(self._task())
        assert result.approved is False

    def test_circuit_tripped_rejected(self):
        ctrl   = self._make_controller(circuit_tripped=True)
        result = ctrl.check(self._task())
        assert result.approved is False

    def test_exception_in_scope_check_fails_closed(self):
        from aiptt.guardrail.controller import GuardrailController

        scope = MagicMock()
        scope.is_in_scope.side_effect = RuntimeError("unexpected error")

        blast   = MagicMock()
        rate    = MagicMock()
        circuit = MagicMock()
        audit   = MagicMock()

        ctrl = GuardrailController(
            scope_enforcer=scope, blast_radius=blast,
            rate_limiter=rate, circuit_breaker=circuit, audit=audit,
        )
        result = ctrl.check(self._task())
        # Must fail CLOSED on any exception
        assert result.approved is False


# ---------------------------------------------------------------------------
# CredentialRateLimiter
# ---------------------------------------------------------------------------

class TestCredentialRateLimiter:
    def test_can_proceed_within_limits(self):
        from aiptt.guardrail.rate_limiter import CredentialRateLimiter

        limiter = CredentialRateLimiter(
            session_factory=MagicMock(),
            audit=MagicMock(),
        )
        # Patch _get_attempt_count to return 0
        with patch.object(limiter, "_get_attempt_count", return_value=0):
            with patch.object(limiter, "get_lockout_policy",
                              return_value={"max_attempts": 5, "window_minutes": 30}):
                assert limiter.can_proceed("10.0.0.1", {}) is True

    def test_blocked_when_at_limit(self):
        from aiptt.guardrail.rate_limiter import CredentialRateLimiter

        limiter = CredentialRateLimiter(
            session_factory=MagicMock(),
            audit=MagicMock(),
        )
        with patch.object(limiter, "_get_attempt_count", return_value=2):
            with patch.object(limiter, "get_lockout_policy",
                              return_value={"max_attempts": 2, "window_minutes": 30}):
                assert limiter.can_proceed("10.0.0.1", {}) is False
