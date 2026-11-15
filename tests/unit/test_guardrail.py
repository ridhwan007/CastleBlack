"""
Unit tests — Guardrail System.

Tests: ScopeEnforcer, BlastRadiusGate, GuardrailController (fail-closed),
CredentialRateLimiter.

These tests are written against the real module APIs:
  - GuardrailController(scope, blast, rate, circuit, audit) and returns
    GuardrailResult(passed, reason, blocker).
  - GuardrailController reads scope.validate_target_before_action(),
    blast.check().approved, rate.can_proceed(), and circuit.is_tripped
    (a property/attribute, not a call).
  - BlastRadiusGate(blast_radius=...) returns BlastRadiusResult(approved, reason).
  - CredentialRateLimiter(dc_ip, domain).can_proceed(target, params) using a
    LockoutPolicy dataclass.
"""

from __future__ import annotations

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

    def test_validate_target_before_action_matches_is_in_scope(self):
        se = self._make()
        assert se.validate_target_before_action("10.0.1.5") is True
        assert se.validate_target_before_action("192.168.1.1") is False


# ---------------------------------------------------------------------------
# BlastRadiusGate
# ---------------------------------------------------------------------------

class TestBlastRadiusGate:
    def _make(self, blast_radius="standard"):
        from aiptt.guardrail.blast_radius import BlastRadiusGate
        return BlastRadiusGate(blast_radius=blast_radius)

    def _task(self, module_id="AD-KERB-001", destructive=False, is_novel=False):
        t = MagicMock()
        t.module_id = module_id
        t.destructive = destructive
        t.is_novel = is_novel
        return t

    def test_normal_task_approved_standard(self):
        gate = self._make("standard")
        assert gate.check(self._task()).approved is True

    def test_destructive_blocked_in_conservative(self):
        gate = self._make("conservative")
        assert gate.check(self._task(destructive=True)).approved is False

    def test_destructive_allowed_in_aggressive(self):
        gate = self._make("aggressive")
        assert gate.check(self._task(destructive=True)).approved is True

    def test_novel_destructive_blocked_in_standard(self):
        gate = self._make("standard")
        result = gate.check(self._task(destructive=True, is_novel=True))
        assert result.approved is False

    def test_always_blocked_modules(self):
        gate = self._make("aggressive")
        for mid in ("DOS", "WIPE", "RANSOM", "FORMAT", "ENCRYPT_FILES"):
            assert gate.check(self._task(module_id=mid)).approved is False, (
                f"Expected {mid} to be blocked"
            )

    def test_always_blocked_matches_substring(self):
        gate = self._make("aggressive")
        assert gate.check(self._task(module_id="NET-DOS-001")).approved is False

    def test_invalid_mode_defaults_to_conservative(self):
        gate = self._make("nonsense")
        assert gate.blast_radius == "conservative"
        assert gate.check(self._task(destructive=True)).approved is False


# ---------------------------------------------------------------------------
# GuardrailController — fail-closed
# ---------------------------------------------------------------------------

class TestGuardrailController:
    def _make_controller(self, scope_result=True, blast_result=True,
                         rate_result=True, circuit_tripped=False):
        from aiptt.guardrail.controller import GuardrailController

        scope = MagicMock()
        scope.validate_target_before_action.return_value = scope_result

        blast = MagicMock()
        blast.check.return_value = MagicMock(approved=blast_result, reason="blast")

        rate = MagicMock()
        rate.can_proceed.return_value = rate_result

        circuit = MagicMock()
        # is_tripped is read as an attribute/property, not called.
        circuit.is_tripped = circuit_tripped
        circuit.trip_reason = "anomaly"

        audit = MagicMock()

        return GuardrailController(
            scope=scope,
            blast=blast,
            rate=rate,
            circuit=circuit,
            audit=audit,
        )

    def _task(self, target="10.0.0.5", module_id="AD-KERB-001"):
        t = MagicMock()
        t.target = target
        t.module_id = module_id
        t.destructive = False
        t.parameters = {}
        return t

    def test_all_pass_returns_passed(self):
        ctrl = self._make_controller()
        result = ctrl.check(self._task())
        assert result.passed is True

    def test_out_of_scope_rejected(self):
        ctrl = self._make_controller(scope_result=False)
        result = ctrl.check(self._task())
        assert result.passed is False
        assert result.blocker == "SCOPE"

    def test_blast_rejected(self):
        ctrl = self._make_controller(blast_result=False)
        result = ctrl.check(self._task())
        assert result.passed is False
        assert result.blocker == "BLAST"

    def test_rate_limited_rejected(self):
        # Module id contains "kerb"/"spray" so the rate gate is exercised.
        ctrl = self._make_controller(rate_result=False)
        result = ctrl.check(self._task(module_id="CRED-SPRAY-001"))
        assert result.passed is False
        assert result.blocker == "RATE"

    def test_circuit_tripped_rejected(self):
        ctrl = self._make_controller(circuit_tripped=True)
        result = ctrl.check(self._task())
        assert result.passed is False
        assert result.blocker == "CIRCUIT"

    def test_non_credential_module_skips_rate_check(self):
        # A non-credential module must pass even if the rate gate would block.
        ctrl = self._make_controller(rate_result=False)
        result = ctrl.check(self._task(module_id="NET-RCE-001"))
        assert result.passed is True

    def test_exception_in_scope_check_fails_closed(self):
        from aiptt.guardrail.controller import GuardrailController

        scope = MagicMock()
        scope.validate_target_before_action.side_effect = RuntimeError("boom")

        ctrl = GuardrailController(
            scope=scope,
            blast=MagicMock(),
            rate=MagicMock(),
            circuit=MagicMock(),
            audit=MagicMock(),
        )
        result = ctrl.check(self._task())
        # Must fail CLOSED on any unexpected exception.
        assert result.passed is False
        assert result.blocker == "UNREACHABLE"


# ---------------------------------------------------------------------------
# CredentialRateLimiter
# ---------------------------------------------------------------------------

class TestCredentialRateLimiter:
    def _make(self):
        from aiptt.guardrail.rate_limiter import CredentialRateLimiter
        return CredentialRateLimiter(dc_ip="", domain="")

    def test_no_username_is_allowed(self):
        limiter = self._make()
        # No username in params => nothing to rate-limit.
        assert limiter.can_proceed("10.0.0.1", {}) is True

    def test_within_default_limit(self):
        limiter = self._make()
        with patch.object(limiter, "_count_recent_attempts", return_value=0):
            assert limiter.can_proceed("10.0.0.1", {"username": "svc"}) is True

    def test_blocked_at_default_limit(self):
        # Default policy (no DC) falls back to default_max = 2.
        limiter = self._make()
        with patch.object(limiter, "_count_recent_attempts", return_value=2):
            assert limiter.can_proceed("10.0.0.1", {"username": "svc"}) is False

    def test_respects_explicit_policy_with_safety_margin(self):
        from aiptt.guardrail.rate_limiter import LockoutPolicy
        limiter = self._make()
        policy = LockoutPolicy(
            threshold=5,
            observation_window_minutes=30,
            lockout_duration_minutes=30,
        )
        # _safe_max(5) = 5 - safety_margin(2) = 3, so 2 proceeds, 3 blocks.
        with patch.object(limiter, "get_lockout_policy", return_value=policy):
            with patch.object(limiter, "_count_recent_attempts", return_value=2):
                assert limiter.can_proceed("10.0.0.1", {"username": "svc"}) is True
            with patch.object(limiter, "_count_recent_attempts", return_value=3):
                assert limiter.can_proceed("10.0.0.1", {"username": "svc"}) is False
