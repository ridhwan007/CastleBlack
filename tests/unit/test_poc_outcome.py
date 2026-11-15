"""
Unit tests — PoC outcome heuristic (PoCExecutor._heuristic_outcome).

Regression coverage for the outcome pre-pass. These lock in the fix for the
naive-substring heuristic that reported false SUCCESS on ambiguous output
("$", "password:", "exploit completed, but no session was created").

The heuristic is intentionally conservative: when evidence is weak or
conflicting it returns PARTIAL so the AI validator / human adjudicates.
"""

from __future__ import annotations

import pytest

from aiptt.engine.poc_executor import PoCExecutor


def outcome(stdout="", rc=0, stderr="", timed_out=False):
    return PoCExecutor._heuristic_outcome(stdout, stderr, rc, timed_out)


class TestStrongSignals:
    def test_meterpreter_session_is_success(self):
        assert outcome("Meterpreter session 1 opened (10.0.0.5)") == "SUCCESS"

    def test_id_output_is_success(self):
        assert outcome("uid=0(root) gid=0(root) groups=0(root)") == "SUCCESS"

    def test_root_shell_prompt_is_success(self):
        assert outcome("root@target:~# ") == "SUCCESS"

    def test_connection_refused_is_failure(self):
        assert outcome("", rc=1, stderr="curl: (7) Connection refused") == "FAILURE"

    def test_not_vulnerable_is_failure(self):
        assert outcome("Target is not vulnerable", rc=0) == "FAILURE"


class TestFalsePositivesFixed:
    """Inputs the old substring heuristic wrongly scored as SUCCESS."""

    def test_msf_no_session_is_failure(self):
        assert outcome("Exploit completed, but no session was created.") == "FAILURE"

    def test_password_prompt_is_not_success(self):
        assert outcome("Password: ", rc=0) == "PARTIAL"

    def test_bare_shell_char_is_not_success(self):
        assert outcome("$ ", rc=0) == "PARTIAL"

    def test_unsuccessful_is_failure_not_success(self):
        # "unsuccessful" contains the substring "success".
        assert outcome("Login was unsuccessful", rc=1) == "FAILURE"


class TestWeakAndInconclusive:
    def test_weak_success_with_clean_exit_is_success(self):
        assert outcome("Authentication successful", rc=0) == "SUCCESS"

    def test_weak_success_with_bad_exit_is_failure(self):
        assert outcome("Authentication successful then crashed", rc=1) == "FAILURE"

    def test_clean_exit_no_proof_is_partial(self):
        assert outcome("Request sent, 200 OK", rc=0) == "PARTIAL"

    def test_timeout_is_partial(self):
        assert outcome("connecting...", rc=-1, timed_out=True) == "PARTIAL"

    def test_conflicting_strong_signals_are_partial(self):
        combined = "Meterpreter session 1 opened\nlater: exploit failed"
        assert outcome(combined, rc=0) == "PARTIAL"
