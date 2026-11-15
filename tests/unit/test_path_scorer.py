"""
Unit tests — PathScorer.

Tests: scoring weights, RCE override, boundary conditions.
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock


def _make_task(module_id="AD-KERB-001", cvss=7.5, access_level="user",
               hops=0, reliability=0.8, technique="T1558.003"):
    t = MagicMock()
    t.module_id    = module_id
    t.cvss_base    = cvss
    t.access_level = access_level
    t.hops         = hops
    t.reliability  = reliability
    t.technique    = technique
    return t


class TestPathScorer:

    def _scorer(self):
        from aiptt.engine.path_scorer import PathScorer
        return PathScorer()

    def test_score_is_between_0_and_1(self):
        scorer = self._scorer()
        task   = _make_task(cvss=5.0, access_level="user", hops=1, reliability=0.5)
        score  = scorer.score(task)
        assert 0.0 <= score <= 1.0

    def test_higher_cvss_gives_higher_score(self):
        scorer = self._scorer()
        low    = scorer.score(_make_task(cvss=3.0))
        high   = scorer.score(_make_task(cvss=9.0))
        assert high > low

    def test_rce_override_sets_priority_1(self):
        """CVSS >= 9.0 + rce in module_id → priority_score = 1.0"""
        scorer = self._scorer()
        task   = _make_task(module_id="NET-RCE-001", cvss=9.8)
        score  = scorer.score(task)
        assert score == pytest.approx(1.0)

    def test_rce_override_requires_cvss_9(self):
        """CVSS < 9.0 with rce module should NOT get override."""
        scorer = self._scorer()
        task   = _make_task(module_id="NET-RCE-001", cvss=7.0)
        score  = scorer.score(task)
        assert score < 1.0

    def test_more_hops_reduces_score(self):
        scorer = self._scorer()
        near   = scorer.score(_make_task(hops=0))
        far    = scorer.score(_make_task(hops=5))
        assert near > far

    def test_domain_admin_access_gives_max_access_score(self):
        scorer   = self._scorer()
        user_s   = scorer.score(_make_task(access_level="user"))
        admin_s  = scorer.score(_make_task(access_level="domain_admin"))
        assert admin_s >= user_s

    def test_zero_cvss_gives_low_score(self):
        scorer = self._scorer()
        score  = scorer.score(_make_task(cvss=0.0))
        assert score < 0.3

    def test_reliability_affects_score(self):
        scorer  = self._scorer()
        high_r  = scorer.score(_make_task(reliability=1.0, cvss=5.0))
        low_r   = scorer.score(_make_task(reliability=0.1, cvss=5.0))
        assert high_r > low_r

    def test_score_weights_sum(self):
        """Sanity check: CVSS 10, admin, 0 hops, reliability 1.0 → near 1.0."""
        scorer = self._scorer()
        score  = scorer.score(
            _make_task(cvss=10.0, access_level="domain_admin", hops=0, reliability=1.0)
        )
        # Should be at or very close to 1.0
        assert score >= 0.9
