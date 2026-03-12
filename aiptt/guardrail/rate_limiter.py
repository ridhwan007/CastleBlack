"""
Credential rate limiter.

BR-SAFE-05: Never exceed the AD lockout threshold.
Reads live lockout policy via LDAP; falls back to 2 attempts/hour if unreadable.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from aiptt.core.config import get_config


@dataclass
class LockoutPolicy:
    threshold: Optional[int]           # None = unreadable / disabled
    observation_window_minutes: int    # Reset window in minutes
    lockout_duration_minutes: int      # How long accounts stay locked


class CredentialRateLimiter:
    """
    Enforces per-account credential attempt limits.
    Reads the live AD Fine-Grained Password Policy via LDAP.
    Falls back to safe defaults when policy is unreadable (BR-SAFE-05 edge).
    """

    DEFAULT_MAX_ATTEMPTS    = 2    # BR-SAFE-05: fallback when threshold unknown
    LOCKOUT_SAFETY_MARGIN   = 2    # Always stay this many attempts below threshold
    DEFAULT_WINDOW_MINUTES  = 60

    def __init__(self, dc_ip: str = "", domain: str = ""):
        self.dc_ip  = dc_ip
        self.domain = domain
        cfg = get_config()
        self._default_max   = cfg.credential_attacks.default_max_attempts_per_account
        self._safety_margin = cfg.credential_attacks.lockout_safety_margin
        self._spray_window  = cfg.credential_attacks.spray_window_minutes

    def get_lockout_policy(self) -> LockoutPolicy:
        """
        Query AD for the default domain lockout policy via LDAP.
        Returns a safe-default policy if the query fails.
        """
        if not self.dc_ip or not self.domain:
            return self._default_policy()

        try:
            import ldap3
            server = ldap3.Server(self.dc_ip, get_info=ldap3.ALL)
            conn   = ldap3.Connection(server, auto_bind=True)

            conn.search(
                search_base=f"DC={self.domain.replace('.', ',DC=')}",
                search_filter="(objectClass=domainDNS)",
                attributes=["lockoutThreshold", "lockoutObservationWindow",
                            "lockoutDuration"],
                search_scope=ldap3.BASE,
            )

            if conn.entries:
                entry     = conn.entries[0]
                threshold = int(str(entry.lockoutThreshold))
                # Windows stores these as negative 100-nanosecond intervals
                obs_window = abs(int(str(entry.lockoutObservationWindow))) // 10_000_000 // 60
                duration   = abs(int(str(entry.lockoutDuration)))  // 10_000_000 // 60
                return LockoutPolicy(
                    threshold=threshold if threshold > 0 else None,
                    observation_window_minutes=max(obs_window, 1),
                    lockout_duration_minutes=max(duration, 1),
                )
        except Exception:
            pass

        return self._default_policy()

    def can_proceed(self, target: str, params: dict) -> bool:
        """Quick check used by GuardrailController — no wait."""
        username = params.get("username", "")
        if not username:
            return True
        count = self._count_recent_attempts(target, username)
        policy = self.get_lockout_policy()
        max_a  = (self._safe_max(policy.threshold)
                  if policy.threshold else self._default_max)
        return count < max_a

    def wait_if_needed(self, username: str, window_minutes: int) -> None:
        """Block until it is safe to attempt another credential guess."""
        # Simple token-bucket style: sleep fractionally per attempt
        interval = (window_minutes * 60) / max(self._default_max, 1)
        time.sleep(max(interval, 1.0))

    def record_attempt(self, engagement_id: str, dc_ip: str,
                       username: str, success: bool) -> None:
        """Persist a spray attempt to the credential_spray_log table."""
        try:
            from aiptt.storage.db import get_session
            from aiptt.storage.models import CredentialSprayLog
            with get_session() as session:
                session.add(CredentialSprayLog(
                    engagement_id=engagement_id,
                    target_dc=dc_ip,
                    username=username,
                    success=success,
                ))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _safe_max(self, threshold: Optional[int]) -> int:
        if threshold is None:
            return self._default_max
        return max(1, threshold - self._safety_margin)

    def _default_policy(self) -> LockoutPolicy:
        return LockoutPolicy(
            threshold=None,
            observation_window_minutes=self._spray_window,
            lockout_duration_minutes=30,
        )

    def _count_recent_attempts(self, dc_ip: str, username: str) -> int:
        """Count spray attempts in the current observation window."""
        try:
            from aiptt.storage.db import get_session
            from aiptt.storage.models import CredentialSprayLog
            cutoff = (
                datetime.now(timezone.utc) - timedelta(minutes=self._spray_window)
            ).isoformat()
            with get_session() as session:
                return (
                    session.query(CredentialSprayLog)
                    .filter(
                        CredentialSprayLog.target_dc == dc_ip,
                        CredentialSprayLog.username == username,
                        CredentialSprayLog.attempt_at >= cutoff,
                    )
                    .count()
                )
        except Exception:
            return 0
