"""
Active Directory topology mapper.

FR-DISC-04: Enumerate AD objects (users, groups, computers, trusts, GPOs)
via LDAP using impacket or ldap3.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ADObject:
    dn: str
    object_class: str
    attributes: dict = field(default_factory=dict)


@dataclass
class ADTopology:
    domain: str
    domain_controllers: list[str] = field(default_factory=list)
    computers: list[dict] = field(default_factory=list)
    users: list[dict] = field(default_factory=list)
    groups: list[dict] = field(default_factory=list)
    trusts: list[dict] = field(default_factory=list)
    spn_accounts: list[dict] = field(default_factory=list)   # Kerberoastable
    asrep_accounts: list[dict] = field(default_factory=list) # ASREPRoastable


class ADMapper:
    """
    Enumerates Active Directory topology via LDAP.

    Requires valid domain credentials (username + password or NTLM hash).
    Results are fed directly into the KnowledgeGraph.
    """

    def __init__(self, audit):
        self.audit = audit

    def map(
        self,
        dc_ip: str,
        domain: str,
        username: str,
        password: str = "",
        nt_hash: str = "",
    ) -> ADTopology:
        """Full AD topology enumeration."""
        self.audit.log_intent("AD_MAP_START", domain=domain, dc_ip=dc_ip)

        topology = ADTopology(domain=domain)

        try:
            import ldap3
            server = ldap3.Server(dc_ip, get_info=ldap3.ALL)
            base_dn = ",".join(f"DC={part}" for part in domain.split("."))

            if nt_hash:
                # NTLM hash auth
                conn = ldap3.Connection(
                    server,
                    user=f"{domain}\\{username}",
                    password=f"aad3b435b51404eeaad3b435b51404ee:{nt_hash}",
                    authentication=ldap3.NTLM,
                    auto_bind=True,
                )
            else:
                conn = ldap3.Connection(
                    server,
                    user=f"{domain}\\{username}",
                    password=password,
                    authentication=ldap3.NTLM,
                    auto_bind=True,
                )

            topology.domain_controllers = self._get_dcs(conn, base_dn)
            topology.computers          = self._get_computers(conn, base_dn)
            topology.users              = self._get_users(conn, base_dn)
            topology.groups             = self._get_groups(conn, base_dn)
            topology.trusts             = self._get_trusts(conn, base_dn)
            topology.spn_accounts       = self._get_spn_accounts(conn, base_dn)
            topology.asrep_accounts     = self._get_asrep_accounts(conn, base_dn)

            conn.unbind()

        except Exception as e:
            self.audit.log_event("AD_MAP_ERROR", domain=domain, error=str(e))

        self.audit.log_event(
            "AD_MAP_COMPLETE",
            domain=domain,
            computers=len(topology.computers),
            users=len(topology.users),
            spn_accounts=len(topology.spn_accounts),
        )
        return topology

    # ------------------------------------------------------------------
    # LDAP queries
    # ------------------------------------------------------------------

    def _get_dcs(self, conn, base_dn: str) -> list[str]:
        try:
            import ldap3
            conn.search(
                search_base=base_dn,
                search_filter="(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
                attributes=["dNSHostName", "operatingSystem"],
            )
            return [str(e.dNSHostName) for e in conn.entries if e.dNSHostName]
        except Exception:
            return []

    def _get_computers(self, conn, base_dn: str) -> list[dict]:
        try:
            import ldap3
            conn.search(
                search_base=base_dn,
                search_filter="(objectClass=computer)",
                attributes=["name", "dNSHostName", "operatingSystem",
                            "operatingSystemVersion", "lastLogonTimestamp"],
            )
            return [
                {
                    "name":    str(e.name),
                    "dns":     str(e.dNSHostName) if e.dNSHostName else "",
                    "os":      str(e.operatingSystem) if e.operatingSystem else "",
                    "os_ver":  str(e.operatingSystemVersion) if e.operatingSystemVersion else "",
                }
                for e in conn.entries
            ]
        except Exception:
            return []

    def _get_users(self, conn, base_dn: str) -> list[dict]:
        try:
            conn.search(
                search_base=base_dn,
                search_filter="(&(objectClass=user)(objectCategory=person))",
                attributes=["sAMAccountName", "memberOf", "adminCount",
                            "userAccountControl"],
            )
            return [
                {
                    "username":   str(e.sAMAccountName),
                    "is_admin":   int(str(e.adminCount or 0)) > 0,
                    "uac":        int(str(e.userAccountControl or 0)),
                }
                for e in conn.entries
            ]
        except Exception:
            return []

    def _get_groups(self, conn, base_dn: str) -> list[dict]:
        try:
            conn.search(
                search_base=base_dn,
                search_filter="(objectClass=group)",
                attributes=["sAMAccountName", "member", "groupType"],
            )
            return [{"name": str(e.sAMAccountName)} for e in conn.entries]
        except Exception:
            return []

    def _get_trusts(self, conn, base_dn: str) -> list[dict]:
        try:
            conn.search(
                search_base=base_dn,
                search_filter="(objectClass=trustedDomain)",
                attributes=["name", "trustDirection", "trustType", "trustAttributes"],
            )
            return [
                {
                    "name":      str(e.name),
                    "direction": str(e.trustDirection),
                    "type":      str(e.trustType),
                }
                for e in conn.entries
            ]
        except Exception:
            return []

    def _get_spn_accounts(self, conn, base_dn: str) -> list[dict]:
        """Accounts with SPNs set — Kerberoastable."""
        try:
            conn.search(
                search_base=base_dn,
                search_filter="(&(objectClass=user)(servicePrincipalName=*)(!objectClass=computer))",
                attributes=["sAMAccountName", "servicePrincipalName"],
            )
            return [
                {
                    "username": str(e.sAMAccountName),
                    "spns":     list(e.servicePrincipalName),
                }
                for e in conn.entries
            ]
        except Exception:
            return []

    def _get_asrep_accounts(self, conn, base_dn: str) -> list[dict]:
        """Accounts with DONT_REQ_PREAUTH flag — ASREPRoastable."""
        DONT_REQ_PREAUTH = 4194304
        try:
            conn.search(
                search_base=base_dn,
                search_filter="(&(objectClass=user)"
                              f"(userAccountControl:1.2.840.113556.1.4.803:={DONT_REQ_PREAUTH}))",
                attributes=["sAMAccountName"],
            )
            return [{"username": str(e.sAMAccountName)} for e in conn.entries]
        except Exception:
            return []
