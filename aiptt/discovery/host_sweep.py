"""
CIDR host discovery sweep.

FR-DISC-01: TCP + UDP sweep.
Edge case: UDP-only hosts are flagged (udp_only=True), not silently dropped.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Generator


@dataclass
class DiscoveredHost:
    ip: str
    status: str                    # up | down
    mac: str = ""
    hostname: str = ""
    udp_only: bool = False         # True = no TCP response, only UDP
    suspected_honeypot: bool = False
    open_ports: list[int] = field(default_factory=list)


class HostSweeper:
    """
    CIDR sweep using python-nmap.
    Performs TCP ping sweep first, then UDP sweep to catch UDP-only hosts.
    Flags UDP-only hosts rather than silently dropping (FR-DISC-01 edge case).
    """

    UDP_PORTS = "53,67,123,161"   # DNS, DHCP, NTP, SNMP

    def __init__(self, audit, rate: str = "T3"):
        self.audit = audit
        self.rate  = rate
        try:
            import nmap
            self.nm = nmap.PortScanner()
        except ImportError:
            self.nm = None

    def sweep(self, cidr: str) -> Generator[DiscoveredHost, None, None]:
        """Yield DiscoveredHost objects for every live host in the CIDR."""
        self.audit.log_intent("HOST_SWEEP_START", cidr=cidr)

        if self.nm is None:
            self.audit.log_event("HOST_SWEEP_ERROR",
                                  error="python-nmap not installed")
            return

        # TCP ping sweep
        self.nm.scan(hosts=cidr, arguments=f"-sn -{self.rate}")
        tcp_up = set(self.nm.all_hosts())

        # UDP sweep (catch UDP-only hosts)
        self.nm.scan(
            hosts=cidr,
            arguments=f"-sU -p {self.UDP_PORTS} -{self.rate} --open",
        )
        udp_hosts = set(self.nm.all_hosts())
        udp_only  = udp_hosts - tcp_up

        # Yield TCP-responsive hosts
        for ip in tcp_up:
            yield DiscoveredHost(
                ip=ip,
                status="up",
                hostname=self._get_hostname(ip),
                mac=self._get_mac(ip),
            )

        # Yield UDP-only hosts (flagged, not dropped)
        for ip in udp_only:
            self.audit.log_event("UDP_ONLY_HOST_FLAGGED", ip=ip)
            yield DiscoveredHost(
                ip=ip,
                status="up",
                udp_only=True,
                hostname=self._get_hostname(ip),
            )

        self.audit.log_event("HOST_SWEEP_COMPLETE", cidr=cidr,
                              tcp_hosts=len(tcp_up),
                              udp_only_hosts=len(udp_only))

    def _get_hostname(self, ip: str) -> str:
        try:
            return self.nm[ip].hostname()
        except Exception:
            return ""

    def _get_mac(self, ip: str) -> str:
        try:
            return self.nm[ip]["addresses"].get("mac", "")
        except Exception:
            return ""
