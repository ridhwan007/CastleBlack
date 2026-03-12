"""
Network utility helpers.

IP validation, CIDR helpers, and hostname resolution.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Generator


def is_valid_ip(ip: str) -> bool:
    """Return True if the string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_cidr(cidr: str) -> bool:
    """Return True if the string is a valid CIDR notation."""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def ip_in_cidr(ip: str, cidr: str) -> bool:
    """Return True if ip falls within the given CIDR."""
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def cidr_hosts(cidr: str) -> Generator[str, None, None]:
    """Yield all usable host IPs in a CIDR (excludes network/broadcast for /24+)."""
    net = ipaddress.ip_network(cidr, strict=False)
    for host in net.hosts():
        yield str(host)


def resolve_hostname(hostname: str) -> str:
    """Resolve a hostname to its primary IPv4 address. Returns '' on failure."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return ""


def reverse_lookup(ip: str) -> str:
    """Reverse DNS lookup. Returns '' on failure."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return ""


def parse_port_spec(spec: str) -> list[int]:
    """
    Parse a port specification string into a list of integers.

    Examples:
        "80"            → [80]
        "80,443"        → [80, 443]
        "8000-8010"     → [8000, 8001, ..., 8010]
        "80,443,8000-8002" → [80, 443, 8000, 8001, 8002]
    """
    ports: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.extend(range(int(lo), int(hi) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))
