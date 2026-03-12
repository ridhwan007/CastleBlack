"""
Knowledge graph node and edge type definitions.

These are plain Python dataclasses used to pass structured data
to/from the KnowledgeGraph. The actual persistence is in Neo4j.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class HostNode:
    ip: str
    hostname: str = ""
    os: str = ""
    udp_only: bool = False
    suspected_honeypot: bool = False
    scan_incomplete: bool = False
    tags: list[str] = field(default_factory=list)
    domain: str = ""


@dataclass
class ServiceNode:
    ip: str
    port: int
    proto: str
    name: str
    version: str = ""
    product: str = ""
    extrainfo: str = ""


@dataclass
class VulnerabilityNode:
    ip: str
    port: int
    cve_id: str
    cvss: float
    severity: str
    description: str = ""
    service: str = ""


@dataclass
class CredentialNode:
    ref: str               # Vault reference (never the actual credential)
    username: str
    cred_type: str         # ntlm_hash | kerberos_ticket | plaintext | asrep_hash
    source_ip: str
    domain: str = ""


@dataclass
class AttackPathEdge:
    from_ip: str
    to_ip: str
    technique: str         # MITRE ATT&CK ID
    via_credential: Optional[str] = None   # Vault ref
    success: bool = False
