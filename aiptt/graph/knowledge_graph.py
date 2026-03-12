"""
Neo4j-backed knowledge graph.

FR-DISC-05: Real-time graph with atomic update guarantee.
All write operations use explicit transactions that rollback on failure.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Generator

from aiptt.core.config import get_config
from aiptt.graph import queries as Q
from aiptt.graph.models import (
    HostNode, VulnerabilityNode, CredentialNode, AttackPathEdge,
)


class KnowledgeGraph:
    """
    Neo4j-backed graph of assets, credentials, and attack paths.

    Business Rule: Updates must be atomic — partial updates rolled back on failure.
    """

    def __init__(self, uri: str | None = None,
                 auth: tuple | None = None,
                 audit=None):
        cfg = get_config()
        _uri  = uri  or cfg.neo4j.uri
        _user = auth[0] if auth else cfg.neo4j.user
        _pass = auth[1] if auth else os.environ.get(cfg.neo4j.password_env, "neo4j")

        from neo4j import GraphDatabase
        self.driver = GraphDatabase.driver(_uri, auth=(_user, _pass))
        self.audit  = audit

    # ------------------------------------------------------------------
    # Context manager for atomic sessions
    # ------------------------------------------------------------------

    @contextmanager
    def _atomic_session(self) -> Generator:
        """Context manager ensuring atomic graph writes (rollback on error)."""
        with self.driver.session() as session:
            tx = session.begin_transaction()
            try:
                yield tx
                tx.commit()
            except Exception as e:
                tx.rollback()
                if self.audit:
                    self.audit.log_event("GRAPH_UPDATE_ROLLBACK", reason=str(e))
                raise

    # ------------------------------------------------------------------
    # Host operations
    # ------------------------------------------------------------------

    def add_host(self, node: HostNode) -> None:
        with self._atomic_session() as tx:
            tx.run(Q.UPSERT_HOST,
                   ip=node.ip,
                   hostname=node.hostname,
                   os=node.os,
                   udp_only=node.udp_only,
                   honeypot=node.suspected_honeypot,
                   scan_incomplete=node.scan_incomplete,
                   domain=node.domain)

    def get_host_metadata(self, ip: str) -> dict:
        with self.driver.session() as session:
            result = session.run(Q.GET_HOST_METADATA, ip=ip)
            record = result.single()
            if record:
                h = record["h"]
                return dict(h)
            return {}

    # ------------------------------------------------------------------
    # Vulnerability operations
    # ------------------------------------------------------------------

    def add_vulnerability(self, node: VulnerabilityNode) -> None:
        with self._atomic_session() as tx:
            tx.run(Q.UPSERT_VULNERABILITY,
                   ip=node.ip,
                   cve_id=node.cve_id,
                   cvss=node.cvss,
                   severity=node.severity,
                   service=node.service,
                   description=node.description,
                   port=node.port)

    def mark_exploited(self, ip: str, cve_id: str, port: int,
                       finding_id: str) -> None:
        with self._atomic_session() as tx:
            tx.run(Q.MARK_EXPLOITED, ip=ip, cve_id=cve_id,
                   port=port, finding_id=finding_id)

    # ------------------------------------------------------------------
    # Credential operations
    # ------------------------------------------------------------------

    def add_credential(self, node: CredentialNode) -> None:
        """
        Stores a vault reference — NOT the actual credential.
        Actual credential is in the AES-256 vault (BR-SAFE-06).
        """
        with self._atomic_session() as tx:
            tx.run(Q.UPSERT_CREDENTIAL,
                   ref=node.ref,
                   username=node.username,
                   cred_type=node.cred_type,
                   source_ip=node.source_ip,
                   domain=node.domain)

    # ------------------------------------------------------------------
    # Attack path operations
    # ------------------------------------------------------------------

    def add_attack_path(self, edge: AttackPathEdge) -> None:
        with self._atomic_session() as tx:
            tx.run(Q.UPSERT_ATTACK_PATH,
                   from_ip=edge.from_ip,
                   to_ip=edge.to_ip,
                   technique=edge.technique,
                   via_cred=edge.via_credential,
                   success=edge.success)

    def get_attack_paths_ranked(self) -> list[dict]:
        """Returns exploitable paths sorted by impact × feasibility score."""
        with self.driver.session() as session:
            result = session.run(Q.GET_ATTACK_PATHS_RANKED)
            return [dict(record) for record in result]

    # ------------------------------------------------------------------
    # OPAV OBSERVE phase
    # ------------------------------------------------------------------

    def get_unexhausted_targets(self) -> list[dict]:
        """Returns hosts with unexploited vulnerabilities for OPAV planning."""
        with self.driver.session() as session:
            result = session.run(Q.GET_UNEXHAUSTED_TARGETS)
            return [dict(record) for record in result]

    # ------------------------------------------------------------------
    # Circular pivot detection (FR-AI-03)
    # ------------------------------------------------------------------

    def has_visited_twice(self, ip: str) -> bool:
        """Returns True if the agent has visited this host 2+ times."""
        with self.driver.session() as session:
            result = session.run(Q.GET_VISIT_COUNT, ip=ip)
            record = result.single()
            return (int(record["visits"]) >= 2) if record else False

    def increment_visit(self, ip: str) -> None:
        with self._atomic_session() as tx:
            tx.run(Q.INCREMENT_VISIT, ip=ip)

    # ------------------------------------------------------------------
    # Ingest finding (called after successful exploitation)
    # ------------------------------------------------------------------

    def ingest_finding(self, finding) -> None:
        """Update the graph with the result of a confirmed exploit."""
        try:
            ip  = getattr(finding, "target_ip", None) or ""
            cve = getattr(finding, "technique", "") or ""
            if ip:
                self.increment_visit(ip)
            # Mark technique/module as used for this host
        except Exception as e:
            if self.audit:
                self.audit.log_event("GRAPH_INGEST_ERROR", error=str(e))

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self) -> dict:
        with self.driver.session() as session:
            result = session.run(Q.GET_GRAPH_STATS)
            record = result.single()
            return dict(record) if record else {}

    def close(self) -> None:
        self.driver.close()
