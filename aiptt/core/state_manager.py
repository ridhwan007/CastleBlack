"""
Session state manager.

Tracks the mutable runtime state of a single engagement:
  - Scope boundaries
  - Compromised host list
  - Credential cache (vault references only — never plaintext)
  - Pivot depth counter
  - OPAV cycle counter
  - Checkpoint save/restore (FR-AI-02)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from aiptt.core.config import get_config
from aiptt.guardrail.scope_enforcer import ScopeEnforcer


@dataclass
class EngagementConfig:
    """Parsed config for a single engagement (passed to pre-flight checks)."""
    engagement_id: str
    name: str
    cidr: str
    roe_path: Path
    domains: list[str] = field(default_factory=list)
    exclusions: list[str] = field(default_factory=list)
    blast_radius: str = "conservative"
    time_limit_hrs: int = 8
    output_dir: Path = Path(".")
    tags: list[str] = field(default_factory=list)
    no_ad: bool = False
    no_ai_planner: bool = False
    # Nessus import mode — when set, live scanning is skipped entirely
    nessus_file: Path | None = None


class SessionState:
    """
    Mutable runtime state for one OPAV engagement.

    The knowledge_graph attribute is set externally after graph init.
    """

    def __init__(self, config: EngagementConfig):
        self.config         = config
        self.engagement_id  = config.engagement_id
        self.scope_enforcer = ScopeEnforcer(
            [config.cidr], config.exclusions
        )

        self.compromised_hosts: list[str]  = []
        self.credential_cache: list[dict]  = []  # Vault refs only
        self.pivot_count: int              = 0
        self.cycle: int                    = 0
        self._visited: dict[str, int]      = {}  # ip → visit count
        self._scoped_domains: set[str]     = set(config.domains)
        # Nessus-mode fallback: observations populated from parsed file
        # Used by OPAV OBSERVE phase when Neo4j KG is unavailable
        self.nessus_observations: list[dict] = []

        self.knowledge_graph = None   # Set after graph init
        self._started_at     = datetime.now(timezone.utc)

        cfg = get_config()
        self._time_limit    = timedelta(hours=config.time_limit_hrs)
        self._output_dir    = config.output_dir
        self._checkpoint_path = config.output_dir / "state.json"

    # ------------------------------------------------------------------
    # Scope helpers
    # ------------------------------------------------------------------

    def is_in_scope(self, ip: str) -> bool:
        return self.scope_enforcer.is_in_scope(ip)

    def is_domain_in_scope(self, domain: str) -> bool:
        return domain in self._scoped_domains

    def is_scope_exhausted(self) -> bool:
        """
        True when:
          - Time limit exceeded, OR
          - Knowledge graph has no unexhausted targets
        """
        elapsed = datetime.now(timezone.utc) - self._started_at
        if elapsed >= self._time_limit:
            return True
        if self.knowledge_graph:
            targets = self.knowledge_graph.get_unexhausted_targets()
            return len(targets) == 0
        return False

    def is_time_exceeded(self) -> bool:
        elapsed = datetime.now(timezone.utc) - self._started_at
        return elapsed >= self._time_limit

    # ------------------------------------------------------------------
    # Pivot / compromise tracking
    # ------------------------------------------------------------------

    def add_compromised_host(self, ip: str) -> None:
        if ip not in self.compromised_hosts:
            self.compromised_hosts.append(ip)
        self._visited[ip] = self._visited.get(ip, 0) + 1

    def increment_pivot_count(self) -> None:
        self.pivot_count += 1

    def reset_pivot_count(self) -> None:
        self.pivot_count = 0

    def has_visited_twice(self, ip: str) -> bool:
        """Circular pivot detection (FR-AI-03 edge case)."""
        return self._visited.get(ip, 0) >= 2

    def mark_host_exhausted(self, ip: str) -> None:
        """Mark a host as fully exhausted so it is never targeted again."""
        self._visited[ip] = 2

    def get_host_observation(self, ip: str) -> dict | None:
        """Return the Nessus observation dict for a host IP, or None."""
        for obs in self.nessus_observations:
            if obs.get("ip") == ip:
                return obs
        return None

    def update_cycle(self, cycle: int) -> None:
        self.cycle = cycle
        self.save_checkpoint()

    # ------------------------------------------------------------------
    # Credential cache (vault refs)
    # ------------------------------------------------------------------

    def add_credential_ref(self, vault_ref: str, metadata: dict) -> None:
        """Store a vault reference (never the actual credential)."""
        self.credential_cache.append({"vault_ref": vault_ref, **metadata})

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def record_finding(self, task, result, poe_result) -> object:
        """Persist a confirmed finding to the DB and return the Finding object."""
        from aiptt.storage.db import get_session
        from aiptt.storage.models import Finding, AttackChainSnapshot
        import json as _json

        cvss = 0.0
        if self.knowledge_graph:
            try:
                targets = self.knowledge_graph.get_unexhausted_targets()
                for t in targets:
                    if t["ip"] == task.target:
                        vulns = t.get("vulnerabilities", [])
                        if vulns:
                            cvss = max(v.get("cvss", 0) for v in vulns)
                        break
            except Exception:
                pass

        from aiptt.utils.crypto import sha256_bytes
        with get_session() as session:
            finding = Finding(
                engagement_id=self.engagement_id,
                status="OPEN",
                classification=poe_result.classification,
                severity=_cvss_to_severity(cvss),
                title=f"{task.module_id} → {task.target}",
                description=result.output[:500] if result.output else "",
                cvss_score=cvss,
                target_ip=task.target,
                technique=task.technique,
                module_id=task.module_id,
                poe_vault_ref=poe_result.vault_ref,
                gained_access=result.gained_access,
                access_level=result.access_level,
            )
            session.add(finding)
            session.flush()

            # Snapshot the exact attack chain for fix-verify
            snapshot = AttackChainSnapshot(
                finding_id=finding.id,
                task_json=_json.dumps(task.__dict__, default=str),
                result_json=_json.dumps(result.__dict__, default=str),
            )
            session.add(snapshot)

        return finding

    def record_informational_finding(self, title: str, description: str,
                                      target: str) -> None:
        """Record an INFO-level finding (e.g. trust boundary, honeypot)."""
        from aiptt.storage.db import get_session
        from aiptt.storage.models import Finding
        with get_session() as session:
            session.add(Finding(
                engagement_id=self.engagement_id,
                status="OPEN",
                classification="THEORETICAL",
                severity="INFO",
                title=title,
                description=description,
                target_ip=target,
            ))

    def validate_hitl_token(self, token: str) -> bool:
        """Validate a human-in-the-loop approval token."""
        from aiptt.storage.db import get_session
        from aiptt.storage.models import AuthorisationToken
        with get_session() as session:
            t = session.query(AuthorisationToken).filter_by(token=token).first()
            return t is not None and not t.is_expired()

    # ------------------------------------------------------------------
    # Checkpoint (FR-AI-02)
    # ------------------------------------------------------------------

    def save_checkpoint(self) -> None:
        """Persist current state to state.json for crash recovery."""
        try:
            state = {
                "engagement_id": self.engagement_id,
                "name": self.config.name,
                "status": "RUNNING",
                "created_at": self._started_at.isoformat(),
                "scope": {
                    "cidr": [self.config.cidr],
                    "domains": self.config.domains,
                    "exclusions": self.config.exclusions,
                    "blast_radius": self.config.blast_radius,
                },
                "opav_cycle": self.cycle,
                "pivot_count": self.pivot_count,
                "phase": "ATTACK_EXECUTION",
                "last_checkpoint": datetime.now(timezone.utc).isoformat(),
                "compromised_hosts": self.compromised_hosts,
                "discovered_credentials": len(self.credential_cache),
            }
            self._checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
            self._checkpoint_path.write_text(json.dumps(state, indent=2))
        except Exception:
            pass  # Never crash OPAV loop due to checkpoint failure

    @classmethod
    def restore_from_checkpoint(cls, checkpoint_path: Path,
                                 config: EngagementConfig) -> "SessionState":
        """Restore state from a saved checkpoint (FR-AI-02)."""
        state = cls(config)
        try:
            data = json.loads(checkpoint_path.read_text())
            state.compromised_hosts = data.get("compromised_hosts", [])
            state.pivot_count       = data.get("pivot_count", 0)
            state.cycle             = data.get("opav_cycle", 0)
        except Exception:
            pass
        return state


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0.0:  return "LOW"
    return "INFO"
