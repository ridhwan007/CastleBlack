"""
SQLAlchemy ORM models for all AIPTT database tables.

Schema matches Section 20 of the backend implementation guide.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    Boolean, Column, Float, ForeignKey, Integer, String, Text, DateTime,
)
from sqlalchemy.orm import relationship

from aiptt.storage.db import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_iso() -> str:
    return _now().isoformat()


# ---------------------------------------------------------------------------
# Engagement
# ---------------------------------------------------------------------------

class Engagement(Base):
    __tablename__ = "engagements"

    id              = Column(String, primary_key=True, default=lambda: f"ENG-{str(uuid.uuid4())[:8].upper()}")
    name            = Column(String, nullable=False)
    status          = Column(String, nullable=False, default="INIT")
    # INIT | RUNNING | PAUSED | COMPLETE | KILLED
    roe_hash        = Column(String, nullable=False)
    cidr            = Column(String, nullable=False)
    domains         = Column(Text, default="[]")    # JSON array
    exclusions      = Column(Text, default="[]")    # JSON array
    blast_radius    = Column(String, nullable=False, default="conservative")
    created_at      = Column(String, nullable=False, default=_utc_iso)
    updated_at      = Column(String, nullable=False, default=_utc_iso, onupdate=_utc_iso)
    closed_at       = Column(String, nullable=True)
    time_limit_hrs  = Column(Integer, default=8)
    tags            = Column(Text, default="[]")    # JSON array

    findings        = relationship("Finding", back_populates="engagement",
                                   cascade="all, delete-orphan")

    def get_domains(self) -> list[str]:
        return json.loads(self.domains or "[]")

    def get_exclusions(self) -> list[str]:
        return json.loads(self.exclusions or "[]")

    def get_tags(self) -> list[str]:
        return json.loads(self.tags or "[]")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "status": self.status,
            "roe_hash": self.roe_hash,
            "cidr": self.cidr,
            "domains": self.get_domains(),
            "exclusions": self.get_exclusions(),
            "blast_radius": self.blast_radius,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "time_limit_hrs": self.time_limit_hrs,
            "tags": self.get_tags(),
        }


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

class Finding(Base):
    __tablename__ = "findings"

    id                  = Column(String, primary_key=True,
                                 default=lambda: f"FIND-{str(uuid.uuid4())[:8].upper()}")
    engagement_id       = Column(String, ForeignKey("engagements.id"), nullable=False)
    parent_finding_id   = Column(String, ForeignKey("findings.id"), nullable=True)
    status              = Column(String, nullable=False, default="OPEN")
    # OPEN | REMEDIATED | REGRESSION | THEORETICAL | UNCONFIRMED
    classification      = Column(String, nullable=False)
    # CONFIRMED | UNCONFIRMED | THEORETICAL
    severity            = Column(String, nullable=False)
    # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title               = Column(String, nullable=False)
    description         = Column(Text, nullable=True)
    cvss_score          = Column(Float, nullable=True)
    target_ip           = Column(String, nullable=True)
    target_port         = Column(Integer, nullable=True)
    technique           = Column(String, nullable=True)   # MITRE ATT&CK ID
    module_id           = Column(String, nullable=True)
    poe_vault_ref       = Column(String, nullable=True)
    remediation         = Column(Text, nullable=True)
    compensating_controls = Column(Text, nullable=True)  # JSON array
    compliance_tags     = Column(Text, default="[]")     # JSON array
    created_at          = Column(String, nullable=False, default=_utc_iso)
    updated_at          = Column(String, nullable=False, default=_utc_iso, onupdate=_utc_iso)
    access_level        = Column(String, default="none")
    gained_access       = Column(Boolean, default=False)

    engagement          = relationship("Engagement", back_populates="findings")
    attack_chain        = relationship("AttackChainSnapshot", back_populates="finding",
                                       uselist=False, cascade="all, delete-orphan")

    def get_compliance_tags(self) -> list[str]:
        return json.loads(self.compliance_tags or "[]")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "engagement_id": self.engagement_id,
            "status": self.status,
            "classification": self.classification,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "cvss_score": self.cvss_score,
            "target": self.target_ip,
            "target_port": self.target_port,
            "technique": self.technique,
            "module_id": self.module_id,
            "poe_vault_ref": self.poe_vault_ref or "",
            "remediation": self.remediation or "",
            "compensating_controls": json.loads(self.compensating_controls or "[]"),
            "compliance_tags": self.get_compliance_tags(),
            "created_at": self.created_at,
        }


# ---------------------------------------------------------------------------
# AttackChainSnapshot
# ---------------------------------------------------------------------------

class AttackChainSnapshot(Base):
    __tablename__ = "attack_chain_snapshots"

    id          = Column(String, primary_key=True,
                         default=lambda: f"SNAP-{str(uuid.uuid4())[:8].upper()}")
    finding_id  = Column(String, ForeignKey("findings.id"), nullable=False, unique=True)
    task_json   = Column(Text, nullable=False)    # Serialised AttackTask
    result_json = Column(Text, nullable=False)    # Serialised AttackResult
    created_at  = Column(String, nullable=False, default=_utc_iso)

    finding     = relationship("Finding", back_populates="attack_chain")

    def to_attack_task(self):
        """Reconstruct AttackTask from stored JSON snapshot."""
        from aiptt.engine.ai_planner import AttackTask
        data = json.loads(self.task_json)
        return AttackTask(**data)


# ---------------------------------------------------------------------------
# HumanReviewQueue
# ---------------------------------------------------------------------------

class HumanReviewQueue(Base):
    __tablename__ = "human_review_queue"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    task_id     = Column(String, nullable=False)
    module_id   = Column(String, nullable=False)
    target      = Column(String, nullable=False)
    reason      = Column(String, nullable=False)
    payload     = Column(Text, nullable=True)     # Exploit code, truncated to 5KB
    status      = Column(String, default="PENDING")  # PENDING | APPROVED | REJECTED
    reviewed_by = Column(String, nullable=True)
    reviewed_at = Column(String, nullable=True)
    created_at  = Column(String, nullable=False, default=_utc_iso)


# ---------------------------------------------------------------------------
# AuthorisationToken
# ---------------------------------------------------------------------------

class AuthorisationToken(Base):
    __tablename__ = "authorisation_tokens"

    token           = Column(String, primary_key=True)
    purpose         = Column(String, nullable=False)
    # dcsync_production | crown_jewel | dos_enable
    issued_by       = Column(String, nullable=False)
    issued_at       = Column(String, nullable=False, default=_utc_iso)
    expires_at      = Column(String, nullable=False)
    used_at         = Column(String, nullable=True)
    engagement_id   = Column(String, ForeignKey("engagements.id"), nullable=True)

    def is_expired(self) -> bool:
        try:
            exp = datetime.fromisoformat(self.expires_at.rstrip("Z"))
            exp = exp.replace(tzinfo=timezone.utc)
            return _now() > exp
        except (ValueError, AttributeError):
            return True


# ---------------------------------------------------------------------------
# CredentialSprayLog
# ---------------------------------------------------------------------------

class CredentialSprayLog(Base):
    __tablename__ = "credential_spray_log"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    engagement_id = Column(String, nullable=False)
    target_dc     = Column(String, nullable=False)
    username      = Column(String, nullable=False)
    attempt_at    = Column(String, nullable=False, default=_utc_iso)
    success       = Column(Boolean, nullable=False, default=False)


# ---------------------------------------------------------------------------
# ArtefactRetentionLog
# ---------------------------------------------------------------------------

class ArtefactRetentionLog(Base):
    __tablename__ = "artefact_retention_log"

    vault_ref   = Column(String, primary_key=True)
    finding_id  = Column(String, nullable=False)
    created_at  = Column(String, nullable=False, default=_utc_iso)
    expires_at  = Column(String, nullable=False)  # created_at + retention_days
    deleted_at  = Column(String, nullable=True)   # Null until deletion job runs
