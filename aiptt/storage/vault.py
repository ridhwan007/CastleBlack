"""
AES-256-GCM encrypted artefact vault.

Credentials and PoE artefacts are encrypted at rest.
Master key sourced exclusively from the AIPTT_MASTER_KEY environment variable.
Auto-deletion enforced by RetentionJob (BR-SAFE-06).
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from aiptt.core.config import get_config


class ArtifactVault:
    """
    AES-256-GCM encrypted storage for credentials and PoE artefacts.

    Key sourced from environment (AIPTT_MASTER_KEY) — never stored on disk.
    Auto-deletion enforced by RetentionJob (BR-SAFE-06).

    Storage format per file:
        [12-byte nonce][ciphertext with 16-byte GCM auth tag]
    Associated data: finding_id bytes (authenticated but not encrypted).
    """

    def __init__(self, vault_path: str | None = None, audit=None):
        cfg = get_config()
        key_env = cfg.encryption.key_env
        key_hex = os.environ.get(key_env, "")
        if not key_hex:
            raise EnvironmentError(
                f"Environment variable {key_env} is not set. "
                "AES-256 master key required for vault operations."
            )
        if len(key_hex) != 64:
            raise ValueError(
                f"{key_env} must be exactly 64 hex characters (32 bytes for AES-256). "
                f"Got {len(key_hex)} characters."
            )
        self.key = bytes.fromhex(key_hex)

        path = vault_path or cfg.encryption.vault_path
        self.vault_dir = Path(path).expanduser()
        self.vault_dir.mkdir(parents=True, exist_ok=True)

        self.audit = audit
        self.retention_days = cfg.retention.artefact_retention_days

    # ------------------------------------------------------------------
    # Store
    # ------------------------------------------------------------------

    def store(self, finding_id: str, data: bytes, artefact_type: str) -> str:
        """
        Encrypt and persist artefact data.

        Returns vault_ref string (used as the filename stem and DB reference).
        """
        nonce  = os.urandom(12)          # 96-bit nonce for AES-GCM
        aesgcm = AESGCM(self.key)
        # Use finding_id as authenticated additional data
        ct = aesgcm.encrypt(nonce, data, finding_id.encode())

        ref      = f"{finding_id}-{artefact_type}"
        out_path = self.vault_dir / f"{ref}.enc"
        out_path.write_bytes(nonce + ct)   # nonce prepended for decryption

        # Record in retention log
        self._register_retention(ref, finding_id)

        if self.audit:
            self.audit.log_event("VAULT_STORE", ref=ref, size=len(data))

        return ref

    # ------------------------------------------------------------------
    # Retrieve
    # ------------------------------------------------------------------

    def retrieve(self, vault_ref: str) -> bytes:
        """Decrypt and return artefact bytes."""
        path = self.vault_dir / f"{vault_ref}.enc"
        if not path.exists():
            raise FileNotFoundError(f"Vault artefact not found: {vault_ref}")

        raw   = path.read_bytes()
        nonce = raw[:12]
        ct    = raw[12:]

        # Reconstruct finding_id from vault_ref (format: FIND-XXXXXXXX-artefact_type)
        parts      = vault_ref.split("-")
        finding_id = f"{parts[0]}-{parts[1]}" if len(parts) >= 2 else vault_ref

        aesgcm = AESGCM(self.key)
        if self.audit:
            self.audit.log_event("VAULT_RETRIEVE", ref=vault_ref)

        return aesgcm.decrypt(nonce, ct, finding_id.encode())

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _register_retention(self, vault_ref: str, finding_id: str) -> None:
        """Register artefact in retention log for auto-deletion tracking."""
        try:
            from aiptt.storage.db import get_session
            from aiptt.storage.models import ArtefactRetentionLog

            now     = datetime.now(timezone.utc)
            expires = now + timedelta(days=self.retention_days)

            with get_session() as session:
                existing = session.query(ArtefactRetentionLog).filter_by(
                    vault_ref=vault_ref).first()
                if not existing:
                    session.add(ArtefactRetentionLog(
                        vault_ref=vault_ref,
                        finding_id=finding_id,
                        created_at=now.isoformat(),
                        expires_at=expires.isoformat(),
                    ))
        except Exception:
            # Don't fail vault operations due to retention log issues
            pass
