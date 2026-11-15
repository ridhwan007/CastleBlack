"""
Artefact retention auto-deletion job.

BR-SAFE-06: 90-day default retention, max 365 days.
Run via: aiptt admin purge
or schedule as a cron job.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from aiptt.core.config import get_config


class RetentionJob:
    """
    Deletes vault artefacts past their retention period.
    Each deletion is confirmed in the audit log (BR-SAFE-06).
    Uses secure overwrite before unlink (prevents forensic recovery).
    """

    def __init__(
        self,
        vault_path: str | None = None,
        audit=None,
        retention_days: int | None = None,
    ):
        cfg = get_config()
        self.vault_dir      = Path(vault_path or cfg.encryption.vault_path).expanduser()
        self.audit          = audit
        self.retention_days = retention_days or cfg.retention.artefact_retention_days

    # ------------------------------------------------------------------
    # Main job
    # ------------------------------------------------------------------

    def run(self) -> dict[str, int]:
        """
        Scan retention log for expired artefacts and delete them.

        Returns summary: {"deleted": n, "errors": m}
        """
        from aiptt.storage.db import get_session
        from aiptt.storage.models import ArtefactRetentionLog

        now     = datetime.now(timezone.utc)
        deleted = 0
        errors  = 0

        with get_session() as session:
            due = session.query(ArtefactRetentionLog).filter(
                ArtefactRetentionLog.expires_at <= now.isoformat(),
                ArtefactRetentionLog.deleted_at.is_(None),
            ).all()

        for record in due:
            enc_file = self.vault_dir / f"{record.vault_ref}.enc"
            try:
                if enc_file.exists():
                    self._secure_delete(enc_file)

                with get_session() as session:
                    r = session.query(ArtefactRetentionLog).filter_by(
                        vault_ref=record.vault_ref).first()
                    if r:
                        r.deleted_at = now.isoformat()

                if self.audit:
                    self.audit.log_event(
                        "ARTEFACT_DELETED",
                        vault_ref=record.vault_ref,
                        reason="retention_expired",
                    )
                deleted += 1

            except Exception as e:
                errors += 1
                if self.audit:
                    self.audit.log_event(
                        "ARTEFACT_DELETE_ERROR",
                        vault_ref=record.vault_ref,
                        error=str(e),
                    )

        return {"deleted": deleted, "errors": errors}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _secure_delete(self, path: Path) -> None:
        """
        Overwrite file content with random bytes before deletion.
        Prevents forensic recovery of sensitive artefacts.
        """
        size = path.stat().st_size
        with open(path, "r+b") as f:
            f.write(os.urandom(size))
            f.flush()
            os.fsync(f.fileno())
        path.unlink()

    def list_due(self) -> list[dict]:
        """Return artefacts currently due for deletion (dry-run helper)."""
        from aiptt.storage.db import get_session
        from aiptt.storage.models import ArtefactRetentionLog

        now = datetime.now(timezone.utc)
        with get_session() as session:
            due = session.query(ArtefactRetentionLog).filter(
                ArtefactRetentionLog.expires_at <= now.isoformat(),
                ArtefactRetentionLog.deleted_at.is_(None),
            ).all()
            return [
                {"vault_ref": r.vault_ref, "expires_at": r.expires_at}
                for r in due
            ]
