"""
Immutable HMAC-chained audit logger.

NFR-AUDIT-01: Every log entry is HMAC-chained to the previous one.
Tampering with any entry breaks the chain and triggers a CISO alert.

Business Rule: Log write failure does NOT block execution but MUST
               trigger an emergency alert (FR-AI-05 edge case).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

from aiptt.core.config import get_config


class AuditLogger:
    """
    Append-only HMAC-chained SQLite audit log.

    Each entry contains:
      - Sequential auto-increment ID
      - UTC timestamp (ISO 8601)
      - Event type string
      - JSON payload
      - HMAC of (prev_hmac || timestamp || payload) keyed by AIPTT_AUDIT_KEY

    All writes are serialized via a threading lock for thread safety.
    """

    HMAC_ALGO = "sha256"
    GENESIS   = "GENESIS"  # Sentinel previous-HMAC for the first entry

    def __init__(self, db_path: str | None = None):
        cfg     = get_config()
        path    = db_path or cfg.audit.log_path
        self.db_path = Path(path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        key_str  = os.environ.get("AIPTT_AUDIT_KEY", "")
        self._key = key_str.encode() if key_str else b"default-insecure-key"

        self._lock = Lock()
        self._conn = self._init_db()
        self._last_hmac = self._get_last_hmac()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log_intent(self, event_type: str, **kwargs) -> None:
        """
        Pre-action intent log.  Called BEFORE execution (FR-AI-05 rule).
        Prefixes the event_type with INTENT_.
        """
        self._write(f"INTENT_{event_type}", kwargs)

    def log_event(self, event_type: str, **kwargs) -> None:
        """Post-action event log."""
        self._write(event_type, kwargs)

    def verify_chain_integrity(self) -> bool:
        """
        Walk the entire log and verify every HMAC link.
        Returns True if chain is intact; False if tamper detected.
        Triggers a CISO alert when tampering is found.
        """
        rows = self._conn.execute(
            "SELECT ts, event_type, payload, entry_hmac FROM audit_log ORDER BY id"
        ).fetchall()

        prev_hmac = self.GENESIS
        for ts, event_type, payload, stored_hmac in rows:
            expected = self._compute_hmac_raw(prev_hmac, ts, payload)
            if not hmac.compare_digest(expected, stored_hmac):
                self._emergency_alert(
                    "CHAIN_INTEGRITY_BROKEN",
                    f"Tamper detected at ts={ts}, event={event_type}",
                )
                return False
            prev_hmac = stored_hmac
        return True

    def recent_events(self, limit: int = 50) -> list[dict]:
        """Return the N most recent audit entries."""
        rows = self._conn.execute(
            "SELECT id, ts, event_type, payload FROM audit_log "
            "ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
        result = []
        for row_id, ts, event_type, payload in rows:
            try:
                data = json.loads(payload)
            except json.JSONDecodeError:
                data = {"raw": payload}
            result.append({"id": row_id, "ts": ts, "event": event_type, "data": data})
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _init_db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts          TEXT    NOT NULL,
                event_type  TEXT    NOT NULL,
                payload     TEXT    NOT NULL,
                entry_hmac  TEXT    NOT NULL
            )
        """)
        conn.execute("PRAGMA journal_mode=WAL")   # Append-only WAL mode
        conn.commit()
        return conn

    def _write(self, event_type: str, payload: dict) -> None:
        ts          = datetime.now(timezone.utc).isoformat()
        payload_str = json.dumps(payload, default=str)
        entry_hmac  = self._compute_hmac_raw(self._last_hmac, ts, payload_str)

        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO audit_log (ts, event_type, payload, entry_hmac) "
                    "VALUES (?, ?, ?, ?)",
                    (ts, event_type, payload_str, entry_hmac),
                )
                self._conn.commit()
                self._last_hmac = entry_hmac
            except Exception as e:
                # Edge case: log write failure — alert but DO NOT block (FR-AI-05)
                self._emergency_alert(event_type, str(e))

    def _compute_hmac_raw(self, prev_hmac: str, ts: str, payload: str) -> str:
        msg = f"{prev_hmac}|{ts}|{payload}".encode()
        return hmac.new(self._key, msg, self.HMAC_ALGO).hexdigest()

    def _get_last_hmac(self) -> str:
        row = self._conn.execute(
            "SELECT entry_hmac FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else self.GENESIS

    def _emergency_alert(self, event_type: str, reason: str) -> None:
        """Fallback alert when audit log is compromised or write fails."""
        # Write to syslog on Linux; fallback to stderr on other platforms
        try:
            import syslog
            syslog.syslog(
                syslog.LOG_CRIT,
                f"AIPTT AUDIT ALERT [{event_type}]: {reason}",
            )
        except (ImportError, OSError):
            import sys
            print(
                f"[AIPTT AUDIT ALERT] [{event_type}]: {reason}",
                file=sys.stderr,
            )


# ---------------------------------------------------------------------------
# Singleton accessor (shared across modules)
# ---------------------------------------------------------------------------

_default_logger: AuditLogger | None = None
_logger_lock = Lock()


def get_audit_logger() -> AuditLogger:
    """Return the process-level singleton AuditLogger."""
    global _default_logger
    if _default_logger is None:
        with _logger_lock:
            if _default_logger is None:
                _default_logger = AuditLogger()
    return _default_logger
