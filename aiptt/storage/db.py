"""
SQLAlchemy engine and session factory.

Supports SQLite (dev/default) and PostgreSQL (prod).
Connection string priority:
  1. POSTGRESQL_URL env var (if set)
  2. config.database.postgresql_url (if engine == "postgresql")
  3. SQLite at config.database.sqlite_path (default)
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session, DeclarativeBase

from aiptt.core.config import get_config

# ---------------------------------------------------------------------------
# Base for all ORM models
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Engine factory (lazy init, cached)
# ---------------------------------------------------------------------------

_engine = None
_SessionFactory = None


def _get_db_url() -> str:
    cfg = get_config()

    # 1. Env var override (highest priority)
    pg_url = os.environ.get("POSTGRESQL_URL", "")
    if pg_url:
        return pg_url

    # 2. Config-defined PostgreSQL
    if cfg.database.engine == "postgresql" and cfg.database.postgresql_url:
        return cfg.database.postgresql_url

    # 3. SQLite (default)
    sqlite_path = Path(cfg.database.sqlite_path).expanduser()
    sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{sqlite_path}"


def get_engine():
    global _engine
    if _engine is None:
        url = _get_db_url()
        kwargs = {}
        if url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False}
        _engine = create_engine(url, **kwargs)

        # Enable WAL mode for SQLite (better concurrency + immutability support)
        if url.startswith("sqlite"):
            @event.listens_for(_engine, "connect")
            def set_wal_mode(dbapi_conn, _):
                dbapi_conn.execute("PRAGMA journal_mode=WAL")

    return _engine


def get_session_factory() -> sessionmaker:
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(bind=get_engine(), expire_on_commit=False)
    return _SessionFactory


def init_db() -> None:
    """Create all tables. Called once at engagement init."""
    from aiptt.storage import models  # noqa: F401 — registers ORM models
    Base.metadata.create_all(get_engine())


@contextmanager
def get_session() -> Generator[Session, None, None]:
    """Context manager yielding a SQLAlchemy session with auto-commit/rollback."""
    factory = get_session_factory()
    session: Session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
