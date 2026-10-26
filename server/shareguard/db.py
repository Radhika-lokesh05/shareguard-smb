"""shareguard.db – SQLAlchemy models, engine, and session factory.

Database: SQLite (file-based for LIVE, in-memory for tests).
ORM: SQLAlchemy 2.x declarative style.

Models:
- :class:`AlertModel`    – persisted alerts.
- :class:`ClientModel`   – known clients (IP + username pairs).
- :class:`EventModel`    – raw audit events (optional ring-buffer table).
- :class:`AuditLogModel` – audit log of administrative actions taken via API.

Session usage::

    from shareguard.db import get_session

    with get_session() as session:
        session.add(...)
        session.commit()
"""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Engine, Float, Integer, String, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

__all__ = [
    "Base",
    "AlertModel",
    "ClientModel",
    "EventModel",
    "AuditLogModel",
    "init_db",
    "get_session",
    "get_db",
    "get_engine",
]

# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models."""


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class AlertModel(Base):
    """Persisted ransomware alert.

    Attributes:
        id: Auto-increment primary key.
        client_ip: Blocked/alerted IP address.
        username: Samba username.
        severity: Alert severity string.
        triggered_rules: Comma-separated rule names.
        ml_score: ML probability score, or NULL.
        explanation: Plain-language explanation text.
        status: Alert status ('open', 'resolved', 'false_positive').
        first_anomaly_ts: Timestamp of first anomalous activity.
        files_touched: JSON-encoded string of touched file paths.
        created_at: UTC creation timestamp.
        resolved_at: UTC resolution timestamp, or NULL.
    """

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    client_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    username: Mapped[str] = mapped_column(String(256), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    triggered_rules: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    ml_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    explanation: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    first_anomaly_ts: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    files_touched: Mapped[str | None] = mapped_column(String(8192), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(UTC))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ClientModel(Base):
    """Known Samba client (IP + username pair).

    Attributes:
        id: Auto-increment primary key.
        client_ip: Client IP address.
        username: Samba username.
        first_seen: UTC timestamp of first event.
        last_seen: UTC timestamp of most recent event.
        is_blocked: Whether this client is currently blocked.
    """

    __tablename__ = "clients"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    client_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    username: Mapped[str] = mapped_column(String(256), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(UTC))
    last_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(UTC))
    is_blocked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class EventModel(Base):
    """Raw audit event (ring-buffer table, pruned periodically).

    Attributes:
        id: Auto-increment primary key.
        client_ip: Client IP address.
        username: Samba username.
        operation: Samba operation name.
        status: ``ok`` or ``err``.
        filename_hash: SHA-256 hash of the filename (not the filename itself).
        occurred_at: UTC timestamp of the event.
    """

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    client_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    username: Mapped[str] = mapped_column(String(256), nullable=False)
    operation: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(8), nullable=False)
    filename_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class AuditLogModel(Base):
    """Audit log of administrative actions taken via API.

    Attributes:
        id: Auto-increment primary key.
        username: Administrator who performed the action.
        action: Name of the action (e.g. 'block', 'unblock', 'restore', 'panic').
        target: Target identifier (e.g. alert ID, client IP, 'settings').
        result: Outcome or summary ('success', 'refused: allowlisted IP', etc.).
        details: Optional JSON string or descriptive text with details.
        created_at: UTC timestamp.
    """

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(256), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[str] = mapped_column(String(256), nullable=False)
    result: Mapped[str] = mapped_column(String(256), nullable=False)
    details: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# Engine & Session Management
# ---------------------------------------------------------------------------

_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def init_db(db_url: str = "sqlite:///shareguard.db") -> Engine:
    """Initialise the database engine and create all tables.

    Args:
        db_url: SQLAlchemy database URL. Defaults to local SQLite file.

    Returns:
        The initialised SQLAlchemy :class:`Engine`.
    """
    global _engine, _session_factory
    connect_args: dict[str, Any] = {}
    if db_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False

    _engine = create_engine(db_url, connect_args=connect_args)
    Base.metadata.create_all(_engine)
    _session_factory = sessionmaker(bind=_engine, expire_on_commit=False)
    return _engine


def get_engine() -> Engine:
    """Return the current database engine, initialising with default if needed."""
    global _engine
    if _engine is None:
        init_db()
    if _engine is None:
        raise RuntimeError("Failed to initialise database engine")
    return _engine


@contextmanager
def get_session() -> Generator[Session, None, None]:
    """Yield a SQLAlchemy session, committing or rolling back on exit.

    Usage::

        with get_session() as session:
            session.add(obj)
    """
    global _session_factory
    if _session_factory is None:
        init_db()
    if _session_factory is None:
        raise RuntimeError("Failed to initialise database session factory")
    session = _session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a transactional database session."""
    with get_session() as session:
        yield session
