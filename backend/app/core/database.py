"""Database engine, session factory and declarative base.

SENTINEL-X targets PostgreSQL in production (docker-compose) but the ORM layer is
kept dialect-neutral so the full test suite — including the end-to-end
simulation -> incident -> report flow — runs against SQLite with no services
running.  Anything Postgres-specific (JSONB, GIN indexes) is applied as a
dialect-conditional variant rather than hard-coded.
"""

from __future__ import annotations

from collections.abc import Generator
from typing import Any

from sqlalchemy import JSON, create_engine, event
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings

# ``JSONVariant`` gives us JSONB (indexable, binary) on Postgres and plain JSON
# on SQLite without any call-site branching.
JSONVariant = JSON().with_variant(JSONB(), "postgresql")


def _build_engine() -> Engine:
    kwargs: dict[str, Any] = {"echo": settings.DB_ECHO, "future": True}
    if settings.is_sqlite:
        # check_same_thread=False is required because FastAPI runs sync
        # endpoints in a worker threadpool.
        kwargs["connect_args"] = {"check_same_thread": False}
    else:
        kwargs["pool_size"] = settings.DB_POOL_SIZE
        kwargs["max_overflow"] = settings.DB_MAX_OVERFLOW
        kwargs["pool_pre_ping"] = True
    return create_engine(settings.DATABASE_URL, **kwargs)


engine = _build_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


@event.listens_for(Engine, "connect")
def _set_sqlite_pragmas(dbapi_connection, connection_record):  # pragma: no cover
    """Enforce foreign keys on SQLite (off by default) so tests catch the same
    referential-integrity bugs Postgres would.

    Keyed on the *connection's* driver rather than on the configured
    ``DATABASE_URL``: the evaluation harness opens its own temporary SQLite
    database even when the application is running on Postgres, and that database
    needs the same integrity guarantees.
    """
    if dbapi_connection.__class__.__module__.startswith("sqlite3"):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


class Base(DeclarativeBase):
    pass


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a request-scoped session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_all() -> None:
    """Create the schema directly.

    Used by tests and by the SQLite quick-start path.  The Postgres deployment
    path uses Alembic migrations (``alembic upgrade head``).
    """
    from app import models  # noqa: F401  (import registers all mappers)

    Base.metadata.create_all(bind=engine)
