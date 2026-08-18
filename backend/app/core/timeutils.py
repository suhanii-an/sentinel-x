"""Timezone handling.

Every timestamp in SENTINEL-X is UTC.  Mixing naive and aware datetimes is the
classic source of silent correlation bugs — a five-minute brute-force window that
quietly becomes a five-and-a-half-hour window — so the boundary is enforced at
the type level rather than by convention.

:class:`UTCDateTime` coerces on the way in and re-attaches UTC on the way out,
which also papers over SQLite's lack of timezone storage so the test suite
behaves identically to the Postgres deployment.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import DateTime
from sqlalchemy.types import TypeDecorator

UTC = dt.UTC


def utcnow() -> dt.datetime:
    return dt.datetime.now(UTC)


def ensure_utc(value: dt.datetime | None) -> dt.datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def parse_timestamp(value: str | dt.datetime) -> dt.datetime:
    """Parse an ISO-8601 timestamp, tolerating a trailing ``Z``."""
    if isinstance(value, dt.datetime):
        return ensure_utc(value)  # type: ignore[return-value]
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return ensure_utc(dt.datetime.fromisoformat(text))  # type: ignore[return-value]


def iso(value: dt.datetime | None) -> str | None:
    v = ensure_utc(value)
    return v.isoformat().replace("+00:00", "Z") if v else None


class UTCDateTime(TypeDecorator):
    """DateTime column that is always timezone-aware UTC in Python space."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):  # noqa: D102
        return ensure_utc(value)

    def process_result_value(self, value, dialect):  # noqa: D102
        return ensure_utc(value)
