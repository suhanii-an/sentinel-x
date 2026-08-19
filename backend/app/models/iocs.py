"""Indicators of compromise and their observed matches.

The IOC store is intentionally provider-neutral: an indicator is a value, a type,
a source and a confidence.  The bundled dataset is *local synthetic demo data*
(documented in ``data/sample_iocs/README.md``); the same table accepts records
from a real feed without schema changes.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import Boolean, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, JSONVariant
from app.core.timeutils import UTCDateTime, utcnow


class IOC(Base):
    __tablename__ = "iocs"
    __table_args__ = (UniqueConstraint("indicator", "ioc_type", name="uq_ioc_value_type"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ioc_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    indicator: Mapped[str] = mapped_column(String(512), index=True)
    ioc_type: Mapped[str] = mapped_column(String(24), index=True)

    #: Where the indicator came from.  "local-demo" for the bundled dataset.
    source: Mapped[str] = mapped_column(String(128), default="local-demo")
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags: Mapped[list] = mapped_column(JSONVariant, default=list)

    first_seen: Mapped[dt.datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    #: Simulated blocklist state set by the response engine.
    is_blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    match_count: Mapped[int] = mapped_column(Integer, default=0)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)

    matches: Mapped[list[IOCMatch]] = relationship(
        back_populates="ioc", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<IOC {self.ioc_type}:{self.indicator}>"


class IOCMatch(Base):
    __tablename__ = "ioc_matches"
    __table_args__ = (UniqueConstraint("ioc_pk", "event_pk", "matched_field", name="uq_ioc_match"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ioc_pk: Mapped[int] = mapped_column(ForeignKey("iocs.id", ondelete="CASCADE"), index=True)
    event_pk: Mapped[int] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), index=True)
    matched_field: Mapped[str] = mapped_column(String(64))
    matched_value: Mapped[str] = mapped_column(String(512))
    matched_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)

    ioc: Mapped[IOC] = relationship(back_populates="matches")
    event: Mapped[Event] = relationship()  # noqa: F821


Index("ix_iocs_type_active", IOC.ioc_type, IOC.is_active)
