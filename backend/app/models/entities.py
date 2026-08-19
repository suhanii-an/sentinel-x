"""Asset and identity inventory.

Hosts and user accounts are first-class records rather than free-text strings on
events.  That is what makes "show me everything that touched LINUX-03" a single
indexed lookup instead of a table scan, and it is where asset criticality — a
real input to the risk model — lives.

Note on naming: ``users`` here are *security principals observed in telemetry*
(the ``/users`` page).  Accounts that log in to SENTINEL-X itself live in
``app_users`` (see ``app/models/auth.py``).  The two are deliberately separate:
conflating the analyst's identity with the identities under investigation is a
modelling mistake that becomes an authorization bug later.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import Boolean, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, JSONVariant
from app.core.timeutils import UTCDateTime, utcnow


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    hostname: Mapped[str] = mapped_column(String(255))
    os_family: Mapped[str] = mapped_column(String(32), default="linux")
    os_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    environment: Mapped[str] = mapped_column(String(32), default="production")

    #: 1 (lab machine) .. 5 (crown-jewel asset).  Feeds the asset weight of the
    #: risk score; documented in docs/detection-engine.md.
    criticality: Mapped[int] = mapped_column(Integer, default=3)

    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    #: Set only by the *simulated* response engine.  SENTINEL-X never isolates a
    #: real host; this flag records that a containment action was rehearsed.
    is_isolated: Mapped[bool] = mapped_column(Boolean, default=False)
    isolated_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)

    tags: Mapped[list] = mapped_column(JSONVariant, default=list)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    first_seen: Mapped[dt.datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[dt.datetime] = mapped_column(UTCDateTime, default=utcnow)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)

    events: Mapped[list[Event]] = relationship(back_populates="host")  # noqa: F821

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Host {self.host_id}>"


class User(Base):
    """A security principal observed in telemetry (not a SENTINEL-X login)."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    domain: Mapped[str | None] = mapped_column(String(128), nullable=True)
    #: human | service | cloud
    user_type: Mapped[str] = mapped_column(String(32), default="human")
    department: Mapped[str | None] = mapped_column(String(128), nullable=True)
    is_privileged: Mapped[bool] = mapped_column(Boolean, default=False)

    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    #: Simulated containment only — see Host.is_isolated.
    is_disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    disabled_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)

    tags: Mapped[list] = mapped_column(JSONVariant, default=list)
    first_seen: Mapped[dt.datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[dt.datetime] = mapped_column(UTCDateTime, default=utcnow)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)

    events: Mapped[list[Event]] = relationship(back_populates="user")  # noqa: F821

    def __repr__(self) -> str:  # pragma: no cover
        return f"<User {self.user_id}>"


Index("ix_hosts_risk", Host.risk_score.desc())
Index("ix_users_risk", User.risk_score.desc())
