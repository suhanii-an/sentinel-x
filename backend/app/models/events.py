"""The normalized security event — the atom of the whole platform.

Every telemetry source, however exotic, is reduced to this one shape before the
detection engine sees it.  Rules are therefore written once against a stable
schema instead of once per log format, which is the entire point of a
normalization layer.

``raw_event`` preserves the original record verbatim so an analyst can always
answer "but what did the log actually say?", and so a normalizer bug is
recoverable rather than a permanent loss of evidence.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, JSONVariant
from app.core.timeutils import UTCDateTime, utcnow


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)

    #: When the activity happened on the source system.
    timestamp: Mapped[dt.datetime] = mapped_column(UTCDateTime, index=True)
    #: When SENTINEL-X received it.  The gap between the two is ingestion lag and
    #: is excluded from detection-latency measurements.
    ingested_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)

    event_type: Mapped[str] = mapped_column(String(32), index=True)
    source: Mapped[str] = mapped_column(String(48), index=True)

    # ------------------------------------------------------------- entities
    host_ref: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    host_pk: Mapped[int | None] = mapped_column(ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True)
    user_ref: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    user_pk: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    bytes_out: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # -------------------------------------------------------------- process
    process_name: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    process_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    parent_process: Mapped[str | None] = mapped_column(String(255), nullable=True)
    command_line: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_hash: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)

    # ---------------------------------------------------------------- cloud
    cloud_provider: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cloud_account: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    cloud_service: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cloud_resource: Mapped[str | None] = mapped_column(Text, nullable=True)
    cloud_region: Mapped[str | None] = mapped_column(String(48), nullable=True)

    # -------------------------------------------------------------- outcome
    action: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(24), default="unknown", index=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)

    meta: Mapped[dict] = mapped_column("metadata", JSONVariant, default=dict)
    raw_event: Mapped[dict] = mapped_column(JSONVariant, default=dict)

    # --------------------------------------------------- provenance / labels
    simulation_run_pk: Mapped[int | None] = mapped_column(
        ForeignKey("simulation_runs.id", ondelete="SET NULL"), nullable=True, index=True
    )
    #: Ground-truth label, present only on evaluation datasets.  Never consulted
    #: by the detection engine — that would be test-set leakage.
    label: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    label_scenario: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    host: Mapped[Host | None] = relationship(back_populates="events")  # noqa: F821
    user: Mapped[User | None] = relationship(back_populates="events")  # noqa: F821

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Event {self.event_id} {self.event_type}/{self.action} {self.status}>"


# Composite indexes chosen from the actual query patterns of the detection
# engine and the hunt builder, not speculatively.
Index("ix_events_type_ts", Event.event_type, Event.timestamp)
Index("ix_events_host_ts", Event.host_ref, Event.timestamp)
Index("ix_events_user_ts", Event.user_ref, Event.timestamp)
Index("ix_events_srcip_ts", Event.source_ip, Event.timestamp)
Index("ix_events_label_pair", Event.label, Event.label_scenario)
