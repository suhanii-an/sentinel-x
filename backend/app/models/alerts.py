"""Alerts: a detection rule's verdict on a specific set of events.

An alert is never free-floating.  It always carries the concrete events that
caused it (``alert_events``), which is what makes every downstream claim —
including anything the AI assistant says — traceable back to telemetry.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import Boolean, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, JSONVariant
from app.core.timeutils import UTCDateTime, utcnow
from app.models.enums import AlertStatus


class AlertEvent(Base):
    """Association between an alert and the evidence that produced it.

    ``role`` distinguishes the events that actually satisfied the rule condition
    ("trigger") from events included for analyst context ("context").  Evaluation
    scores only trigger events.
    """

    __tablename__ = "alert_events"
    __table_args__ = (UniqueConstraint("alert_pk", "event_pk", name="uq_alert_event"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_pk: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    event_pk: Mapped[int] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(24), default="trigger")
    step: Mapped[str | None] = mapped_column(String(64), nullable=True)

    alert: Mapped[Alert] = relationship(back_populates="evidence_links")
    event: Mapped[Event] = relationship()  # noqa: F821


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)

    created_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    #: Timestamp of the latest event that satisfied the rule — the moment the
    #: attack became detectable.  Detection latency is measured from here.
    detected_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, index=True)
    first_event_at: Mapped[dt.datetime] = mapped_column(UTCDateTime)
    last_event_at: Mapped[dt.datetime] = mapped_column(UTCDateTime)
    #: Event-time latency: first_event_at -> detected_at, in milliseconds.  This
    #: is "how far into the attack were we when the rule fired", which is the
    #: figure that matters operationally and is stable under dataset replay.
    detection_latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    #: Wall-clock pipeline latency: event ingestion -> alert written.  Measures
    #: the platform, not the detection.  Reported separately for that reason.
    processing_latency_ms: Mapped[int] = mapped_column(Integer, default=0)

    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    rule_name: Mapped[str] = mapped_column(String(255))
    rule_type: Mapped[str] = mapped_column(String(24))

    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), index=True)
    #: Rule-declared confidence, adjusted by runtime signal strength.
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_breakdown: Mapped[list] = mapped_column(JSONVariant, default=list)

    status: Mapped[str] = mapped_column(String(24), default=AlertStatus.NEW, index=True)

    host_ref: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    user_ref: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    technique_ids: Mapped[list] = mapped_column(JSONVariant, default=list)
    tactics: Mapped[list] = mapped_column(JSONVariant, default=list)
    #: Short, human-readable statements of *why* the rule fired, e.g.
    #: "11 failed authentications from 203.0.113.44 in 300s (threshold: 5)".
    explanation: Mapped[list] = mapped_column(JSONVariant, default=list)
    entity_keys: Mapped[list] = mapped_column(JSONVariant, default=list)

    incident_pk: Mapped[int | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True
    )
    simulation_run_pk: Mapped[int | None] = mapped_column(
        ForeignKey("simulation_runs.id", ondelete="SET NULL"), nullable=True, index=True
    )

    triaged_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    triaged_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    false_positive_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    #: Deduplication key: one open alert per (rule, entity set, window).
    dedup_key: Mapped[str] = mapped_column(String(255), index=True)

    evidence_links: Mapped[list[AlertEvent]] = relationship(
        back_populates="alert", cascade="all, delete-orphan", lazy="selectin"
    )
    incident: Mapped[Incident | None] = relationship(back_populates="alerts")  # noqa: F821

    @property
    def evidence_event_pks(self) -> list[int]:
        return [link.event_pk for link in self.evidence_links]

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Alert {self.alert_id} {self.rule_id} {self.severity}>"


Index("ix_alerts_status_sev", Alert.status, Alert.severity)
Index("ix_alerts_detected", Alert.detected_at.desc())
