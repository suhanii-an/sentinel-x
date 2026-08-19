"""Incidents: correlated attack narratives, not alert aliases.

The distinction matters.  An alert says "this rule matched these events".  An
incident says "these alerts are the same adversary doing one thing", and carries
the reconstruction: the ordered attack chain, the affected entities, the
techniques, and an auditable explanation of why the correlation was made.

``correlation_reason`` exists so the UI never has to assert anything it cannot
substantiate — the "Why was this incident created?" panel renders that field
directly.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import Boolean, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, JSONVariant
from app.core.timeutils import UTCDateTime, utcnow
from app.models.enums import IncidentStatus


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)

    title: Mapped[str] = mapped_column(String(255))
    summary: Mapped[str] = mapped_column(Text, default="")

    created_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    updated_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)
    first_seen: Mapped[dt.datetime] = mapped_column(UTCDateTime, index=True)
    last_seen: Mapped[dt.datetime] = mapped_column(UTCDateTime, index=True)

    severity: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(24), default=IncidentStatus.OPEN, index=True)

    #: Attack-chain confidence, 0..1.  Derived in app/correlation/confidence.py
    #: from evidence volume, detection confidence, entity/temporal consistency,
    #: technique breadth and IOC corroboration.
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    confidence_breakdown: Mapped[list] = mapped_column(JSONVariant, default=list)

    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    risk_breakdown: Mapped[list] = mapped_column(JSONVariant, default=list)

    #: Structured, quantified justification for the correlation decision.
    correlation_reason: Mapped[dict] = mapped_column(JSONVariant, default=dict)
    #: Ordered tactic-level reconstruction, e.g.
    #: [{"tactic":"TA0006","label":"Credential Access","first_seen":...}, ...]
    attack_chain: Mapped[list] = mapped_column(JSONVariant, default=list)

    affected_hosts: Mapped[list] = mapped_column(JSONVariant, default=list)
    #: Accounts with *successful* activity in this incident — the ones that may
    #: be compromised.
    affected_users: Mapped[list] = mapped_column(JSONVariant, default=list)
    #: Accounts that only ever appear on failed attempts. Keeping these separate
    #: matters: an analyst resets credentials for accounts that were used, and
    #: monitors accounts that were merely attempted. Merging the two lists turns
    #: every brute-force wordlist entry into an apparent victim.
    targeted_users: Mapped[list] = mapped_column(JSONVariant, default=list)
    source_ips: Mapped[list] = mapped_column(JSONVariant, default=list)
    destination_ips: Mapped[list] = mapped_column(JSONVariant, default=list)
    technique_ids: Mapped[list] = mapped_column(JSONVariant, default=list)
    ioc_matches: Mapped[list] = mapped_column(JSONVariant, default=list)
    #: Namespaced entity identifiers ("host:LINUX-03", "user:admin", "ip:...").
    #: Materialised so the correlation engine can find candidate incidents for a
    #: new alert without loading every open incident's alerts first.
    entity_keys: Mapped[list] = mapped_column(JSONVariant, default=list)

    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    event_count: Mapped[int] = mapped_column(Integer, default=0)

    assigned_to: Mapped[str | None] = mapped_column(String(128), nullable=True)
    closed_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    closed_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    false_positive_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: first alert -> first containment action, measured.
    mttr_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)

    simulation_run_pk: Mapped[int | None] = mapped_column(
        ForeignKey("simulation_runs.id", ondelete="SET NULL"), nullable=True, index=True
    )
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    alerts: Mapped[list[Alert]] = relationship(back_populates="incident", lazy="selectin")  # noqa: F821
    techniques: Mapped[list[IncidentTechnique]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", lazy="selectin"
    )
    notes: Mapped[list[AnalystNote]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", lazy="selectin"
    )
    event_links: Mapped[list[IncidentEvent]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )

    @property
    def duration_seconds(self) -> int:
        return max(0, int((self.last_seen - self.first_seen).total_seconds()))

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Incident {self.incident_id} {self.severity} {self.status}>"


class IncidentEvent(Base):
    """Materialised incident -> event index.

    The same information is reachable by walking alerts, but incident
    investigation reads this constantly (timeline, graph, evidence tab, AI
    context) and the join is hot enough to be worth denormalising.
    """

    __tablename__ = "incident_events"
    __table_args__ = (UniqueConstraint("incident_pk", "event_pk", name="uq_incident_event"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_pk: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    event_pk: Mapped[int] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(24), default="evidence")

    incident: Mapped[Incident] = relationship(back_populates="event_links")
    event: Mapped[Event] = relationship()  # noqa: F821


class IncidentTechnique(Base):
    """A MITRE technique observed within an incident, with its own evidence."""

    __tablename__ = "incident_techniques"
    __table_args__ = (UniqueConstraint("incident_pk", "technique_id", name="uq_incident_technique"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_pk: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    technique_id: Mapped[str] = mapped_column(String(24), index=True)
    tactic_id: Mapped[str | None] = mapped_column(String(24), nullable=True, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    #: Earliest and latest *evidence* timestamps for this technique.
    first_observed: Mapped[dt.datetime] = mapped_column(UTCDateTime)
    last_observed: Mapped[dt.datetime] = mapped_column(UTCDateTime)
    #: When this technique first became *detectable* — the moment a rule mapped
    #: to it fired.  Distinct from first_observed: a sequence rule's evidence
    #: reaches back to the session that started the chain, but the technique it
    #: identifies only became visible when the sequence completed.  The attack
    #: chain is ordered by this field for that reason.
    detected_at: Mapped[dt.datetime] = mapped_column(UTCDateTime)
    #: Public event identifiers (EVT-...) supporting this mapping.
    evidence_event_ids: Mapped[list] = mapped_column(JSONVariant, default=list)
    source_rule_ids: Mapped[list] = mapped_column(JSONVariant, default=list)

    incident: Mapped[Incident] = relationship(back_populates="techniques")


class AnalystNote(Base):
    __tablename__ = "analyst_notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_pk: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    author: Mapped[str] = mapped_column(String(128))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, default=utcnow)

    incident: Mapped[Incident] = relationship(back_populates="notes")


Index("ix_incidents_status_sev", Incident.status, Incident.severity)
Index("ix_incidents_lastseen", Incident.last_seen.desc())
