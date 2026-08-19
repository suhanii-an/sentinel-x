"""Operational records: response actions, audit trail, AI sessions, reports.

Everything in this module exists to answer "who did what, when, and on what
basis?" — the question that separates a security tool from a demo.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import Boolean, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, JSONVariant
from app.core.timeutils import UTCDateTime, utcnow


class ResponseAction(Base):
    """A containment action.

    ``is_simulated`` is not a flag with two meaningful values — it is a constant
    invariant enforced by the response service.  SENTINEL-X has no code path that
    performs a real containment action against a real system.  The column exists
    so that the invariant is visible in the data, not just in the code.
    """

    __tablename__ = "response_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    action_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    incident_pk: Mapped[int | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True
    )
    action_type: Mapped[str] = mapped_column(String(48), index=True)
    target_type: Mapped[str] = mapped_column(String(32))
    target: Mapped[str] = mapped_column(String(255), index=True)

    status: Mapped[str] = mapped_column(String(24), default="simulated")
    is_simulated: Mapped[bool] = mapped_column(Boolean, default=True)
    parameters: Mapped[dict] = mapped_column(JSONVariant, default=dict)
    result: Mapped[dict] = mapped_column(JSONVariant, default=dict)
    playbook_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    playbook_step: Mapped[int | None] = mapped_column(Integer, nullable=True)
    justification: Mapped[str | None] = mapped_column(Text, nullable=True)

    requested_by: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<ResponseAction {self.action_id} {self.action_type} -> {self.target}>"


class AuditLog(Base):
    """Append-only record of sensitive application actions."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(128), index=True)
    actor_role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str | None] = mapped_column(String(48), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    result: Mapped[str] = mapped_column(String(24), default="success")
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    details: Mapped[dict] = mapped_column(JSONVariant, default=dict)


class AIInvestigation(Base):
    """Every AI interaction, persisted with the evidence it was given.

    Stored for two reasons: analysts need the investigation history, and an
    ungrounded or rejected model response is a security-relevant event that must
    be reviewable after the fact.
    """

    __tablename__ = "ai_investigations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_pk: Mapped[int | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True, index=True
    )
    created_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    created_by: Mapped[str] = mapped_column(String(128))

    question: Mapped[str] = mapped_column(Text)
    task: Mapped[str] = mapped_column(String(48), default="question")
    provider: Mapped[str] = mapped_column(String(32))
    model: Mapped[str] = mapped_column(String(128))
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)

    #: The validated structured answer, or null if validation rejected it.
    answer: Mapped[dict | None] = mapped_column(JSONVariant, nullable=True)
    #: accepted | rejected_schema | rejected_grounding | provider_error
    validation_status: Mapped[str] = mapped_column(String(32), index=True)
    validation_errors: Mapped[list] = mapped_column(JSONVariant, default=list)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)

    #: Public IDs of everything the model was allowed to cite.
    offered_evidence_ids: Mapped[list] = mapped_column(JSONVariant, default=list)
    cited_evidence_ids: Mapped[list] = mapped_column(JSONVariant, default=list)
    #: True when prompt-injection heuristics fired on the supplied telemetry.
    injection_flagged: Mapped[bool] = mapped_column(Boolean, default=False)
    injection_signals: Mapped[list] = mapped_column(JSONVariant, default=list)


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    report_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    incident_pk: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    generated_by: Mapped[str] = mapped_column(String(128))
    title: Mapped[str] = mapped_column(String(255))
    #: Rendered Markdown.  PDF is produced on demand from the same source.
    content: Mapped[str] = mapped_column(Text)
    sections: Mapped[list] = mapped_column(JSONVariant, default=list)
    #: True when the executive summary was written by the LLM rather than the
    #: deterministic template.  Surfaced in the UI — provenance is not optional.
    ai_assisted: Mapped[bool] = mapped_column(Boolean, default=False)

    incident: Mapped[Incident] = relationship()  # noqa: F821


Index("ix_audit_actor_action", AuditLog.actor, AuditLog.action)
Index("ix_response_incident_type", ResponseAction.incident_pk, ResponseAction.action_type)
