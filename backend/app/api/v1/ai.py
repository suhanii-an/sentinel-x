"""AI investigation assistant."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from app.ai.service import ai_status, investigate_incident
from app.api.deps import AIRateLimited, DbSession, RequireAnalyst, RequireViewer
from app.core.errors import NotFoundError, ValidationFailed
from app.models.incidents import Incident
from app.models.operations import AIInvestigation
from app.services import audit

router = APIRouter(prefix="/ai", tags=["ai"])


class InvestigateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    task: Literal["explain", "summarize", "question", "next_steps"] = "explain"
    question: str | None = Field(default=None, max_length=1000)
    #: Strict mode discards a response entirely if it cited anything outside the
    #: supplied evidence, rather than stripping the bad citations and showing the
    #: rest.
    strict: bool = False


@router.get("/status", summary="Assistant availability")
def status(_: RequireViewer) -> dict[str, Any]:
    """Whether the assistant is configured, and what still works if it is not.

    The answer is deliberately explicit: detection, correlation, incidents,
    hunting, response simulation, reporting and evaluation are all unaffected by
    AI availability, because none of them depend on it.
    """
    state = ai_status()
    return {
        **state,
        "grounding_policy": {
            "evidence_allowlist": (
                "Responses may only cite identifiers present in the evidence bundle "
                "supplied for that specific request. Anything else is removed before "
                "display and the removal is shown to the analyst."
            ),
            "technique_allowlist": (
                "Responses may only cite ATT&CK techniques actually observed in the "
                "incident."
            ),
            "schema_validation": (
                "Every response is parsed into a Pydantic schema. Non-conforming output "
                "is discarded rather than displayed with a caveat."
            ),
            "injection_defence": (
                "Telemetry is delimited and labelled as untrusted data, the delimiter "
                "cannot be escaped, injection-shaped content is flagged on the "
                "investigation record, and the model has no tools and no database access."
            ),
            "authority": (
                "The assistant cannot create, close or reclassify anything. Detection is "
                "deterministic and happens before the assistant is ever consulted."
            ),
        },
    }


@router.post("/incidents/{incident_id}/investigate", summary="Ask the assistant about an incident")
def investigate(
    incident_id: str,
    payload: InvestigateRequest,
    db: DbSession,
    principal: RequireAnalyst,
    _rate: AIRateLimited,
) -> dict[str, Any]:
    incident = db.execute(
        select(Incident).where(Incident.incident_id == incident_id)
    ).scalar_one_or_none()
    if incident is None:
        raise NotFoundError(f"Incident '{incident_id}' does not exist.")

    if payload.task == "question" and not (payload.question or "").strip():
        raise ValidationFailed("A question is required for the 'question' task.")

    result, row = investigate_incident(
        db,
        incident,
        task=payload.task,
        question=payload.question,
        created_by=principal.username,
        strict=payload.strict,
    )

    audit.record(
        db,
        actor=principal.username,
        actor_role=principal.role.value,
        action="ai_investigation" if result.accepted else "ai_response_rejected",
        target_type="incident",
        target_id=incident.incident_id,
        result="success" if result.accepted else "rejected",
        details={
            "task": payload.task,
            "validation_status": result.validation_status,
            "citations_removed": len(result.dropped_evidence_ids),
            "injection_flagged": result.injection_flagged,
            "provider": result.provider,
        },
        ip_address=principal.ip_address,
    )
    db.commit()

    return {
        "incident_id": incident.incident_id,
        "investigation_id": row.id,
        "evidence_events_supplied": result.evidence_event_count,
        **result.to_dict(),
    }


@router.get("/incidents/{incident_id}/history", summary="Previous AI interactions")
def history(
    incident_id: str,
    db: DbSession,
    _: RequireViewer,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
) -> dict[str, Any]:
    """Every AI interaction for this incident, including rejected ones.

    Rejections are kept on purpose: an ungrounded or schema-invalid response is a
    security-relevant event worth reviewing, and a history that only shows
    accepted answers hides how often the model had to be corrected.
    """
    incident = db.execute(
        select(Incident).where(Incident.incident_id == incident_id)
    ).scalar_one_or_none()
    if incident is None:
        raise NotFoundError(f"Incident '{incident_id}' does not exist.")

    rows = db.execute(
        select(AIInvestigation).where(AIInvestigation.incident_pk == incident.id)
        .order_by(AIInvestigation.created_at.desc()).limit(limit)
    ).scalars().all()

    return {
        "incident_id": incident.incident_id,
        "total": len(rows),
        "accepted": sum(1 for r in rows if r.validation_status == "accepted"),
        "rejected": sum(1 for r in rows if r.validation_status != "accepted"),
        "items": [
            {
                "id": r.id,
                "created_at": r.created_at.isoformat(),
                "created_by": r.created_by,
                "task": r.task,
                "question": r.question,
                "provider": r.provider,
                "model": r.model,
                "latency_ms": r.latency_ms,
                "validation_status": r.validation_status,
                "validation_errors": r.validation_errors,
                "confidence": r.confidence,
                "answer": r.answer,
                "cited_evidence_ids": r.cited_evidence_ids,
                "evidence_offered": len(r.offered_evidence_ids or []),
                "injection_flagged": r.injection_flagged,
                "injection_signals": r.injection_signals,
            }
            for r in rows
        ],
    }
