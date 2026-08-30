"""Incident reporting."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query, Response, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select

from app.api.deps import DbSession, RequireAnalyst, RequireViewer
from app.core.errors import NotFoundError
from app.models.incidents import Incident
from app.models.operations import Report
from app.reporting.generator import generate_report
from app.reporting.pdf import render_pdf
from app.services import audit

router = APIRouter(prefix="/reports", tags=["reports"])


class GenerateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    incident_id: str
    #: When true and an AI provider is configured, the executive summary is
    #: AI-drafted. The report always records which was used.
    use_ai_summary: bool = False


@router.get("", summary="Generated reports")
def list_reports(
    db: DbSession,
    _: RequireViewer,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    incident_id: str | None = None,
) -> dict[str, Any]:
    stmt = select(Report)
    count_stmt = select(func.count()).select_from(Report)
    if incident_id:
        incident = db.execute(
            select(Incident).where(Incident.incident_id == incident_id)
        ).scalar_one_or_none()
        if incident is None:
            raise NotFoundError(f"Incident '{incident_id}' does not exist.")
        stmt = stmt.where(Report.incident_pk == incident.id)
        count_stmt = count_stmt.where(Report.incident_pk == incident.id)

    total = db.execute(count_stmt).scalar_one()
    rows = db.execute(
        stmt.order_by(Report.created_at.desc()).limit(limit).offset(offset)
    ).scalars().all()
    return {
        "total": total,
        "items": [
            {
                "report_id": r.report_id,
                "incident_id": r.incident.incident_id if r.incident else None,
                "title": r.title,
                "created_at": r.created_at.isoformat(),
                "generated_by": r.generated_by,
                "sections": r.sections,
                "ai_assisted": r.ai_assisted,
                "length_chars": len(r.content),
            }
            for r in rows
        ],
    }


@router.post("", status_code=status.HTTP_201_CREATED, summary="Generate an incident report")
def generate(payload: GenerateRequest, db: DbSession, principal: RequireAnalyst) -> dict[str, Any]:
    incident = db.execute(
        select(Incident).where(Incident.incident_id == payload.incident_id)
    ).scalar_one_or_none()
    if incident is None:
        raise NotFoundError(f"Incident '{payload.incident_id}' does not exist.")

    ai_summary = None
    ai_note = None
    if payload.use_ai_summary:
        from app.ai.service import executive_summary
        from app.core.errors import AIUnavailableError

        try:
            result, _row = executive_summary(db, incident, created_by=principal.username)
            if result.accepted and result.answer:
                ai_summary = result.answer
            else:
                # Fall back to the deterministic summary rather than failing the
                # report: the report must be producible without a working model.
                ai_note = (
                    f"AI executive summary was requested but rejected "
                    f"({result.validation_status}); the deterministic summary was used instead."
                )
        except AIUnavailableError:
            ai_note = (
                "AI executive summary was requested but no AI provider is configured; "
                "the deterministic summary was used instead."
            )

    report = generate_report(
        db, incident, generated_by=principal.username, ai_summary=ai_summary
    )
    audit.record(
        db, actor=principal.username, actor_role=principal.role.value,
        action="report_generated", target_type="incident", target_id=incident.incident_id,
        details={"report_id": report.report_id, "ai_assisted": report.ai_assisted},
        ip_address=principal.ip_address,
    )
    db.commit()
    db.refresh(report)

    return {
        "report_id": report.report_id,
        "incident_id": incident.incident_id,
        "title": report.title,
        "sections": report.sections,
        "ai_assisted": report.ai_assisted,
        "created_at": report.created_at.isoformat(),
        "content": report.content,
        "note": ai_note,
    }


def _load(db, report_id: str) -> Report:
    report = db.execute(select(Report).where(Report.report_id == report_id)).scalar_one_or_none()
    if report is None:
        raise NotFoundError(f"Report '{report_id}' does not exist.")
    return report


@router.get("/{report_id}", summary="Report content")
def get_report(report_id: str, db: DbSession, _: RequireViewer) -> dict[str, Any]:
    report = _load(db, report_id)
    return {
        "report_id": report.report_id,
        "incident_id": report.incident.incident_id if report.incident else None,
        "title": report.title,
        "created_at": report.created_at.isoformat(),
        "generated_by": report.generated_by,
        "sections": report.sections,
        "ai_assisted": report.ai_assisted,
        "content": report.content,
    }


@router.get("/{report_id}/markdown", summary="Download as Markdown")
def download_markdown(report_id: str, db: DbSession, principal: RequireViewer) -> Response:
    report = _load(db, report_id)
    audit.record(
        db, actor=principal.username, actor_role=principal.role.value,
        action="report_exported", target_type="report", target_id=report.report_id,
        details={"format": "markdown"}, ip_address=principal.ip_address,
    )
    db.commit()
    return Response(
        content=report.content,
        media_type="text/markdown; charset=utf-8",
        headers={"content-disposition": f'attachment; filename="{report.report_id}.md"'},
    )


@router.get("/{report_id}/pdf", summary="Download as PDF")
def download_pdf(report_id: str, db: DbSession, principal: RequireViewer) -> Response:
    report = _load(db, report_id)
    pdf = render_pdf(report.content, title=report.title)
    audit.record(
        db, actor=principal.username, actor_role=principal.role.value,
        action="report_exported", target_type="report", target_id=report.report_id,
        details={"format": "pdf", "bytes": len(pdf)}, ip_address=principal.ip_address,
    )
    db.commit()
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"content-disposition": f'attachment; filename="{report.report_id}.pdf"'},
    )
