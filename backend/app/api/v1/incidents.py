"""Incident investigation — the platform's primary workflow."""

from __future__ import annotations

import datetime as dt
from typing import Annotated, Any

from fastapi import APIRouter, Query
from sqlalchemy import Text, cast, func, or_, select

from app.api.deps import DbSession, RequireAnalyst, RequireViewer
from app.core.errors import NotFoundError, ValidationFailed
from app.core.sqlutils import LIKE_ESCAPE, json_member
from app.core.timeutils import utcnow
from app.mitre import catalog
from app.models.enums import IncidentStatus
from app.models.events import Event
from app.models.incidents import AnalystNote, Incident
from app.schemas.common import Page
from app.schemas.security import (
    AlertSummary,
    AnalystNoteOut,
    EventDetail,
    IncidentDetail,
    IncidentStatusUpdate,
    IncidentSummary,
    NoteCreate,
    TechniqueMapping,
)
from app.services import audit
from app.services.graph import build_incident_graph
from app.services.timeline import build_incident_timeline

router = APIRouter(prefix="/incidents", tags=["incidents"])

SORTABLE = {
    "last_seen": Incident.last_seen,
    "first_seen": Incident.first_seen,
    "risk_score": Incident.risk_score,
    "confidence": Incident.confidence,
    "created_at": Incident.created_at,
}


def _load(db, incident_id: str) -> Incident:
    incident = db.execute(
        select(Incident).where(Incident.incident_id == incident_id)
    ).scalar_one_or_none()
    if incident is None:
        raise NotFoundError(f"Incident '{incident_id}' does not exist.")
    return incident


def _detail(incident: Incident) -> IncidentDetail:
    """Build the full incident payload.

    Constructed field by field rather than with ``model_validate(incident)``:
    the schema's ``techniques`` are enriched with ATT&CK names and URLs from the
    catalogue, so they are not the ORM relationship of the same name and letting
    Pydantic try to coerce one into the other fails. Explicit is also easier to
    follow than a validate-then-overwrite dance.
    """
    ordered_alerts = sorted(incident.alerts, key=lambda a: a.detected_at)
    alerts: list[AlertSummary] = []
    for alert in ordered_alerts:
        summary = AlertSummary.model_validate(alert)
        summary.incident_id = incident.incident_id
        alerts.append(summary)

    names = catalog.tactic_names()
    techniques: list[TechniqueMapping] = []
    for technique in sorted(incident.techniques, key=lambda t: t.detected_at):
        info = catalog.technique(technique.technique_id)
        techniques.append(TechniqueMapping(
            technique_id=technique.technique_id,
            name=info.name if info else technique.technique_id,
            tactic_id=technique.tactic_id,
            tactic_name=names.get(technique.tactic_id or ""),
            confidence=technique.confidence,
            first_observed=technique.first_observed,
            last_observed=technique.last_observed,
            detected_at=technique.detected_at,
            evidence_event_ids=technique.evidence_event_ids or [],
            source_rule_ids=technique.source_rule_ids or [],
            url=info.url if info else None,
        ))

    return IncidentDetail(
        incident_id=incident.incident_id,
        title=incident.title,
        summary=incident.summary,
        severity=incident.severity,
        status=incident.status,
        confidence=incident.confidence,
        risk_score=incident.risk_score,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        first_seen=incident.first_seen,
        last_seen=incident.last_seen,
        duration_seconds=incident.duration_seconds,
        alert_count=incident.alert_count,
        event_count=incident.event_count,
        affected_hosts=incident.affected_hosts or [],
        affected_users=incident.affected_users or [],
        targeted_users=incident.targeted_users or [],
        source_ips=incident.source_ips or [],
        destination_ips=incident.destination_ips or [],
        technique_ids=incident.technique_ids or [],
        risk_breakdown=incident.risk_breakdown or [],
        confidence_breakdown=incident.confidence_breakdown or [],
        correlation_reason=incident.correlation_reason or {},
        attack_chain=incident.attack_chain or [],
        ioc_matches=incident.ioc_matches or [],
        assigned_to=incident.assigned_to,
        mttr_seconds=incident.mttr_seconds,
        closed_at=incident.closed_at,
        false_positive_reason=incident.false_positive_reason,
        is_demo=incident.is_demo,
        alerts=alerts,
        techniques=techniques,
        notes=[
            AnalystNoteOut.model_validate(n)
            for n in sorted(incident.notes, key=lambda n: n.created_at)
        ],
    )


@router.get("", response_model=Page[IncidentSummary], summary="Incident list")
def list_incidents(
    db: DbSession,
    _: RequireViewer,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    severity: Annotated[list[str] | None, Query()] = None,
    status_filter: Annotated[list[str] | None, Query(alias="status")] = None,
    host: str | None = None,
    user: str | None = None,
    technique: str | None = None,
    assigned_to: str | None = None,
    since: dt.datetime | None = None,
    sort: Annotated[str, Query()] = "last_seen",
    order: Annotated[str, Query(pattern="^(asc|desc)$")] = "desc",
) -> Page[IncidentSummary]:
    if sort not in SORTABLE:
        raise ValidationFailed(f"Cannot sort by '{sort}'. Sortable: {', '.join(sorted(SORTABLE))}")

    conditions = []
    if severity:
        conditions.append(Incident.severity.in_(severity))
    if status_filter:
        conditions.append(Incident.status.in_(status_filter))
    if assigned_to:
        conditions.append(Incident.assigned_to == assigned_to)
    if since:
        conditions.append(Incident.last_seen >= since)
    if host:
        conditions.append(
            cast(Incident.affected_hosts, Text).ilike(json_member(host), escape=LIKE_ESCAPE)
        )
    if user:
        conditions.append(or_(
            cast(Incident.affected_users, Text).ilike(json_member(user), escape=LIKE_ESCAPE),
            cast(Incident.targeted_users, Text).ilike(json_member(user), escape=LIKE_ESCAPE),
        ))
    if technique:
        conditions.append(
            cast(Incident.technique_ids, Text).ilike(json_member(technique), escape=LIKE_ESCAPE)
        )

    stmt = select(Incident)
    count_stmt = select(func.count()).select_from(Incident)
    for condition in conditions:
        stmt = stmt.where(condition)
        count_stmt = count_stmt.where(condition)

    column = SORTABLE[sort]
    stmt = stmt.order_by(column.desc() if order == "desc" else column.asc())

    total = db.execute(count_stmt).scalar_one()
    rows = db.execute(stmt.limit(limit).offset(offset)).scalars().all()
    return Page[IncidentSummary](
        items=[IncidentSummary.model_validate(i) for i in rows],
        total=total, limit=limit, offset=offset,
    )


@router.get("/{incident_id}", response_model=IncidentDetail, summary="Full incident record")
def get_incident(incident_id: str, db: DbSession, _: RequireViewer) -> IncidentDetail:
    return _detail(_load(db, incident_id))


@router.get("/{incident_id}/timeline", summary="Chronological evidence")
def incident_timeline(incident_id: str, db: DbSession, _: RequireViewer) -> dict[str, Any]:
    incident = _load(db, incident_id)
    return {
        "incident_id": incident.incident_id,
        "attack_chain": incident.attack_chain,
        "events": build_incident_timeline(db, incident),
        "note": (
            "attack_chain is the tactic-level reconstruction, ordered by when each "
            "tactic became detectable. events is the underlying evidence in strict "
            "chronological order. Where they disagree, the events are authoritative."
        ),
    }


@router.get("/{incident_id}/graph", summary="Attack graph")
def incident_graph(incident_id: str, db: DbSession, _: RequireViewer) -> dict[str, Any]:
    """Nodes and edges derived from this incident's evidence.

    Every edge carries the event IDs that produced it, so the graph is navigable
    back to the telemetry rather than being an illustration.
    """
    return build_incident_graph(db, _load(db, incident_id))


@router.get("/{incident_id}/evidence", summary="All evidence events")
def incident_evidence(
    incident_id: str,
    db: DbSession,
    _: RequireViewer,
    limit: Annotated[int, Query(ge=1, le=1000)] = 250,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    incident = _load(db, incident_id)
    event_pks = sorted({link.event_pk for a in incident.alerts for link in a.evidence_links})
    if not event_pks:
        return {"incident_id": incident.incident_id, "total": 0, "events": []}

    rows = db.execute(
        select(Event).where(Event.id.in_(event_pks))
        .order_by(Event.timestamp.asc()).limit(limit).offset(offset)
    ).scalars().all()
    return {
        "incident_id": incident.incident_id,
        "total": len(event_pks),
        "limit": limit,
        "offset": offset,
        "events": [EventDetail.model_validate(e).model_dump(by_alias=True) for e in rows],
    }


@router.get("/{incident_id}/techniques", summary="ATT&CK mapping with evidence")
def incident_techniques(incident_id: str, db: DbSession, _: RequireViewer) -> dict[str, Any]:
    incident = _load(db, incident_id)
    detail = _detail(incident)
    return {
        "incident_id": incident.incident_id,
        "techniques": [t.model_dump() for t in detail.techniques],
        "attack_chain": incident.attack_chain,
        "tactics_covered": catalog.tactics_for(incident.technique_ids or []),
    }


@router.patch("/{incident_id}/status", response_model=IncidentDetail, summary="Update incident state")
def update_status(
    incident_id: str,
    payload: IncidentStatusUpdate,
    db: DbSession,
    principal: RequireAnalyst,
) -> IncidentDetail:
    incident = _load(db, incident_id)
    try:
        new_status = IncidentStatus(payload.status)
    except ValueError:
        raise ValidationFailed(
            f"'{payload.status}' is not a valid incident status. "
            f"Valid: {', '.join(s.value for s in IncidentStatus)}"
        ) from None

    if new_status == IncidentStatus.FALSE_POSITIVE and not (payload.reason or "").strip():
        raise ValidationFailed(
            "A reason is required when closing an incident as a false positive."
        )

    previous = incident.status
    incident.status = new_status
    if payload.assigned_to is not None:
        incident.assigned_to = payload.assigned_to
    if new_status in (IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE):
        incident.closed_at = utcnow()
        incident.closed_by = principal.username
        if new_status == IncidentStatus.FALSE_POSITIVE:
            incident.false_positive_reason = payload.reason
    else:
        incident.closed_at = None
        incident.closed_by = None

    audit.record(
        db,
        actor=principal.username,
        actor_role=principal.role.value,
        action="incident_false_positive" if new_status == IncidentStatus.FALSE_POSITIVE
        else "incident_status_changed",
        target_type="incident",
        target_id=incident.incident_id,
        details={"from": previous, "to": str(new_status), "reason": payload.reason,
                 "assigned_to": incident.assigned_to},
        ip_address=principal.ip_address,
    )
    db.commit()
    db.refresh(incident)
    return _detail(incident)


@router.post("/{incident_id}/notes", response_model=IncidentDetail, summary="Add an analyst note")
def add_note(
    incident_id: str,
    payload: NoteCreate,
    db: DbSession,
    principal: RequireAnalyst,
) -> IncidentDetail:
    incident = _load(db, incident_id)
    db.add(AnalystNote(
        incident_pk=incident.id,
        author=principal.username,
        body=payload.body,
        created_at=utcnow(),
    ))
    audit.record(
        db,
        actor=principal.username,
        actor_role=principal.role.value,
        action="incident_note_added",
        target_type="incident",
        target_id=incident.incident_id,
        ip_address=principal.ip_address,
    )
    db.commit()
    db.refresh(incident)
    return _detail(incident)


@router.post("/{incident_id}/recorrelate", response_model=IncidentDetail,
             summary="Recompute derived state")
def recorrelate(incident_id: str, db: DbSession, principal: RequireAnalyst) -> IncidentDetail:
    """Rebuild every derived field from the incident's current alerts.

    Useful after triage changes, and a deliberate safety valve: because
    ``refresh_incident`` rebuilds rather than patches, this can always restore a
    consistent view.
    """
    from app.correlation.engine import refresh_incident

    incident = _load(db, incident_id)
    refresh_incident(db, incident)
    db.commit()
    db.refresh(incident)
    return _detail(incident)


@router.get("/{incident_id}/similar", summary="Structurally similar incidents")
def similar_incidents(
    incident_id: str,
    db: DbSession,
    _: RequireViewer,
    limit: Annotated[int, Query(ge=1, le=20)] = 5,
) -> dict[str, Any]:
    """Find incidents resembling this one.

    Similarity is computed from structured features — shared ATT&CK techniques,
    contributing rules, entity overlap and severity — using weighted Jaccard
    overlap. Not embeddings: the features that make two intrusions alike are
    already discrete and named, and a similarity score an analyst can decompose
    is worth more than one they cannot.
    """
    incident = _load(db, incident_id)
    candidates = db.execute(
        select(Incident).where(Incident.id != incident.id)
        .order_by(Incident.last_seen.desc()).limit(300)
    ).scalars().all()

    def jaccard(a: set[str], b: set[str]) -> float:
        if not a and not b:
            return 0.0
        union = a | b
        return len(a & b) / len(union) if union else 0.0

    base_techniques = set(incident.technique_ids or [])
    base_rules = {a.rule_id for a in incident.alerts}
    base_entities = set(incident.entity_keys or [])

    weights = {"techniques": 0.45, "rules": 0.30, "entities": 0.15, "severity": 0.10}
    scored: list[dict[str, Any]] = []

    for candidate in candidates:
        technique_overlap = jaccard(base_techniques, set(candidate.technique_ids or []))
        rule_overlap = jaccard(base_rules, {a.rule_id for a in candidate.alerts})
        entity_overlap = jaccard(base_entities, set(candidate.entity_keys or []))
        severity_match = 1.0 if candidate.severity == incident.severity else 0.0

        score = (
            weights["techniques"] * technique_overlap
            + weights["rules"] * rule_overlap
            + weights["entities"] * entity_overlap
            + weights["severity"] * severity_match
        )
        if score <= 0:
            continue

        scored.append({
            "incident_id": candidate.incident_id,
            "title": candidate.title,
            "severity": candidate.severity,
            "status": candidate.status,
            "risk_score": candidate.risk_score,
            "last_seen": candidate.last_seen.isoformat(),
            "similarity": round(score, 3),
            "matched_on": {
                "techniques": {
                    "score": round(technique_overlap, 3),
                    "shared": sorted(base_techniques & set(candidate.technique_ids or []))[:10],
                },
                "rules": {
                    "score": round(rule_overlap, 3),
                    "shared": sorted(base_rules & {a.rule_id for a in candidate.alerts})[:10],
                },
                "entities": {
                    "score": round(entity_overlap, 3),
                    "shared": sorted(base_entities & set(candidate.entity_keys or []))[:10],
                },
                "severity": {"score": severity_match, "value": candidate.severity},
            },
        })

    scored.sort(key=lambda item: item["similarity"], reverse=True)
    return {
        "incident_id": incident.incident_id,
        "method": "weighted Jaccard similarity over techniques, rules, entities and severity",
        "weights": weights,
        "candidates_considered": len(candidates),
        "similar": scored[:limit],
    }
