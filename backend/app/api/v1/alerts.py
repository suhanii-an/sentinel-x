"""Alert queue and triage."""

from __future__ import annotations

import datetime as dt
from typing import Annotated, Any

from fastapi import APIRouter, Query
from sqlalchemy import Text, cast, func, or_, select

from app.api.deps import DbSession, RequireAnalyst, RequireViewer
from app.core.errors import NotFoundError, ValidationFailed
from app.core.sqlutils import LIKE_ESCAPE, contains, json_member
from app.core.timeutils import utcnow
from app.models.alerts import Alert
from app.models.enums import AlertStatus
from app.models.events import Event
from app.schemas.common import Page
from app.schemas.security import AlertDetail, AlertStatusUpdate, AlertSummary, EventSummary
from app.services import audit

router = APIRouter(prefix="/alerts", tags=["alerts"])

SORTABLE = {
    "detected_at": Alert.detected_at,
    "created_at": Alert.created_at,
    "risk_score": Alert.risk_score,
    "confidence": Alert.confidence,
    "severity": Alert.severity,
}


def _to_summary(alert: Alert) -> AlertSummary:
    summary = AlertSummary.model_validate(alert)
    summary.incident_id = alert.incident.incident_id if alert.incident else None
    return summary


@router.get("", response_model=Page[AlertSummary], summary="The alert queue")
def list_alerts(
    db: DbSession,
    _: RequireViewer,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    severity: Annotated[list[str] | None, Query()] = None,
    status_filter: Annotated[list[str] | None, Query(alias="status")] = None,
    rule_id: str | None = None,
    host: str | None = None,
    user: str | None = None,
    source_ip: str | None = None,
    technique: str | None = None,
    incident_id: str | None = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    since: dt.datetime | None = None,
    until: dt.datetime | None = None,
    sort: Annotated[str, Query()] = "detected_at",
    order: Annotated[str, Query(pattern="^(asc|desc)$")] = "desc",
) -> Page[AlertSummary]:
    if sort not in SORTABLE:
        raise ValidationFailed(f"Cannot sort by '{sort}'. Sortable: {', '.join(sorted(SORTABLE))}")

    conditions = []
    if severity:
        conditions.append(Alert.severity.in_(severity))
    if status_filter:
        conditions.append(Alert.status.in_(status_filter))
    if rule_id:
        conditions.append(Alert.rule_id == rule_id)
    if host:
        conditions.append(Alert.host_ref == host)
    if user:
        conditions.append(Alert.user_ref == user)
    if source_ip:
        conditions.append(Alert.source_ip == source_ip)
    if technique:
        conditions.append(
            cast(Alert.technique_ids, Text).ilike(json_member(technique), escape=LIKE_ESCAPE)
        )
    if since:
        conditions.append(Alert.detected_at >= since)
    if until:
        conditions.append(Alert.detected_at <= until)
    if q:
        needle = contains(q)
        conditions.append(or_(
            Alert.title.ilike(needle, escape="\\"),
            Alert.rule_id.ilike(needle, escape="\\"),
            Alert.rule_name.ilike(needle, escape="\\"),
        ))
    if incident_id:
        from app.models.incidents import Incident

        incident = db.execute(
            select(Incident).where(Incident.incident_id == incident_id)
        ).scalar_one_or_none()
        if incident is None:
            raise NotFoundError(f"Incident '{incident_id}' does not exist.")
        conditions.append(Alert.incident_pk == incident.id)

    stmt = select(Alert)
    count_stmt = select(func.count()).select_from(Alert)
    for condition in conditions:
        stmt = stmt.where(condition)
        count_stmt = count_stmt.where(condition)

    column = SORTABLE[sort]
    stmt = stmt.order_by(column.desc() if order == "desc" else column.asc())

    total = db.execute(count_stmt).scalar_one()
    rows = db.execute(stmt.limit(limit).offset(offset)).scalars().all()
    return Page[AlertSummary](
        items=[_to_summary(a) for a in rows], total=total, limit=limit, offset=offset
    )


@router.get("/stats", summary="Alert queue composition")
def alert_stats(db: DbSession, _: RequireViewer) -> dict[str, Any]:
    by_severity = dict(
        db.execute(select(Alert.severity, func.count()).group_by(Alert.severity)).all()
    )
    by_status = dict(
        db.execute(select(Alert.status, func.count()).group_by(Alert.status)).all()
    )
    by_rule = [
        {"rule_id": rule_id, "count": count}
        for rule_id, count in db.execute(
            select(Alert.rule_id, func.count()).group_by(Alert.rule_id)
            .order_by(func.count().desc()).limit(15)
        ).all()
    ]
    return {"by_severity": by_severity, "by_status": by_status, "by_rule": by_rule,
            "total": sum(by_status.values())}


@router.get("/{alert_id}", response_model=AlertDetail, summary="One alert with its evidence")
def get_alert(alert_id: str, db: DbSession, _: RequireViewer) -> AlertDetail:
    alert = db.execute(select(Alert).where(Alert.alert_id == alert_id)).scalar_one_or_none()
    if alert is None:
        raise NotFoundError(f"Alert '{alert_id}' does not exist.")

    detail = AlertDetail.model_validate(alert)
    detail.incident_id = alert.incident.incident_id if alert.incident else None

    event_pks = [link.event_pk for link in alert.evidence_links]
    if event_pks:
        events = db.execute(
            select(Event).where(Event.id.in_(event_pks)).order_by(Event.timestamp.asc())
        ).scalars().all()
        detail.evidence = [EventSummary.model_validate(e) for e in events]
    return detail


@router.patch("/{alert_id}/status", response_model=AlertDetail, summary="Triage an alert")
def update_status(
    alert_id: str,
    payload: AlertStatusUpdate,
    db: DbSession,
    principal: RequireAnalyst,
) -> AlertDetail:
    """Change an alert's triage state.

    Marking something a false positive requires a reason. An unexplained
    dismissal destroys the only record of why a detection was wrong, which is
    exactly the information needed to improve the rule.
    """
    alert = db.execute(select(Alert).where(Alert.alert_id == alert_id)).scalar_one_or_none()
    if alert is None:
        raise NotFoundError(f"Alert '{alert_id}' does not exist.")

    try:
        new_status = AlertStatus(payload.status)
    except ValueError:
        raise ValidationFailed(
            f"'{payload.status}' is not a valid alert status. "
            f"Valid: {', '.join(s.value for s in AlertStatus)}"
        ) from None

    if new_status == AlertStatus.FALSE_POSITIVE and not (payload.reason or "").strip():
        raise ValidationFailed(
            "A reason is required when marking an alert as a false positive. "
            "It becomes the record of why this detection was wrong."
        )

    previous = alert.status
    alert.status = new_status
    alert.triaged_by = principal.username
    alert.triaged_at = utcnow()
    if new_status == AlertStatus.FALSE_POSITIVE:
        alert.false_positive_reason = payload.reason

    audit.record(
        db,
        actor=principal.username,
        actor_role=principal.role.value,
        action="alert_false_positive" if new_status == AlertStatus.FALSE_POSITIVE
        else "alert_status_changed",
        target_type="alert",
        target_id=alert.alert_id,
        details={"from": previous, "to": str(new_status), "reason": payload.reason,
                 "rule_id": alert.rule_id},
        ip_address=principal.ip_address,
    )

    # A triage decision changes the incident's picture, so recompute it.
    if alert.incident is not None:
        from app.correlation.engine import refresh_incident

        refresh_incident(db, alert.incident)

    db.commit()
    db.refresh(alert)

    detail = AlertDetail.model_validate(alert)
    detail.incident_id = alert.incident.incident_id if alert.incident else None
    return detail
