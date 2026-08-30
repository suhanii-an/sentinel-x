"""Host and identity inventory pages."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query
from sqlalchemy import Text, cast, func, or_, select

from app.api.deps import DbSession, RequireViewer
from app.core.errors import NotFoundError
from app.core.sqlutils import LIKE_ESCAPE, contains, json_member
from app.models.alerts import Alert
from app.models.entities import Host, User
from app.models.enums import IncidentStatus
from app.models.events import Event
from app.models.incidents import Incident
from app.models.platform import BehaviorBaseline
from app.schemas.common import Page
from app.schemas.security import (
    AlertSummary,
    HostDetail,
    HostSummary,
    IncidentSummary,
    UserDetail,
    UserSummary,
)

hosts_router = APIRouter(prefix="/hosts", tags=["hosts"])
users_router = APIRouter(prefix="/users", tags=["users"])

ACTIVE = [IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED]


def _alert_counts(db, column, value: str) -> dict[str, int]:
    rows = db.execute(
        select(Alert.severity, func.count()).where(column == value).group_by(Alert.severity)
    ).all()
    return dict(rows)


def _incidents_for(db, entity_key: str, limit: int = 10) -> list[IncidentSummary]:
    rows = db.execute(
        select(Incident)
        .where(cast(Incident.entity_keys, Text).ilike(json_member(entity_key), escape=LIKE_ESCAPE),
               Incident.status.in_(ACTIVE))
        .order_by(Incident.last_seen.desc()).limit(limit)
    ).scalars().all()
    return [IncidentSummary.model_validate(i) for i in rows]


def _recent_alerts(db, column, value: str, limit: int = 15) -> list[AlertSummary]:
    rows = db.execute(
        select(Alert).where(column == value).order_by(Alert.detected_at.desc()).limit(limit)
    ).scalars().all()
    out = []
    for alert in rows:
        summary = AlertSummary.model_validate(alert)
        summary.incident_id = alert.incident.incident_id if alert.incident else None
        out.append(summary)
    return out


# ---------------------------------------------------------------------- hosts
@hosts_router.get("", response_model=Page[HostSummary], summary="Asset inventory")
def list_hosts(
    db: DbSession,
    _: RequireViewer,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    os_family: str | None = None,
    environment: str | None = None,
    isolated: bool | None = None,
    q: Annotated[str | None, Query(max_length=128)] = None,
) -> Page[HostSummary]:
    conditions = []
    if os_family:
        conditions.append(Host.os_family == os_family)
    if environment:
        conditions.append(Host.environment == environment)
    if isolated is not None:
        conditions.append(Host.is_isolated.is_(isolated))
    if q:
        needle = contains(q)
        conditions.append(
            or_(
                Host.host_id.ilike(needle, escape=LIKE_ESCAPE),
                Host.hostname.ilike(needle, escape=LIKE_ESCAPE),
            )
        )

    stmt = select(Host)
    count_stmt = select(func.count()).select_from(Host)
    for condition in conditions:
        stmt = stmt.where(condition)
        count_stmt = count_stmt.where(condition)

    total = db.execute(count_stmt).scalar_one()
    rows = db.execute(
        stmt.order_by(Host.criticality.desc(), Host.host_id.asc()).limit(limit).offset(offset)
    ).scalars().all()
    return Page[HostSummary](
        items=[HostSummary.model_validate(h) for h in rows],
        total=total, limit=limit, offset=offset,
    )


@hosts_router.get("/{host_id}", response_model=HostDetail, summary="Host detail")
def get_host(host_id: str, db: DbSession, _: RequireViewer) -> HostDetail:
    host = db.execute(select(Host).where(Host.host_id == host_id)).scalar_one_or_none()
    if host is None:
        raise NotFoundError(f"Host '{host_id}' is not in the asset inventory.")

    detail = HostDetail.model_validate(host)
    detail.event_count = db.execute(
        select(func.count()).select_from(Event).where(Event.host_ref == host_id)
    ).scalar_one()
    detail.alert_counts = _alert_counts(db, Alert.host_ref, host_id)
    detail.open_incidents = _incidents_for(db, f"host:{host_id}")
    detail.recent_alerts = _recent_alerts(db, Alert.host_ref, host_id)

    detail.users = [
        row[0] for row in db.execute(
            select(Event.user_ref).where(Event.host_ref == host_id, Event.user_ref.isnot(None))
            .group_by(Event.user_ref).order_by(func.count().desc()).limit(20)
        ).all()
    ]
    detail.top_processes = [
        {"process": name, "count": count}
        for name, count in db.execute(
            select(Event.process_name, func.count())
            .where(Event.host_ref == host_id, Event.process_name.isnot(None))
            .group_by(Event.process_name).order_by(func.count().desc()).limit(15)
        ).all()
    ]
    detail.network_peers = [
        {"destination_ip": ip, "port": port, "connections": count}
        for ip, port, count in db.execute(
            select(Event.destination_ip, Event.destination_port, func.count())
            .where(Event.host_ref == host_id, Event.destination_ip.isnot(None))
            .group_by(Event.destination_ip, Event.destination_port)
            .order_by(func.count().desc()).limit(15)
        ).all()
    ]
    return detail


@hosts_router.get("/{host_id}/timeline", summary="Host activity timeline")
def host_timeline(
    host_id: str,
    db: DbSession,
    _: RequireViewer,
    limit: Annotated[int, Query(ge=1, le=250)] = 80,
) -> list[dict[str, Any]]:
    from app.services.timeline import build_live_timeline

    return build_live_timeline(db, limit=limit, host=host_id)


# ---------------------------------------------------------------------- users
@users_router.get("", response_model=Page[UserSummary], summary="Identity inventory")
def list_users(
    db: DbSession,
    _: RequireViewer,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    user_type: str | None = None,
    privileged: bool | None = None,
    disabled: bool | None = None,
    q: Annotated[str | None, Query(max_length=128)] = None,
) -> Page[UserSummary]:
    conditions = []
    if user_type:
        conditions.append(User.user_type == user_type)
    if privileged is not None:
        conditions.append(User.is_privileged.is_(privileged))
    if disabled is not None:
        conditions.append(User.is_disabled.is_(disabled))
    if q:
        needle = contains(q)
        conditions.append(
            or_(
                User.user_id.ilike(needle, escape=LIKE_ESCAPE),
                User.display_name.ilike(needle, escape=LIKE_ESCAPE),
            )
        )

    stmt = select(User)
    count_stmt = select(func.count()).select_from(User)
    for condition in conditions:
        stmt = stmt.where(condition)
        count_stmt = count_stmt.where(condition)

    total = db.execute(count_stmt).scalar_one()
    rows = db.execute(
        stmt.order_by(User.is_privileged.desc(), User.user_id.asc()).limit(limit).offset(offset)
    ).scalars().all()
    return Page[UserSummary](
        items=[UserSummary.model_validate(u) for u in rows],
        total=total, limit=limit, offset=offset,
    )


@users_router.get("/{user_id}", response_model=UserDetail, summary="Identity detail")
def get_user(user_id: str, db: DbSession, _: RequireViewer) -> UserDetail:
    user = db.execute(select(User).where(User.user_id == user_id)).scalar_one_or_none()
    if user is None:
        raise NotFoundError(f"Account '{user_id}' is not in the identity inventory.")

    detail = UserDetail.model_validate(user)
    detail.event_count = db.execute(
        select(func.count()).select_from(Event).where(Event.user_ref == user_id)
    ).scalar_one()
    detail.alert_counts = _alert_counts(db, Alert.user_ref, user_id)
    detail.open_incidents = _incidents_for(db, f"user:{user_id}")
    detail.recent_alerts = _recent_alerts(db, Alert.user_ref, user_id)

    detail.source_ips = [
        {"source_ip": ip, "count": count}
        for ip, count in db.execute(
            select(Event.source_ip, func.count())
            .where(Event.user_ref == user_id, Event.source_ip.isnot(None))
            .group_by(Event.source_ip).order_by(func.count().desc()).limit(20)
        ).all()
    ]
    detail.hosts = [
        {"host": host, "count": count}
        for host, count in db.execute(
            select(Event.host_ref, func.count())
            .where(Event.user_ref == user_id, Event.host_ref.isnot(None))
            .group_by(Event.host_ref).order_by(func.count().desc()).limit(20)
        ).all()
    ]

    auth_rows = db.execute(
        select(Event.status, func.count())
        .where(Event.user_ref == user_id, Event.event_type == "authentication")
        .group_by(Event.status)
    ).all()
    auth_counts = dict(auth_rows)
    detail.authentication_summary = {
        "success": auth_counts.get("success", 0),
        "failure": auth_counts.get("failure", 0),
        "total": sum(auth_counts.values()),
    }

    # The behavioural baseline, exposed so the analyst can see exactly what
    # "unusual" is being measured against rather than taking the score on trust.
    baselines = db.execute(
        select(BehaviorBaseline).where(
            BehaviorBaseline.entity_type == "user",
            BehaviorBaseline.entity_ref == user_id.lower(),
        )
    ).scalars().all()
    detail.baseline = {
        row.feature: {
            "value": row.value,
            "observations": row.observation_count,
            "updated_at": row.updated_at.isoformat(),
        }
        for row in baselines
    }
    return detail


@users_router.get("/{user_id}/timeline", summary="Identity activity timeline")
def user_timeline(
    user_id: str,
    db: DbSession,
    _: RequireViewer,
    limit: Annotated[int, Query(ge=1, le=250)] = 80,
) -> list[dict[str, Any]]:
    from app.services.timeline import build_live_timeline

    return build_live_timeline(db, limit=limit, user=user_id)
