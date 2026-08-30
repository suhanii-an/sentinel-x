"""Indicator store."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query, status
from sqlalchemy import Text, cast, func, select

from app.api.deps import DbSession, RequireAnalyst, RequireViewer
from app.core.errors import ConflictError, NotFoundError, ValidationFailed
from app.core.ids import ioc_id as new_ioc_id
from app.core.sqlutils import LIKE_ESCAPE, contains, json_member
from app.core.timeutils import utcnow
from app.models.enums import IOCType
from app.models.events import Event
from app.models.incidents import Incident
from app.models.iocs import IOC, IOCMatch
from app.schemas.common import Page
from app.schemas.security import EventSummary, IncidentSummary, IOCCreate, IOCDetail, IOCSummary
from app.services import audit
from app.services.ioc_store import install_indicators, load_indicator_file

router = APIRouter(prefix="/iocs", tags=["indicators"])


@router.get("", response_model=Page[IOCSummary], summary="Indicator list")
def list_iocs(
    db: DbSession,
    _: RequireViewer,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    ioc_type: str | None = None,
    active: bool | None = None,
    matched_only: bool = False,
    q: Annotated[str | None, Query(max_length=256)] = None,
) -> Page[IOCSummary]:
    conditions = []
    if ioc_type:
        conditions.append(IOC.ioc_type == ioc_type)
    if active is not None:
        conditions.append(IOC.is_active.is_(active))
    if matched_only:
        conditions.append(IOC.match_count > 0)
    if q:
        conditions.append(IOC.indicator.ilike(contains(q), escape=LIKE_ESCAPE))

    stmt = select(IOC)
    count_stmt = select(func.count()).select_from(IOC)
    for condition in conditions:
        stmt = stmt.where(condition)
        count_stmt = count_stmt.where(condition)

    total = db.execute(count_stmt).scalar_one()
    rows = db.execute(
        stmt.order_by(IOC.match_count.desc(), IOC.confidence.desc()).limit(limit).offset(offset)
    ).scalars().all()
    return Page[IOCSummary](
        items=[IOCSummary.model_validate(i) for i in rows],
        total=total, limit=limit, offset=offset,
    )


@router.get("/provenance", summary="Where the bundled indicators came from")
def provenance(_: RequireViewer) -> dict[str, Any]:
    """Separate local demo data from external threat intelligence, explicitly.

    The README makes the same distinction. Presenting synthetic indicators as
    though they came from a feed would be the single most misleading thing this
    platform could do.
    """
    document = load_indicator_file()
    return {
        "dataset": document.get("dataset"),
        "version": document.get("version"),
        "provenance": document.get("provenance"),
        "notice": document.get("notice"),
        "indicator_count": len(document.get("indicators", [])),
        "external_feeds_configured": [],
        "external_feed_support": (
            "Not implemented. The IOC schema is provider-neutral and the matching engine "
            "reads whatever is in the store, so attaching a STIX/TAXII or commercial feed "
            "is a loader change rather than a data-model change. No feed integration ships "
            "with this project."
        ),
    }


@router.get("/{ioc_id}", response_model=IOCDetail, summary="Indicator detail with matches")
def get_ioc(ioc_id: str, db: DbSession, _: RequireViewer) -> IOCDetail:
    ioc = db.execute(select(IOC).where(IOC.ioc_id == ioc_id)).scalar_one_or_none()
    if ioc is None:
        raise NotFoundError(f"Indicator '{ioc_id}' does not exist.")

    detail = IOCDetail.model_validate(ioc)
    matches = db.execute(
        select(IOCMatch).where(IOCMatch.ioc_pk == ioc.id)
        .order_by(IOCMatch.matched_at.desc()).limit(100)
    ).scalars().all()

    event_pks = [m.event_pk for m in matches]
    if event_pks:
        events = db.execute(
            select(Event).where(Event.id.in_(event_pks)).order_by(Event.timestamp.desc())
        ).scalars().all()
        detail.matched_events = [EventSummary.model_validate(e) for e in events]
        detail.affected_hosts = sorted({e.host_ref for e in events if e.host_ref})

    incidents = db.execute(
        select(Incident)
        .where(cast(Incident.ioc_matches, Text).ilike(json_member(ioc.ioc_id), escape=LIKE_ESCAPE))
        .order_by(Incident.last_seen.desc()).limit(20)
    ).scalars().all()
    detail.related_incidents = [IncidentSummary.model_validate(i) for i in incidents]
    return detail


@router.post("", response_model=IOCSummary, status_code=status.HTTP_201_CREATED,
             summary="Add an indicator")
def create_ioc(payload: IOCCreate, db: DbSession, principal: RequireAnalyst) -> IOCSummary:
    if payload.ioc_type not in {t.value for t in IOCType}:
        raise ValidationFailed(
            f"'{payload.ioc_type}' is not a supported indicator type. "
            f"Supported: {', '.join(t.value for t in IOCType)}"
        )

    existing = db.execute(
        select(IOC).where(IOC.indicator == payload.indicator, IOC.ioc_type == payload.ioc_type)
    ).scalar_one_or_none()
    if existing is not None:
        raise ConflictError(f"Indicator '{payload.indicator}' already exists as {existing.ioc_id}.")

    ioc = IOC(
        ioc_id=new_ioc_id(),
        indicator=payload.indicator.strip(),
        ioc_type=payload.ioc_type,
        source=payload.source,
        confidence=payload.confidence,
        severity=payload.severity,
        description=payload.description,
        tags=payload.tags,
        first_seen=utcnow(),
        is_demo=False,
    )
    db.add(ioc)
    audit.record(
        db, actor=principal.username, actor_role=principal.role.value,
        action="ioc_created", target_type="ioc", target_id=ioc.ioc_id,
        details={"indicator": ioc.indicator, "type": ioc.ioc_type},
        ip_address=principal.ip_address,
    )
    db.commit()
    db.refresh(ioc)
    return IOCSummary.model_validate(ioc)


@router.post("/reload", summary="Reload the bundled indicator dataset")
def reload_indicators(db: DbSession, principal: RequireAnalyst) -> dict[str, Any]:
    created, updated = install_indicators(db)
    audit.record(
        db, actor=principal.username, actor_role=principal.role.value,
        action="ioc_created", target_type="ioc_dataset", target_id="local-demo",
        details={"created": created, "updated": updated},
        ip_address=principal.ip_address,
    )
    db.commit()
    return {"created": created, "updated": updated,
            "message": "Bundled local demo indicators reloaded."}
