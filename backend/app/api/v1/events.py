"""Event ingestion and retrieval."""

from __future__ import annotations

import datetime as dt
from typing import Annotated, Any

from fastapi import APIRouter, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from app.api.deps import DbSession, RequireAnalyst, RequireViewer
from app.core.errors import NotFoundError, ValidationFailed
from app.models.events import Event
from app.schemas.common import Page
from app.schemas.security import EventDetail, EventSummary
from app.services.pipeline import process_events, process_raw_records
from app.services.timeline import build_live_timeline
from app.telemetry.registry import supported_sources
from app.telemetry.schema import NormalizedEvent, RawTelemetry

router = APIRouter(prefix="/events", tags=["events"])

MAX_BATCH = 500


class NormalizedBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    events: list[NormalizedEvent] = Field(min_length=1, max_length=MAX_BATCH)


class RawBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: str
    records: list[dict[str, Any]] = Field(min_length=1, max_length=MAX_BATCH)
    #: When true a single malformed record fails the whole batch. Off by default:
    #: one bad line in a shipper's payload should not discard the attack in the
    #: other 199 records.
    strict: bool = False


class IngestionResult(BaseModel):
    events_ingested: int
    events_rejected: int
    alerts_created: int
    alerts_suppressed: int
    incidents_touched: int
    ioc_matches: int
    detection_ms: int
    correlation_ms: int
    total_ms: int
    rejected: list[dict[str, Any]] = Field(default_factory=list)
    alert_ids: list[str] = Field(default_factory=list)
    incident_ids: list[str] = Field(default_factory=list)
    rule_errors: list[str] = Field(default_factory=list)


def _result(result) -> IngestionResult:
    return IngestionResult(
        **result.summary(),
        rejected=result.rejected[:25],
        alert_ids=[a.alert_id for a in result.alerts],
        incident_ids=sorted({i.incident_id for i in result.incidents}),
        rule_errors=result.rule_errors[:10],
    )


@router.get("", response_model=Page[EventSummary], summary="Query security events")
def list_events(
    db: DbSession,
    _: RequireViewer,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    event_type: str | None = None,
    host: str | None = None,
    user: str | None = None,
    source_ip: str | None = None,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    since: dt.datetime | None = None,
    until: dt.datetime | None = None,
) -> Page[EventSummary]:
    conditions = []
    if event_type:
        conditions.append(Event.event_type == event_type)
    if host:
        conditions.append(Event.host_ref == host)
    if user:
        conditions.append(Event.user_ref == user)
    if source_ip:
        conditions.append(Event.source_ip == source_ip)
    if status_filter:
        conditions.append(Event.status == status_filter)
    if since:
        conditions.append(Event.timestamp >= since)
    if until:
        conditions.append(Event.timestamp <= until)

    stmt = select(Event)
    count_stmt = select(func.count()).select_from(Event)
    for condition in conditions:
        stmt = stmt.where(condition)
        count_stmt = count_stmt.where(condition)

    total = db.execute(count_stmt).scalar_one()
    rows = db.execute(
        stmt.order_by(Event.timestamp.desc()).limit(limit).offset(offset)
    ).scalars().all()

    return Page[EventSummary](
        items=[EventSummary.model_validate(r) for r in rows],
        total=total, limit=limit, offset=offset,
    )


@router.get("/timeline", summary="Recent estate-wide activity")
def timeline(
    db: DbSession,
    _: RequireViewer,
    limit: Annotated[int, Query(ge=1, le=250)] = 60,
    host: str | None = None,
    user: str | None = None,
    minutes: Annotated[int | None, Query(ge=1, le=60 * 24 * 30)] = None,
) -> list[dict[str, Any]]:
    from app.core.timeutils import utcnow

    since = utcnow() - dt.timedelta(minutes=minutes) if minutes else None
    return build_live_timeline(db, limit=limit, since=since, host=host, user=user)


@router.get("/sources", summary="Telemetry sources with normalizers")
def sources(_: RequireViewer) -> dict[str, Any]:
    return {
        "sources": supported_sources(),
        "note": (
            "Each source has a normalizer that maps its native format onto the "
            "canonical event schema. Detection rules are written against the "
            "canonical schema only."
        ),
    }


@router.get("/{event_id}", response_model=EventDetail, summary="One event, including its raw record")
def get_event(event_id: str, db: DbSession, _: RequireViewer) -> EventDetail:
    event = db.execute(select(Event).where(Event.event_id == event_id)).scalar_one_or_none()
    if event is None:
        raise NotFoundError(f"Event '{event_id}' does not exist.")
    return EventDetail.model_validate(event)


@router.post(
    "",
    response_model=IngestionResult,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest pre-normalized events",
)
def ingest_normalized(payload: NormalizedBatch, db: DbSession, _: RequireAnalyst) -> IngestionResult:
    """Ingest events already in the canonical schema.

    Runs the full pipeline: persistence, detection, alerting and correlation.
    There is no separate path for demo data — everything goes through here.
    """
    result = process_events(db, payload.events)
    db.commit()
    return _result(result)


@router.post(
    "/raw",
    response_model=IngestionResult,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest source-native telemetry",
)
def ingest_raw(payload: RawBatch, db: DbSession, _: RequireAnalyst) -> IngestionResult:
    """Ingest records in a source's native format, normalizing on the way in."""
    if payload.source not in supported_sources():
        raise ValidationFailed(
            f"No normalizer for source '{payload.source}'. "
            f"Supported: {', '.join(supported_sources())}"
        )
    # Bound each record before it reaches the normalizer.
    for record in payload.records:
        RawTelemetry(source=payload.source, record=record)

    result = process_raw_records(db, payload.source, payload.records, strict=payload.strict)
    db.commit()
    return _result(result)
