"""Stateful detection pass: database in, alerts out.

The candidate-event query is the interesting part.  Stateful rules (threshold,
sequence) need history, but loading the whole table on every ingestion does not
scale and loading only the new batch would make those rules impossible.

The compromise is an *entity-scoped lookback*: fetch history within the lookback
window, restricted to entities that appear in the incoming batch.  This is sound
rather than merely convenient — every stateful rule is required by the schema to
declare ``group_by``, and grouping is always on an entity field, so an event that
shares no entity with the new batch cannot participate in any group the batch
could complete.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Sequence
from dataclasses import dataclass, field

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.core.timeutils import utcnow
from app.detection.engine import DetectionEngine
from app.detection.results import DetectionContext, DetectionResult
from app.models.alerts import Alert
from app.models.events import Event
from app.services import baselines as baseline_service
from app.services import ioc_matching
from app.services.alerts import persist_detections
from app.services.rule_registry import active_engine, record_rule_firings

logger = get_logger("sentinelx.pipeline")

#: Hard cap on the candidate set.  A pathological batch must not be able to pull
#: the entire events table into memory.
MAX_CANDIDATE_EVENTS = 20_000


@dataclass(slots=True)
class DetectionOutcome:
    alerts: list[Alert] = field(default_factory=list)
    results: list[DetectionResult] = field(default_factory=list)
    suppressed: int = 0
    candidate_count: int = 0
    ioc_matches: int = 0
    duration_ms: int = 0
    rule_errors: list[str] = field(default_factory=list)


def candidate_events(
    db: Session,
    new_events: Sequence[Event],
    *,
    lookback_seconds: int | None = None,
) -> list[Event]:
    """History the stateful rules need, scoped to the batch's entities."""
    if not new_events:
        return []

    lookback = lookback_seconds if lookback_seconds is not None else settings.DETECTION_LOOKBACK_SECONDS
    earliest = min(e.timestamp for e in new_events)
    latest = max(e.timestamp for e in new_events)
    window_start = earliest - dt.timedelta(seconds=lookback)

    hosts = sorted({e.host_ref for e in new_events if e.host_ref})
    users = sorted({e.user_ref for e in new_events if e.user_ref})
    ips = sorted({ip for e in new_events for ip in (e.source_ip, e.destination_ip) if ip})
    accounts = sorted({e.cloud_account for e in new_events if e.cloud_account})

    entity_filters = []
    if hosts:
        entity_filters.append(Event.host_ref.in_(hosts))
    if users:
        entity_filters.append(Event.user_ref.in_(users))
    if ips:
        entity_filters.append(Event.source_ip.in_(ips))
        entity_filters.append(Event.destination_ip.in_(ips))
    if accounts:
        entity_filters.append(Event.cloud_account.in_(accounts))

    stmt = select(Event).where(Event.timestamp >= window_start, Event.timestamp <= latest)
    if entity_filters:
        stmt = stmt.where(or_(*entity_filters))
    stmt = stmt.order_by(Event.timestamp.asc()).limit(MAX_CANDIDATE_EVENTS)

    rows = list(db.execute(stmt).scalars().all())

    # Guarantee the new batch is present even if it fell outside the filters
    # (for example an event whose only entity is a destination IP).
    known = {row.id for row in rows}
    for event in new_events:
        if event.id not in known:
            rows.append(event)
    rows.sort(key=lambda e: e.timestamp)
    return rows


def run_detection(
    db: Session,
    new_events: Sequence[Event],
    *,
    simulation_run_pk: int | None = None,
    is_demo: bool = False,
    engine: DetectionEngine | None = None,
    update_baselines: bool = True,
) -> DetectionOutcome:
    started = utcnow()
    outcome = DetectionOutcome()
    if not new_events:
        return outcome

    rule_errors: list[str] = []
    if engine is None:
        engine, rule_errors = active_engine(db)
    outcome.rule_errors = rule_errors

    events = candidate_events(db, new_events)
    outcome.candidate_count = len(events)

    ctx = DetectionContext(
        events=events,
        now=started,
        iocs=ioc_matching.build_ioc_index(db),
        baselines=baseline_service.build_snapshot(db, [e.user_ref for e in events if e.user_ref]),
        new_event_ids={e.event_id for e in new_events},
    )

    results = engine.evaluate(ctx)
    outcome.results = results

    # IOC matches are recorded before alerting so the risk model can see them.
    outcome.ioc_matches = ioc_matching.record_ioc_matches(db, results)

    alerts, suppressed = persist_detections(
        db, results, simulation_run_pk=simulation_run_pk, is_demo=is_demo
    )
    outcome.alerts = alerts
    outcome.suppressed = suppressed

    record_rule_firings(db, [a.rule_id for a in alerts])

    # Baselines are updated last: detection must evaluate an event against the
    # history that existed *before* it arrived.
    if update_baselines:
        baseline_service.update_baselines(db, new_events)

    outcome.duration_ms = int((utcnow() - started).total_seconds() * 1000)
    logger.info(
        "detection_pass",
        extra={
            "new_events": len(new_events),
            "candidates": outcome.candidate_count,
            "detections": len(results),
            "alerts": len(alerts),
            "suppressed": suppressed,
            "duration_ms": outcome.duration_ms,
        },
    )
    return outcome
