"""Hunt execution.

Simple hunts compile to a single SELECT.  Sequence hunts fetch the candidate set
in one query and then match ordering in Python, because expressing "A then B then
C within N seconds, correlated on the same source address" in portable SQL
produces something unreadable and dialect-specific for no gain at this scale.
The candidate set is bounded so the trade-off cannot become a denial of service.
"""

from __future__ import annotations

import datetime as dt
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.core.timeutils import iso, parse_timestamp, utcnow
from app.models.alerts import Alert
from app.models.events import Event
from app.models.incidents import Incident
from app.threat_hunting.builder import (
    build_condition,
    build_count,
    build_select,
    explain,
)
from app.threat_hunting.dsl import HuntQuery, SequenceHunt

logger = get_logger("sentinelx.hunt")

#: Bound on the working set for sequence hunts.
MAX_SEQUENCE_CANDIDATES = 20_000


@dataclass(slots=True)
class HuntResult:
    query: HuntQuery
    rows: list[dict[str, Any]] = field(default_factory=list)
    total: int = 0
    returned: int = 0
    duration_ms: int = 0
    interpretation: str = ""
    compiled_sql: str = ""
    truncated: bool = False
    #: Populated for sequence hunts: one entry per correlated match.
    matches: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "interpretation": self.interpretation,
            "query": self.query.model_dump(mode="json", exclude_none=True),
            "compiled_sql": self.compiled_sql,
            "total": self.total,
            "returned": self.returned,
            "duration_ms": self.duration_ms,
            "truncated": self.truncated,
            "rows": self.rows,
            "matches": self.matches,
        }


def _serialize_event(event: Event) -> dict[str, Any]:
    return {
        "kind": "event",
        "id": event.event_id,
        "timestamp": iso(event.timestamp),
        "event_type": event.event_type,
        "source": event.source,
        "host": event.host_ref,
        "user": event.user_ref,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "destination_port": event.destination_port,
        "process": event.process_name,
        "command_line": event.command_line,
        "file_path": event.file_path,
        "cloud_account": event.cloud_account,
        "action": event.action,
        "status": event.status,
        "message": event.message,
        "metadata": event.meta,
        "label": event.label,
        "is_demo": event.is_demo,
    }


def _serialize_alert(alert: Alert) -> dict[str, Any]:
    return {
        "kind": "alert",
        "id": alert.alert_id,
        "timestamp": iso(alert.detected_at),
        "rule_id": alert.rule_id,
        "rule_type": alert.rule_type,
        "title": alert.title,
        "severity": alert.severity,
        "status": alert.status,
        "confidence": alert.confidence,
        "risk_score": alert.risk_score,
        "host": alert.host_ref,
        "user": alert.user_ref,
        "source_ip": alert.source_ip,
        "technique_ids": alert.technique_ids,
        "incident_id": alert.incident.incident_id if alert.incident else None,
    }


def _serialize_incident(incident: Incident) -> dict[str, Any]:
    return {
        "kind": "incident",
        "id": incident.incident_id,
        "timestamp": iso(incident.last_seen),
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "confidence": incident.confidence,
        "risk_score": incident.risk_score,
        "alert_count": incident.alert_count,
        "event_count": incident.event_count,
        "affected_hosts": incident.affected_hosts,
        "affected_users": incident.affected_users,
        "technique_ids": incident.technique_ids,
    }


SERIALIZERS = {
    "events": _serialize_event,
    "alerts": _serialize_alert,
    "incidents": _serialize_incident,
}


def run_hunt(db: Session, query: HuntQuery, *, include_sql: bool = True) -> HuntResult:
    started = utcnow()
    result = HuntResult(query=query, interpretation=query.describe())

    if query.sequence is not None:
        _run_sequence(db, query, result)
    else:
        rows = list(db.execute(build_select(query)).scalars().all())
        serializer = SERIALIZERS[query.dataset]
        result.rows = [serializer(row) for row in rows]
        result.returned = len(rows)
        result.total = int(db.execute(build_count(query)).scalar_one())
        result.truncated = result.total > result.returned + query.offset

    if include_sql:
        try:
            result.compiled_sql = explain(query, db)
        except Exception:  # never let a display nicety fail the hunt
            result.compiled_sql = ""

    result.duration_ms = int((utcnow() - started).total_seconds() * 1000)
    logger.info(
        "hunt_executed",
        extra={
            "dataset": query.dataset,
            "filters": len(query.filters),
            "sequence": query.sequence is not None,
            "returned": result.returned,
            "duration_ms": result.duration_ms,
        },
    )
    return result


def _entity_key(event: Event, fields: list[str]) -> tuple:
    mapping = {
        "host": event.host_ref,
        "user": event.user_ref,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "cloud_account": event.cloud_account,
        "process": event.process_name,
    }
    return tuple((mapping.get(f) or "").lower() for f in fields)


def _run_sequence(db: Session, query: HuntQuery, result: HuntResult) -> None:
    sequence: SequenceHunt = query.sequence  # type: ignore[assignment]

    # One query for the whole candidate set: any event matching any step.
    step_conditions = []
    for step in sequence.steps:
        conditions = [build_condition("events", f) for f in step.filters]
        if conditions:
            from sqlalchemy import and_

            step_conditions.append(and_(*conditions))

    stmt = select(Event)
    if step_conditions:
        stmt = stmt.where(or_(*step_conditions))
    if query.filters:
        from sqlalchemy import and_

        stmt = stmt.where(and_(*[build_condition("events", f) for f in query.filters]))
    if query.time_range:
        if query.time_range.start:
            stmt = stmt.where(Event.timestamp >= query.time_range.start)
        if query.time_range.end:
            stmt = stmt.where(Event.timestamp <= query.time_range.end)
    stmt = stmt.order_by(Event.timestamp.asc()).limit(MAX_SEQUENCE_CANDIDATES)

    candidates = list(db.execute(stmt).scalars().all())
    result.truncated = len(candidates) >= MAX_SEQUENCE_CANDIDATES

    groups: dict[tuple, list[Event]] = defaultdict(list)
    for event in candidates:
        groups[_entity_key(event, sequence.correlate_on)].append(event)

    matches: list[dict[str, Any]] = []
    matched_events: list[Event] = []

    for key, events in groups.items():
        if all(part == "" for part in key):
            continue  # no correlating entity: cannot be a sequence
        matched = _match_ordered(events, sequence)
        if matched is None:
            continue
        flat = [e for _, step_events in matched for e in step_events]
        matched_events.extend(flat)
        matches.append({
            "correlation": dict(zip(sequence.correlate_on, key, strict=True)),
            "first_seen": iso(flat[0].timestamp),
            "last_seen": iso(flat[-1].timestamp),
            "span_seconds": int((flat[-1].timestamp - flat[0].timestamp).total_seconds()),
            "steps": [
                {
                    "name": name,
                    "count": len(step_events),
                    "event_ids": [e.event_id for e in step_events],
                    "first_seen": iso(step_events[0].timestamp),
                }
                for name, step_events in matched
            ],
            "event_ids": [e.event_id for e in flat],
        })
        if len(matches) >= query.limit:
            break

    seen: set[str] = set()
    ordered_rows: list[dict[str, Any]] = []
    for event in sorted(matched_events, key=lambda e: e.timestamp):
        if event.event_id in seen:
            continue
        seen.add(event.event_id)
        ordered_rows.append(_serialize_event(event))

    result.matches = matches
    result.rows = ordered_rows
    result.returned = len(ordered_rows)
    result.total = len(matches)


def _match_ordered(events: list[Event], sequence: SequenceHunt):
    """Greedy ordered match of the sequence steps within one correlation group."""
    from app.threat_hunting.builder import build_condition  # noqa: F401  (kept for symmetry)

    def step_matches(event: Event, step) -> bool:
        return all(_filter_matches(event, f) for f in step.filters)

    events = sorted(events, key=lambda e: e.timestamp)
    first_step = sequence.steps[0]
    anchors = [i for i, e in enumerate(events) if step_matches(e, first_step)][:200]

    for anchor in anchors:
        start = events[anchor].timestamp
        cursor = anchor
        matched: list[tuple[str, list[Event]]] = []
        ok = True

        for index, step in enumerate(sequence.steps):
            collected: list[Event] = []
            scan = cursor if index == 0 else cursor + 1
            for position in range(scan, len(events)):
                event = events[position]
                if (event.timestamp - start).total_seconds() > sequence.within_seconds:
                    break
                if step_matches(event, step):
                    collected.append(event)
                    cursor = position
                    if len(collected) >= step.min_count:
                        break
            if len(collected) < step.min_count:
                ok = False
                break
            matched.append((step.name, collected))

        if ok:
            return matched
    return None


def _filter_matches(event: Event, item) -> bool:
    """In-memory evaluation of one hunt filter.

    Ordering across sequence steps is not expressible in a single query, so the
    sequence path matches steps here instead. That means two implementations of
    the same filter semantics, which is a standing drift risk: they *had*
    drifted, with this path lowercasing strings while the builder compared them
    exactly, and with every datetime comparison here returning False.

    ``TestMatcherParity`` in tests/test_hunting.py now runs the same filters
    through both and asserts they select the same events. Any change here needs
    the matching change in app/threat_hunting/builder.py, and that test is what
    catches it if it does not.
    """
    from app.detection.fields import FIELD_MAP

    if item.field.startswith("metadata."):
        node: Any = event.meta or {}
        for part in item.field.split(".")[1:]:
            if not isinstance(node, dict) or part not in node:
                node = None
                break
            node = node[part]
        actual = node
    else:
        attr = FIELD_MAP.get(item.field)
        actual = getattr(event, attr, None) if attr else None

    value = item.value
    operator = item.operator

    if operator == "exists":
        return (actual is not None) == bool(value)
    if actual is None:
        return operator in {"ne", "not_in", "not_contains"}

    a = actual.lower() if isinstance(actual, str) else actual

    def norm(v: Any) -> Any:
        return v.lower() if isinstance(v, str) else v

    # Mirror the builder's boolean handling so the in-memory sequence path and
    # the SQL path agree on `metadata.flag == true`.
    def boolean_like(v: Any) -> bool:
        return isinstance(v, bool) or (isinstance(v, str) and str(v).lower() in {"true", "false"})

    def to_bool(v: Any) -> bool:
        return v if isinstance(v, bool) else str(v).lower() == "true"

    if operator in {"eq", "ne"} and boolean_like(value) and boolean_like(actual):
        equal = to_bool(actual) is to_bool(value)
        return equal if operator == "eq" else not equal

    if operator == "eq":
        return a == norm(value)
    if operator == "ne":
        return a != norm(value)
    if operator == "in":
        return a in [norm(v) for v in value]
    if operator == "not_in":
        return a not in [norm(v) for v in value]
    if operator == "contains":
        return str(norm(value)) in str(a)
    if operator == "not_contains":
        return str(norm(value)) not in str(a)
    if operator == "startswith":
        return str(a).startswith(str(norm(value)))
    if operator == "endswith":
        return str(a).endswith(str(norm(value)))
    if operator in {"gt", "gte", "lt", "lte"}:
        left: Any
        right: Any
        if isinstance(actual, dt.datetime):
            # The DSL coerces timestamp filters to datetimes, so both sides are
            # comparable. Returning False here — as this used to — made every
            # time comparison inside a sequence hunt silently match nothing
            # while the identical simple hunt worked.
            right = value if isinstance(value, dt.datetime) else parse_timestamp(str(value))
            left = actual
        else:
            try:
                left, right = float(actual), float(value)
            except (TypeError, ValueError):
                return False
        return {"gt": left > right, "gte": left >= right,
                "lt": left < right, "lte": left <= right}[operator]
    return False
