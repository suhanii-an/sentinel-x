"""Builders shared across test modules.

Kept out of ``conftest.py`` because these are constructors, not fixtures — a
test that wants two incidents should not have to fight pytest's fixture
caching to get them.
"""

from __future__ import annotations

import datetime as dt
import itertools

from sqlalchemy.orm import Session

from app.core.ids import alert_id, next_incident_id
from app.models.alerts import Alert, AlertEvent
from app.models.enums import IncidentStatus
from app.models.events import Event
from app.models.incidents import Incident, IncidentEvent

_COUNTER = itertools.count(1)


def make_event(
    db: Session,
    *,
    at: dt.datetime | None = None,
    event_type: str = "authentication",
    source: str = "linux_auth",
    status: str = "failure",
    host: str | None = "web-01",
    user: str | None = "alice",
    source_ip: str | None = "203.0.113.10",
    command_line: str | None = None,
    metadata: dict | None = None,
) -> Event:
    event = Event(
        event_id=f"EVT-{next(_COUNTER):010d}",
        timestamp=at or dt.datetime.now(dt.UTC),
        event_type=event_type,
        source=source,
        action="login",
        status=status,
        host_ref=host,
        user_ref=user,
        source_ip=source_ip,
        command_line=command_line,
        meta=metadata or {},
        raw_event={},
    )
    db.add(event)
    db.flush()
    return event


def make_alert(
    db: Session,
    events: list[Event],
    *,
    rule_id: str = "TEST_RULE",
    severity: str = "high",
    confidence: float = 0.8,
    techniques: list[str] | None = None,
    tactics: list[str] | None = None,
) -> Alert:
    first = min(e.timestamp for e in events)
    last = max(e.timestamp for e in events)
    entity_keys = sorted(
        {f"host:{e.host_ref}" for e in events if e.host_ref}
        | {f"user:{e.user_ref}" for e in events if e.user_ref}
        | {f"ip:{e.source_ip}" for e in events if e.source_ip}
    )
    alert = Alert(
        alert_id=alert_id(),
        rule_id=rule_id,
        rule_name=rule_id.replace("_", " ").title(),
        rule_type="threshold",
        title=f"{rule_id} fired",
        description="A test detection.",
        severity=severity,
        confidence=confidence,
        status="new",
        detected_at=last,
        first_event_at=first,
        last_event_at=last,
        entity_keys=entity_keys,
        technique_ids=techniques or ["T1110"],
        tactics=tactics or ["TA0006"],
        explanation=["Because the test said so."],
        risk_score=60.0,
        risk_breakdown=[],
        dedup_key=f"{rule_id}:{next(_COUNTER)}",
    )
    db.add(alert)
    db.flush()
    for event in events:
        db.add(AlertEvent(alert_pk=alert.id, event_pk=event.id, role="trigger"))
    db.flush()
    return alert


def seeded_incident(
    db: Session,
    *,
    command_line: str | None = None,
    event_count: int = 3,
) -> Incident:
    """A minimal but complete incident: events, an alert, and the links.

    Complete on purpose — an incident with no evidence exercises none of the
    code that reads evidence, which is most of what the AI and reporting layers
    do.
    """
    base = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=30)
    events = [
        make_event(
            db,
            at=base + dt.timedelta(seconds=i * 30),
            command_line=command_line,
            event_type="process" if command_line else "authentication",
        )
        for i in range(event_count)
    ]
    alert = make_alert(db, events)

    incident = Incident(
        incident_id=next_incident_id(db),
        title="Test incident",
        summary="Seeded by the test suite.",
        first_seen=events[0].timestamp,
        last_seen=events[-1].timestamp,
        severity="high",
        status=IncidentStatus.OPEN,
        confidence=0.8,
        confidence_breakdown=[],
        risk_score=65.0,
        risk_breakdown=[],
        correlation_reason={"shared_entities": ["user:alice"]},
        attack_chain=[],
        affected_hosts=["web-01"],
        affected_users=["alice"],
        targeted_users=[],
        source_ips=["203.0.113.10"],
        destination_ips=[],
        technique_ids=["T1110"],
        ioc_matches=[],
        entity_keys=["host:web-01", "user:alice", "ip:203.0.113.10"],
        alert_count=1,
        event_count=len(events),
    )
    db.add(incident)
    db.flush()

    alert.incident_pk = incident.id
    for event in events:
        db.add(IncidentEvent(incident_pk=incident.id, event_pk=event.id, role="trigger"))
    db.flush()
    return incident
