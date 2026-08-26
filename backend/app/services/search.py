"""Global search.

An analyst types one thing — an incident number, a hostname, an address, a
technique ID — and expects the platform to work out what it is. Type is inferred
from shape first (``SX-2026-0042`` can only be an incident, ``T1110`` can only be
a technique), then falls back to a bounded search across entity names.

Every branch is an indexed lookup or a bounded prefix search. There is no
cross-table LIKE '%term%' scan here, because a search box that gets slower as the
platform fills up is a search box analysts stop using.
"""

from __future__ import annotations

import re
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.netutils import parse as parse_ip
from app.core.sqlutils import LIKE_ESCAPE, contains, escape_like, json_member, starts_with
from app.core.timeutils import iso
from app.mitre import catalog
from app.models.alerts import Alert
from app.models.entities import Host, User
from app.models.enums import AlertStatus, IncidentStatus
from app.models.events import Event
from app.models.incidents import Incident
from app.models.iocs import IOC

INCIDENT_PATTERN = re.compile(r"^SX-\d{4}-\d{4}$", re.IGNORECASE)
ALERT_PATTERN = re.compile(r"^ALT-[A-Z0-9]+$", re.IGNORECASE)
EVENT_PATTERN = re.compile(r"^EVT-[A-Z0-9]+$", re.IGNORECASE)
IOC_PATTERN = re.compile(r"^IOC-[A-Z0-9]+$", re.IGNORECASE)
TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)
HASH_PATTERN = re.compile(r"^[a-f0-9]{32,128}$", re.IGNORECASE)

MAX_PER_CATEGORY = 10

ACTIVE_INCIDENTS = [IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED]
OPEN_ALERTS = [AlertStatus.NEW, AlertStatus.INVESTIGATING, AlertStatus.ESCALATED]


def classify_term(term: str) -> str:
    """What kind of thing the analyst typed."""
    term = term.strip()
    if INCIDENT_PATTERN.match(term):
        return "incident_id"
    if ALERT_PATTERN.match(term):
        return "alert_id"
    if EVENT_PATTERN.match(term):
        return "event_id"
    if IOC_PATTERN.match(term):
        return "ioc_id"
    if TECHNIQUE_PATTERN.match(term):
        return "technique"
    if parse_ip(term) is not None:
        return "ip"
    if HASH_PATTERN.match(term):
        return "hash"
    return "text"


def search(db: Session, term: str, *, limit: int = MAX_PER_CATEGORY) -> dict[str, Any]:
    term = (term or "").strip()
    if len(term) < 2:
        return {"query": term, "kind": "too_short", "results": {},
                "message": "Enter at least two characters."}

    kind = classify_term(term)
    results: dict[str, list[dict[str, Any]]] = {}

    if kind == "incident_id":
        results["incidents"] = _incidents(
            db, Incident.incident_id.ilike(escape_like(term), escape=LIKE_ESCAPE), limit
        )
    elif kind == "alert_id":
        results["alerts"] = _alerts(db, Alert.alert_id.ilike(escape_like(term), escape=LIKE_ESCAPE), limit)
    elif kind == "event_id":
        results["events"] = _events(db, Event.event_id.ilike(escape_like(term), escape=LIKE_ESCAPE), limit)
    elif kind == "ioc_id":
        results["indicators"] = _iocs(db, IOC.ioc_id.ilike(escape_like(term), escape=LIKE_ESCAPE), limit)
    elif kind == "technique":
        results["techniques"] = _technique(db, term.upper())
    elif kind == "ip":
        results["events"] = _events(
            db, or_(Event.source_ip == term, Event.destination_ip == term), limit
        )
        results["alerts"] = _alerts(db, Alert.source_ip == term, limit)
        results["indicators"] = _iocs(db, IOC.indicator == term, limit)
        results["hosts"] = _hosts(db, Host.ip_address == term, limit)
        results["incidents"] = _incidents_by_entity(db, f"ip:{term}", limit)
    elif kind == "hash":
        results["events"] = _events(db, Event.file_hash.ilike(escape_like(term), escape=LIKE_ESCAPE), limit)
        results["indicators"] = _iocs(
            db, IOC.indicator.ilike(escape_like(term), escape=LIKE_ESCAPE), limit
        )
    else:
        pattern = starts_with(term)
        substring = contains(term)
        results["hosts"] = _hosts(
            db,
            or_(
                Host.host_id.ilike(pattern, escape=LIKE_ESCAPE),
                Host.hostname.ilike(pattern, escape=LIKE_ESCAPE),
            ),
            limit,
        )
        results["users"] = _users(
            db,
            or_(
                User.user_id.ilike(pattern, escape=LIKE_ESCAPE),
                User.display_name.ilike(substring, escape=LIKE_ESCAPE),
            ),
            limit,
        )
        results["indicators"] = _iocs(db, IOC.indicator.ilike(pattern, escape=LIKE_ESCAPE), limit)
        results["incidents"] = _incidents(
            db, Incident.title.ilike(substring, escape=LIKE_ESCAPE), limit
        )
        results["alerts"] = _alerts(
            db,
            or_(
                Alert.title.ilike(substring, escape=LIKE_ESCAPE),
                Alert.rule_id.ilike(pattern, escape=LIKE_ESCAPE),
            ),
            limit,
        )
        results["techniques"] = _techniques_by_name(term)

    results = {key: value for key, value in results.items() if value}
    total = sum(len(v) for v in results.values())
    return {
        "query": term,
        "kind": kind,
        "total": total,
        "results": results,
        "message": None if total else f"No results for '{term}'.",
    }


def _incidents(db: Session, condition, limit: int) -> list[dict[str, Any]]:
    rows = db.execute(
        select(Incident).where(condition).order_by(Incident.last_seen.desc()).limit(limit)
    ).scalars().all()
    return [_incident_row(i) for i in rows]


def _incidents_by_entity(db: Session, entity_key: str, limit: int) -> list[dict[str, Any]]:
    from sqlalchemy import Text, cast

    rows = db.execute(
        select(Incident)
        .where(cast(Incident.entity_keys, Text).ilike(json_member(entity_key), escape=LIKE_ESCAPE))
        .order_by(Incident.last_seen.desc()).limit(limit)
    ).scalars().all()
    return [_incident_row(i) for i in rows]


def _incident_row(incident: Incident) -> dict[str, Any]:
    return {
        "type": "incident",
        "id": incident.incident_id,
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "risk_score": incident.risk_score,
        "last_seen": iso(incident.last_seen),
        "href": f"/incidents/{incident.incident_id}",
    }


def _alerts(db: Session, condition, limit: int) -> list[dict[str, Any]]:
    rows = db.execute(
        select(Alert).where(condition).order_by(Alert.detected_at.desc()).limit(limit)
    ).scalars().all()
    return [
        {
            "type": "alert",
            "id": a.alert_id,
            "title": a.title,
            "severity": a.severity,
            "status": a.status,
            "rule_id": a.rule_id,
            "detected_at": iso(a.detected_at),
            "incident_id": a.incident.incident_id if a.incident else None,
            "href": f"/alerts?alert={a.alert_id}",
        }
        for a in rows
    ]


def _events(db: Session, condition, limit: int) -> list[dict[str, Any]]:
    rows = db.execute(
        select(Event).where(condition).order_by(Event.timestamp.desc()).limit(limit)
    ).scalars().all()
    return [
        {
            "type": "event",
            "id": e.event_id,
            "event_type": e.event_type,
            "action": e.action,
            "status": e.status,
            "host": e.host_ref,
            "user": e.user_ref,
            "source_ip": e.source_ip,
            "timestamp": iso(e.timestamp),
            "href": f"/events?event={e.event_id}",
        }
        for e in rows
    ]


def _hosts(db: Session, condition, limit: int) -> list[dict[str, Any]]:
    rows = db.execute(select(Host).where(condition).limit(limit)).scalars().all()
    return [
        {
            "type": "host",
            "id": h.host_id,
            "hostname": h.hostname,
            "os_family": h.os_family,
            "criticality": h.criticality,
            "risk_score": h.risk_score,
            "is_isolated": h.is_isolated,
            "href": f"/hosts/{h.host_id}",
        }
        for h in rows
    ]


def _users(db: Session, condition, limit: int) -> list[dict[str, Any]]:
    rows = db.execute(select(User).where(condition).limit(limit)).scalars().all()
    return [
        {
            "type": "user",
            "id": u.user_id,
            "display_name": u.display_name,
            "user_type": u.user_type,
            "is_privileged": u.is_privileged,
            "is_disabled": u.is_disabled,
            "risk_score": u.risk_score,
            "href": f"/users/{u.user_id}",
        }
        for u in rows
    ]


def _iocs(db: Session, condition, limit: int) -> list[dict[str, Any]]:
    rows = db.execute(select(IOC).where(condition).limit(limit)).scalars().all()
    return [
        {
            "type": "indicator",
            "id": i.ioc_id,
            "indicator": i.indicator,
            "ioc_type": i.ioc_type,
            "confidence": i.confidence,
            "severity": i.severity,
            "match_count": i.match_count,
            "href": f"/iocs/{i.ioc_id}",
        }
        for i in rows
    ]


def _technique(db: Session, technique_id: str) -> list[dict[str, Any]]:
    info = catalog.technique(technique_id)
    if info is None:
        return []
    from sqlalchemy import Text, cast

    alert_count = db.execute(
        select(func.count()).select_from(Alert)
        .where(cast(Alert.technique_ids, Text).ilike(json_member(technique_id), escape=LIKE_ESCAPE))
    ).scalar_one()
    return [{
        "type": "technique",
        "id": info.technique_id,
        "name": info.name,
        "tactics": [catalog.tactic_names().get(t, t) for t in info.tactic_ids],
        "alert_count": alert_count,
        "url": info.url,
        "href": f"/mitre?technique={info.technique_id}",
    }]


def _techniques_by_name(term: str) -> list[dict[str, Any]]:
    lowered = term.lower()
    matches = [
        info for info in catalog.technique_index().values()
        if lowered in info.name.lower()
    ][:MAX_PER_CATEGORY]
    return [
        {
            "type": "technique",
            "id": info.technique_id,
            "name": info.name,
            "tactics": [catalog.tactic_names().get(t, t) for t in info.tactic_ids],
            "url": info.url,
            "href": f"/mitre?technique={info.technique_id}",
        }
        for info in matches
    ]


def entity_context(db: Session, kind: str, value: str) -> dict[str, Any]:
    """Counts for an entity, used by the search result summary line."""
    from sqlalchemy import Text, cast

    key = f"{kind}:{value}"
    incidents = db.execute(
        select(func.count()).select_from(Incident)
        .where(cast(Incident.entity_keys, Text).ilike(json_member(key), escape=LIKE_ESCAPE))
    ).scalar_one()

    if kind == "host":
        alerts = db.execute(
            select(func.count()).select_from(Alert).where(Alert.host_ref == value)
        ).scalar_one()
        events = db.execute(
            select(func.count()).select_from(Event).where(Event.host_ref == value)
        ).scalar_one()
    elif kind == "user":
        alerts = db.execute(
            select(func.count()).select_from(Alert).where(Alert.user_ref == value)
        ).scalar_one()
        events = db.execute(
            select(func.count()).select_from(Event).where(Event.user_ref == value)
        ).scalar_one()
    else:
        alerts = db.execute(
            select(func.count()).select_from(Alert).where(Alert.source_ip == value)
        ).scalar_one()
        events = db.execute(
            select(func.count()).select_from(Event)
            .where(or_(Event.source_ip == value, Event.destination_ip == value))
        ).scalar_one()

    return {"entity": key, "incidents": incidents, "alerts": alerts, "events": events}
