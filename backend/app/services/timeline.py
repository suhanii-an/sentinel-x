"""Event timelines.

Two distinct views, and conflating them is a common mistake:

*The event timeline* is every piece of evidence in chronological order —
the ground truth of what the telemetry recorded.

*The attack chain* (built in the correlation engine) is the tactic-level
reconstruction — an interpretation layered on top of that evidence.

The investigation UI shows both, labelled, so an analyst can always drop from the
interpretation back to the records that produced it.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.timeutils import iso
from app.models.alerts import Alert, AlertEvent
from app.models.events import Event
from app.models.incidents import Incident
from app.models.iocs import IOCMatch

#: Metadata keys worth surfacing directly on a timeline entry.
HIGHLIGHT_KEYS = (
    "auth_method", "failure_reason", "logon_type_name", "discovery_category",
    "persistence_mechanism", "iam_category", "iam_risk", "policy", "group",
    "target_user", "service", "argument_indicators", "uid_zero",
    "privileged_group", "high_risk_policy", "invalid_user",
)


def _summarize(event: Event) -> str:
    """One analyst-readable line describing an event."""
    meta = event.meta or {}
    who = event.user_ref or "unknown account"
    where = event.host_ref or event.cloud_account or "unknown system"

    if event.event_type == "authentication":
        verb = {"success": "authenticated successfully", "failure": "failed authentication"}.get(
            event.status, event.action or "authentication event"
        )
        source = f" from {event.source_ip}" if event.source_ip else ""
        reason = f" ({meta['failure_reason']})" if meta.get("failure_reason") else ""
        return f"{who} {verb} on {where}{source}{reason}"

    if event.event_type in ("process", "discovery"):
        command = event.command_line or event.process_name or "process"
        return f"{who} executed `{command}` on {where}"

    if event.event_type == "privilege":
        target = meta.get("target_user") or meta.get("target_principal")
        if event.cloud_account:
            return f"{who} performed {event.action} in cloud account {event.cloud_account}"
        return f"{who} elevated privileges on {where}" + (f" to {target}" if target else "")

    if event.event_type == "file":
        mechanism = meta.get("persistence_mechanism")
        suffix = f" ({mechanism} persistence)" if mechanism else ""
        return f"{who} {event.action or 'modified'} {event.file_path} on {where}{suffix}"

    if event.event_type == "network":
        return (
            f"{where} connected to {event.destination_ip}:{event.destination_port or '?'} "
            f"({event.protocol or 'tcp'}, {event.bytes_out or 0} bytes out)"
        )

    if event.event_type == "account":
        return f"Account change on {where}: {event.action} ({who})"

    if event.event_type in ("cloud_audit", "service", "scheduled_task"):
        return f"{who} performed {event.action} on {where}"

    return f"{event.event_type} / {event.action or 'event'} on {where}"


def _highlights(event: Event) -> dict[str, Any]:
    meta = event.meta or {}
    return {k: meta[k] for k in HIGHLIGHT_KEYS if k in meta and meta[k] not in (None, "", [])}


def build_incident_timeline(db: Session, incident: Incident) -> list[dict[str, Any]]:
    """Chronological evidence for an incident, annotated with detections."""
    alerts = list(incident.alerts)
    links = []
    if alerts:
        links = list(
            db.execute(
                select(AlertEvent).where(AlertEvent.alert_pk.in_([a.id for a in alerts]))
            ).scalars().all()
        )

    alert_by_pk = {a.id: a for a in alerts}
    alerts_by_event: dict[int, list[tuple[Alert, str | None]]] = {}
    for link in links:
        alert = alert_by_pk.get(link.alert_pk)
        if alert:
            alerts_by_event.setdefault(link.event_pk, []).append((alert, link.step))

    event_pks = sorted(alerts_by_event.keys())
    if not event_pks:
        return []

    events = list(
        db.execute(
            select(Event).where(Event.id.in_(event_pks)).order_by(Event.timestamp.asc())
        ).scalars().all()
    )

    ioc_by_event: dict[int, list[IOCMatch]] = {}
    for match in db.execute(
        select(IOCMatch).where(IOCMatch.event_pk.in_(event_pks))
    ).scalars().all():
        ioc_by_event.setdefault(match.event_pk, []).append(match)

    entries: list[dict[str, Any]] = []
    for event in events:
        related = alerts_by_event.get(event.id, [])
        entries.append({
            "event_id": event.event_id,
            "timestamp": iso(event.timestamp),
            "event_type": event.event_type,
            "source": event.source,
            "action": event.action,
            "status": event.status,
            "host": event.host_ref,
            "user": event.user_ref,
            "source_ip": event.source_ip,
            "destination_ip": event.destination_ip,
            "process": event.process_name,
            "command_line": event.command_line,
            "file_path": event.file_path,
            "cloud_account": event.cloud_account,
            "summary": _summarize(event),
            "highlights": _highlights(event),
            "alerts": [
                {
                    "alert_id": alert.alert_id,
                    "rule_id": alert.rule_id,
                    "severity": alert.severity,
                    "step": step,
                    "technique_ids": alert.technique_ids,
                }
                for alert, step in related
            ],
            "severity": _peak_severity([a for a, _ in related]),
            "ioc_matches": [
                {"ioc_id": m.ioc.ioc_id, "indicator": m.ioc.indicator, "field": m.matched_field}
                for m in ioc_by_event.get(event.id, [])
            ],
        })
    return entries


def _peak_severity(alerts: list[Alert]) -> str:
    from app.models.enums import Severity

    return str(Severity.max_of([a.severity for a in alerts])) if alerts else "info"


def build_live_timeline(
    db: Session,
    *,
    limit: int = 60,
    since: dt.datetime | None = None,
    host: str | None = None,
    user: str | None = None,
) -> list[dict[str, Any]]:
    """Recent estate-wide activity for the dashboard timeline."""
    stmt = select(Event).order_by(Event.timestamp.desc()).limit(min(limit, 250))
    if since is not None:
        stmt = stmt.where(Event.timestamp >= since)
    if host:
        stmt = stmt.where(Event.host_ref == host)
    if user:
        stmt = stmt.where(Event.user_ref == user)

    events = list(db.execute(stmt).scalars().all())
    if not events:
        return []

    event_pks = [e.id for e in events]
    alerts_by_event: dict[int, list[Alert]] = {}
    links = db.execute(select(AlertEvent).where(AlertEvent.event_pk.in_(event_pks))).scalars().all()
    if links:
        alert_rows = db.execute(
            select(Alert).where(Alert.id.in_({link.alert_pk for link in links}))
        ).scalars().all()
        alert_by_pk = {a.id: a for a in alert_rows}
        for link in links:
            alert = alert_by_pk.get(link.alert_pk)
            if alert:
                alerts_by_event.setdefault(link.event_pk, []).append(alert)

    entries = []
    for event in events:
        related = alerts_by_event.get(event.id, [])
        entries.append({
            "event_id": event.event_id,
            "timestamp": iso(event.timestamp),
            "event_type": event.event_type,
            "status": event.status,
            "host": event.host_ref,
            "user": event.user_ref,
            "source_ip": event.source_ip,
            "summary": _summarize(event),
            "severity": _peak_severity(related),
            "alert_count": len(related),
            "alert_ids": [a.alert_id for a in related],
            "incident_ids": sorted({
                a.incident.incident_id for a in related if a.incident is not None
            }),
        })
    return entries
