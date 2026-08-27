"""Evidence bundles: everything the model is allowed to know.

The bundle is also the *allow-list*.  The set of identifiers it contains is
exactly the set the model may cite, and :mod:`app.ai.guard` enforces that after
the fact.  So the question "could the AI invent an event ID?" has a structural
answer rather than a hopeful one: it can emit whatever it likes, and anything
outside this bundle is removed before an analyst sees it.

Bundles are also budgeted.  An incident with 4,000 events cannot be sent whole,
so selection is explicit and biased toward the events that caused detections
rather than truncating arbitrarily and quietly losing the interesting half.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.timeutils import iso
from app.mitre import catalog
from app.models.alerts import AlertEvent
from app.models.entities import Host, User
from app.models.events import Event
from app.models.incidents import Incident
from app.models.iocs import IOCMatch
from app.models.operations import ResponseAction

#: Metadata keys carried into the bundle. The full metadata document is not sent:
#: it is unbounded, and most of it is not decision-relevant.
BUNDLE_METADATA_KEYS = (
    "auth_method", "failure_reason", "logon_type_name", "invalid_user",
    "discovery_category", "argument_indicators", "elevated", "target_user",
    "privileged_group", "group", "uid_zero", "persistence_mechanism",
    "iam_category", "iam_risk", "policy", "high_risk_policy", "mfa_authenticated",
    "internal_lateral_candidate", "service", "setuid", "sensitive_file",
    "windows_event_id", "privileges", "error_code",
)


def _event_payload(event: Event) -> dict[str, Any]:
    meta = event.meta or {}
    payload = {
        "id": event.event_id,
        "timestamp": iso(event.timestamp),
        "type": event.event_type,
        "source": event.source,
        "action": event.action,
        "status": event.status,
        "host": event.host_ref,
        "user": event.user_ref,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "destination_port": event.destination_port,
        "process": event.process_name,
        "command_line": event.command_line,
        "file_path": event.file_path,
        "cloud_account": event.cloud_account,
        "cloud_service": event.cloud_service,
        "bytes_out": event.bytes_out,
        "metadata": {k: meta[k] for k in BUNDLE_METADATA_KEYS if k in meta},
    }
    return {k: v for k, v in payload.items() if v not in (None, "", {}, [])}


def _select_events(
    events: list[Event],
    trigger_pks: set[int],
    limit: int,
) -> tuple[list[Event], int]:
    """Choose which events to include when the incident exceeds the budget.

    Trigger events first (they are why the alerts exist), then context events
    sampled evenly across the incident's timeline so the narrative keeps its
    shape rather than stopping halfway through.
    """
    if len(events) <= limit:
        return events, 0

    triggers = [e for e in events if e.id in trigger_pks]
    context = [e for e in events if e.id not in trigger_pks]

    selected = triggers[:limit]
    remaining = limit - len(selected)
    if remaining > 0 and context:
        step = max(1, len(context) // remaining)
        selected.extend(context[::step][:remaining])

    selected.sort(key=lambda e: e.timestamp)
    return selected, len(events) - len(selected)


def build_incident_bundle(
    db: Session,
    incident: Incident,
    *,
    max_events: int | None = None,
) -> dict[str, Any]:
    """Assemble the evidence context for an incident."""
    max_events = max_events or settings.AI_MAX_EVIDENCE_EVENTS
    alerts = list(incident.alerts)

    links = []
    if alerts:
        links = list(
            db.execute(
                select(AlertEvent).where(AlertEvent.alert_pk.in_([a.id for a in alerts]))
            ).scalars().all()
        )
    trigger_pks = {link.event_pk for link in links if link.role == "trigger"}
    event_pks = sorted({link.event_pk for link in links})

    events: list[Event] = []
    if event_pks:
        events = list(
            db.execute(
                select(Event).where(Event.id.in_(event_pks)).order_by(Event.timestamp.asc())
            ).scalars().all()
        )
    selected, omitted = _select_events(events, trigger_pks, max_events)

    alert_event_ids: dict[int, list[str]] = {}
    event_id_by_pk = {e.id: e.event_id for e in events}
    for link in links:
        public = event_id_by_pk.get(link.event_pk)
        if public:
            alert_event_ids.setdefault(link.alert_pk, []).append(public)

    hosts = (
        db.execute(select(Host).where(Host.host_id.in_(incident.affected_hosts))).scalars().all()
        if incident.affected_hosts else []
    )
    users = (
        db.execute(select(User).where(User.user_id.in_(incident.affected_users))).scalars().all()
        if incident.affected_users else []
    )
    ioc_rows = (
        db.execute(select(IOCMatch).where(IOCMatch.event_pk.in_(event_pks))).scalars().all()
        if event_pks else []
    )
    actions = db.execute(
        select(ResponseAction).where(ResponseAction.incident_pk == incident.id)
        .order_by(ResponseAction.created_at.asc())
    ).scalars().all()

    bundle: dict[str, Any] = {
        "incident": {
            "id": incident.incident_id,
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status,
            "correlation_confidence": incident.confidence,
            "risk_score": incident.risk_score,
            "first_seen": iso(incident.first_seen),
            "last_seen": iso(incident.last_seen),
            "duration_seconds": incident.duration_seconds,
            "alert_count": incident.alert_count,
            "event_count": incident.event_count,
            "affected_hosts": incident.affected_hosts,
            "accounts_with_successful_activity": incident.affected_users,
            "accounts_targeted_but_not_compromised": incident.targeted_users,
            "source_ips": incident.source_ips,
            "destination_ips": incident.destination_ips,
            "deterministic_summary": incident.summary,
        },
        "why_this_incident_exists": incident.correlation_reason,
        "risk_score_breakdown": incident.risk_breakdown,
        "correlation_confidence_breakdown": incident.confidence_breakdown,
        "attack_chain": incident.attack_chain,
        "alerts": [
            {
                "id": alert.alert_id,
                "rule_id": alert.rule_id,
                "rule_name": alert.rule_name,
                "rule_type": alert.rule_type,
                "severity": alert.severity,
                "detection_confidence": alert.confidence,
                "risk_score": alert.risk_score,
                "status": alert.status,
                "detected_at": iso(alert.detected_at),
                "detection_latency_seconds": round(alert.detection_latency_ms / 1000, 1),
                "why_it_fired": alert.explanation,
                "mitre_techniques": alert.technique_ids,
                "evidence_event_ids": alert_event_ids.get(alert.id, []),
            }
            for alert in sorted(alerts, key=lambda a: a.detected_at)
        ],
        "mitre_techniques": [
            {
                "technique_id": technique.technique_id,
                "name": catalog.technique_name(technique.technique_id),
                "tactic_id": technique.tactic_id,
                "confidence": technique.confidence,
                "first_observed": iso(technique.first_observed),
                "evidence_event_ids": technique.evidence_event_ids,
                "detected_by_rules": technique.source_rule_ids,
            }
            for technique in incident.techniques
        ],
        "assets": [
            {
                "host_id": host.host_id,
                "hostname": host.hostname,
                "os": f"{host.os_family} {host.os_version or ''}".strip(),
                "criticality": host.criticality,
                "environment": host.environment,
                "tags": host.tags,
                "currently_isolated_simulated": host.is_isolated,
            }
            for host in hosts
        ],
        "accounts": [
            {
                "user_id": user.user_id,
                "display_name": user.display_name,
                "type": user.user_type,
                "privileged": user.is_privileged,
                "department": user.department,
                "currently_disabled_simulated": user.is_disabled,
            }
            for user in users
        ],
        "indicator_matches": [
            {
                "ioc_id": match.ioc.ioc_id,
                "indicator": match.ioc.indicator,
                "type": match.ioc.ioc_type,
                "source": match.ioc.source,
                "feed_confidence": match.ioc.confidence,
                "matched_field": match.matched_field,
            }
            for match in ioc_rows
        ],
        "response_actions_taken": [
            {
                "action_id": action.action_id,
                "type": action.action_type,
                "target": action.target,
                "status": action.status,
                "simulated": action.is_simulated,
                "at": iso(action.created_at),
            }
            for action in actions
        ],
        "events": [_event_payload(event) for event in selected],
        "events_omitted_for_context_budget": omitted,
    }

    return bundle


def allowed_identifiers(bundle: dict[str, Any]) -> tuple[set[str], set[str]]:
    """The exact identifiers a response may cite, derived from the bundle."""
    evidence_ids: set[str] = {str(bundle["incident"]["id"])}
    for alert in bundle.get("alerts", []):
        evidence_ids.add(str(alert["id"]))
        evidence_ids.update(str(e) for e in alert.get("evidence_event_ids", []))
    for event in bundle.get("events", []):
        evidence_ids.add(str(event["id"]))
    for match in bundle.get("indicator_matches", []):
        evidence_ids.add(str(match["ioc_id"]))

    techniques = {str(t["technique_id"]) for t in bundle.get("mitre_techniques", [])}
    for alert in bundle.get("alerts", []):
        techniques.update(str(t) for t in alert.get("mitre_techniques", []))

    return evidence_ids, techniques
