"""Correlation and incident construction.

An alert is a rule's opinion about some events.  An incident is the claim that
several of those opinions describe *one adversary doing one thing*.  Getting that
claim wrong in either direction is costly: over-merge and two intrusions become
one ticket that hides half the story; under-merge and the analyst reconstructs
the attack by hand across forty alerts.

The rule used here is deliberately simple and deliberately stated:

    Two alerts belong to the same incident when they share at least one entity
    (host, account, address or cloud account) AND their activity windows fall
    within CORRELATION_WINDOW_SECONDS of one another.

Both halves are necessary.  Entity overlap alone would merge everything that ever
touched a busy jump host; time proximity alone would merge unrelated activity
that happened to coincide.  The decision, and the numbers behind it, are stored
on the incident so the UI can show *why* the correlation was made rather than
asserting it.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.ids import next_incident_id
from app.core.logging import get_logger
from app.core.timeutils import utcnow
from app.correlation import risk as risk_model
from app.correlation.confidence import compute_confidence
from app.mitre import catalog
from app.models.alerts import Alert
from app.models.entities import Host, User
from app.models.enums import IncidentStatus, Severity
from app.models.events import Event
from app.models.incidents import Incident, IncidentEvent, IncidentTechnique
from app.models.iocs import IOCMatch

logger = get_logger("sentinelx.correlation")

#: Incident statuses that can still absorb new alerts.
ACTIVE_STATUSES = [IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED]


class _UnionFind:
    def __init__(self, size: int):
        self.parent = list(range(size))

    def find(self, a: int) -> int:
        while self.parent[a] != a:
            self.parent[a] = self.parent[self.parent[a]]
            a = self.parent[a]
        return a

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def _within_window(a: Alert, b: Alert, window: int) -> bool:
    """True when two alert activity windows are within ``window`` of each other."""
    if a.first_event_at > b.last_event_at:
        gap = (a.first_event_at - b.last_event_at).total_seconds()
    elif b.first_event_at > a.last_event_at:
        gap = (b.first_event_at - a.last_event_at).total_seconds()
    else:
        gap = 0.0  # overlapping windows
    return gap <= window


def cluster_alerts(alerts: Sequence[Alert], *, window: int) -> list[list[Alert]]:
    """Group alerts that share an entity and are close in time."""
    if not alerts:
        return []

    uf = _UnionFind(len(alerts))
    key_sets = [set(a.entity_keys or []) for a in alerts]

    for i in range(len(alerts)):
        for j in range(i + 1, len(alerts)):
            if key_sets[i] & key_sets[j] and _within_window(alerts[i], alerts[j], window):
                uf.union(i, j)

    clusters: dict[int, list[Alert]] = {}
    for index, alert in enumerate(alerts):
        clusters.setdefault(uf.find(index), []).append(alert)
    return list(clusters.values())


def _find_matching_incidents(
    db: Session,
    cluster: Sequence[Alert],
    *,
    window: int,
) -> list[Incident]:
    """Open incidents that already cover this cluster's entities and timeframe."""
    cluster_keys: set[str] = set()
    for alert in cluster:
        cluster_keys.update(alert.entity_keys or [])
    if not cluster_keys:
        return []

    earliest = min(a.first_event_at for a in cluster)
    latest = max(a.last_event_at for a in cluster)
    horizon = dt.timedelta(seconds=window)

    candidates = db.execute(
        select(Incident).where(
            Incident.status.in_(ACTIVE_STATUSES),
            Incident.last_seen >= earliest - horizon,
            Incident.first_seen <= latest + horizon,
        )
    ).scalars().all()

    return [c for c in candidates if cluster_keys & set(c.entity_keys or [])]


def correlate(
    db: Session,
    alerts: Sequence[Alert],
    *,
    simulation_run_pk: int | None = None,
    is_demo: bool = False,
    window: int | None = None,
) -> list[Incident]:
    """Fold new alerts into incidents, creating or merging as required."""
    if not alerts:
        return []

    window = window if window is not None else settings.CORRELATION_WINDOW_SECONDS
    unassigned = [a for a in alerts if a.incident_pk is None]
    if not unassigned:
        return []

    touched: dict[int, Incident] = {}

    for cluster in cluster_alerts(unassigned, window=window):
        matches = _find_matching_incidents(db, cluster, window=window)

        if matches:
            # Oldest incident wins: analysts reference incident IDs, so the
            # long-lived one should keep its identity.
            matches.sort(key=lambda i: i.first_seen)
            target = matches[0]
            absorbed = list(matches[1:])
            for other in absorbed:
                _absorb(db, target, other)
        else:
            target = Incident(
                incident_id=next_incident_id(db),
                title="Security incident",
                created_at=utcnow(),
                first_seen=min(a.first_event_at for a in cluster),
                last_seen=max(a.last_event_at for a in cluster),
                severity=str(Severity.max_of([a.severity for a in cluster])),
                status=IncidentStatus.OPEN,
                simulation_run_pk=simulation_run_pk,
                is_demo=is_demo,
            )
            db.add(target)
            db.flush()

        for alert in cluster:
            alert.incident_pk = target.id
        db.flush()
        touched[target.id] = target

    for incident in touched.values():
        refresh_incident(db, incident)

    db.flush()
    return list(touched.values())


def _absorb(db: Session, target: Incident, other: Incident) -> None:
    """Move another incident's alerts into ``target`` and retire it."""
    if target.id == other.id:
        return
    for alert in list(other.alerts):
        alert.incident_pk = target.id
    reason = dict(target.correlation_reason or {})
    merged = list(reason.get("merged_from", []))
    merged.append({
        "incident_id": other.incident_id,
        "alert_count": len(other.alerts),
        "merged_at": utcnow().isoformat(),
    })
    reason["merged_from"] = merged
    target.correlation_reason = reason
    db.flush()
    db.delete(other)
    db.flush()
    logger.info("incident_merged", extra={"into": target.incident_id, "from": other.incident_id})


def refresh_incident(db: Session, incident: Incident) -> Incident:
    """Recompute every derived field on an incident from its current alerts.

    Idempotent and total: it never patches state incrementally, it rebuilds it.
    Incremental updates to correlated state are where "the timeline shows six
    events but the header says nine" bugs come from.
    """
    alerts = db.execute(
        select(Alert).where(Alert.incident_pk == incident.id).order_by(Alert.detected_at.asc())
    ).scalars().all()

    if not alerts:
        incident.alert_count = 0
        incident.event_count = 0
        incident.summary = "No alerts remain associated with this incident."
        db.flush()
        return incident

    # ------------------------------------------------------------- evidence
    event_pks: list[int] = []
    seen_pks: set[int] = set()
    for alert in alerts:
        for link in alert.evidence_links:
            if link.event_pk not in seen_pks:
                seen_pks.add(link.event_pk)
                event_pks.append(link.event_pk)

    events: list[Event] = []
    if event_pks:
        events = list(
            db.execute(
                select(Event).where(Event.id.in_(event_pks)).order_by(Event.timestamp.asc())
            ).scalars().all()
        )

    _rebuild_event_links(db, incident, events)

    # ------------------------------------------------------------- entities
    hosts = sorted({e.host_ref for e in events if e.host_ref})
    all_users = {e.user_ref for e in events if e.user_ref}
    # An account seen only on failures was attacked, not compromised.
    succeeded = {e.user_ref for e in events if e.user_ref and e.status != "failure"}
    users = sorted(succeeded)
    targeted_users = sorted(all_users - succeeded)
    source_ips = sorted({e.source_ip for e in events if e.source_ip})
    destination_ips = sorted({e.destination_ip for e in events if e.destination_ip})
    cloud_accounts = sorted({e.cloud_account for e in events if e.cloud_account})

    # Entity keys include targeted accounts: correlation should still link a
    # later event involving an account that was merely attempted earlier.
    #
    # The contributing alerts' own keys are unioned in rather than relying
    # solely on the evidence events. Those keys are what clustering matched on,
    # so an incident that did not carry them could not be matched by the very
    # next alert about the same entity — and any detector that produces an
    # alert with thinner evidence than its entity set would silently open a
    # fresh incident every time instead of extending the existing one.
    derived_keys = (
        [f"host:{h}" for h in hosts]
        + [f"user:{u}" for u in sorted(all_users)]
        + [f"ip:{ip}" for ip in source_ips + destination_ips]
        + [f"cloud:{c}" for c in cloud_accounts]
    )
    alert_keys = {key for a in alerts for key in (a.entity_keys or [])}
    entity_keys = sorted(set(derived_keys) | alert_keys)

    # ----------------------------------------------------------- techniques
    technique_ids = sorted({t for a in alerts for t in (a.technique_ids or [])})
    _rebuild_techniques(db, incident, alerts, events)
    tactics = catalog.tactics_for(technique_ids)

    # -------------------------------------------------------------- scoring
    ioc_rows: list[IOCMatch] = []
    if event_pks:
        ioc_rows = list(
            db.execute(select(IOCMatch).where(IOCMatch.event_pk.in_(event_pks))).scalars().all()
        )

    confidence = compute_confidence(
        alert_confidences=[a.confidence for a in alerts],
        event_count=len(events),
        entity_key_sets=[a.entity_keys or [] for a in alerts],
        alert_times=[a.detected_at for a in alerts],
        distinct_tactics=len(tactics),
        ioc_match_count=len(ioc_rows),
    )

    base_severity = Severity.max_of([a.severity for a in alerts])
    host_rows = (
        db.execute(select(Host).where(Host.host_id.in_(hosts))).scalars().all() if hosts else []
    )
    user_rows = (
        db.execute(select(User).where(User.user_id.in_(users))).scalars().all() if users else []
    )
    anomaly_scores = [
        float(item.get("value", 0.0))
        for a in alerts
        for item in (a.risk_breakdown or [])
        if item.get("factor") == "behavioural"
    ]

    scored = risk_model.score_incident(
        severity=str(base_severity),
        confidence=confidence.value,
        asset_criticalities=[h.criticality for h in host_rows],
        privileged_user=any(u.is_privileged for u in user_rows),
        behavioural_flags=risk_model.collect_behavioural_flags(events),
        anomaly_score=max(anomaly_scores) if anomaly_scores else None,
        ioc_count=len(ioc_rows),
        ioc_confidence=max((m.ioc.confidence for m in ioc_rows), default=0.0),
        event_count=len(events),
        alert_count=len(alerts),
        distinct_tactics=len(tactics),
    )

    # Severity is the stronger of "the worst thing that fired" and "what the
    # risk model concluded".  Stated explicitly because it is a judgement call.
    final_severity = Severity.max_of([str(base_severity), str(Severity.from_score(scored.score))])

    # ----------------------------------------------------------- narrative
    attack_chain = _build_attack_chain(db, incident, tactics)

    incident.first_seen = min(a.first_event_at for a in alerts)
    incident.last_seen = max(a.last_event_at for a in alerts)
    incident.severity = str(final_severity)
    incident.confidence = confidence.value
    incident.confidence_breakdown = confidence.breakdown()
    incident.risk_score = scored.score
    incident.risk_breakdown = scored.breakdown()
    incident.affected_hosts = hosts
    incident.affected_users = users
    incident.targeted_users = targeted_users
    incident.source_ips = source_ips
    incident.destination_ips = destination_ips
    incident.technique_ids = technique_ids
    incident.entity_keys = entity_keys
    incident.alert_count = len(alerts)
    incident.event_count = len(events)
    incident.attack_chain = attack_chain
    incident.ioc_matches = [
        {
            "ioc_id": m.ioc.ioc_id,
            "indicator": m.ioc.indicator,
            "ioc_type": m.ioc.ioc_type,
            "matched_field": m.matched_field,
            "confidence": m.ioc.confidence,
        }
        for m in ioc_rows
    ]
    incident.correlation_reason = _build_correlation_reason(
        incident, alerts, events, confidence.value, entity_keys
    )
    incident.title = _build_title(attack_chain, hosts, users, cloud_accounts)
    incident.summary = _build_summary(incident, alerts, events, attack_chain)
    incident.updated_at = utcnow()

    db.flush()
    return incident


def _rebuild_event_links(db: Session, incident: Incident, events: Sequence[Event]) -> None:
    existing = {
        link.event_pk: link
        for link in db.execute(
            select(IncidentEvent).where(IncidentEvent.incident_pk == incident.id)
        ).scalars().all()
    }
    wanted = {e.id for e in events}
    for pk, link in existing.items():
        if pk not in wanted:
            db.delete(link)
    for event in events:
        if event.id not in existing:
            db.add(IncidentEvent(incident_pk=incident.id, event_pk=event.id, role="evidence"))
    db.flush()


def _rebuild_techniques(
    db: Session,
    incident: Incident,
    alerts: Sequence[Alert],
    events: Sequence[Event],
) -> None:
    """Rebuild technique mappings, each carrying the evidence that supports it."""
    index = catalog.technique_index()
    event_by_pk = {e.id: e for e in events}

    aggregated: dict[str, dict] = {}
    for alert in alerts:
        alert_events = [
            event_by_pk[link.event_pk]
            for link in alert.evidence_links
            if link.event_pk in event_by_pk
        ]
        if not alert_events:
            continue
        for technique_id in alert.technique_ids or []:
            entry = aggregated.setdefault(
                technique_id,
                {
                    "confidences": [],
                    "event_ids": [],
                    "rules": set(),
                    "first": alert_events[0].timestamp,
                    "last": alert_events[-1].timestamp,
                    "detected_at": alert.detected_at,
                },
            )
            entry["confidences"].append(alert.confidence)
            entry["rules"].add(alert.rule_id)
            entry["detected_at"] = min(entry["detected_at"], alert.detected_at)
            for event in alert_events:
                if event.event_id not in entry["event_ids"]:
                    entry["event_ids"].append(event.event_id)
                entry["first"] = min(entry["first"], event.timestamp)
                entry["last"] = max(entry["last"], event.timestamp)

    existing = {
        row.technique_id: row
        for row in db.execute(
            select(IncidentTechnique).where(IncidentTechnique.incident_pk == incident.id)
        ).scalars().all()
    }
    for technique_id, row in existing.items():
        if technique_id not in aggregated:
            db.delete(row)

    order = catalog.tactic_order()
    for technique_id, entry in aggregated.items():
        info = index.get(technique_id)
        primary_tactic = None
        if info and info.tactic_ids:
            primary_tactic = sorted(info.tactic_ids, key=lambda t: order.get(t, 99))[0]

        row = existing.get(technique_id) or IncidentTechnique(
            incident_pk=incident.id, technique_id=technique_id
        )
        row.tactic_id = primary_tactic
        row.confidence = round(max(entry["confidences"]), 3)
        row.first_observed = entry["first"]
        row.last_observed = entry["last"]
        row.detected_at = entry["detected_at"]
        # Cap the stored evidence list: the full set is reachable via the
        # incident's events, and an unbounded JSON column is a liability.
        row.evidence_event_ids = entry["event_ids"][:50]
        row.source_rule_ids = sorted(entry["rules"])
        db.add(row)
    db.flush()


def _build_attack_chain(db: Session, incident: Incident, tactics: Sequence[str]) -> list[dict]:
    """Ordered tactic-level reconstruction, each stage timestamped from evidence."""
    rows = db.execute(
        select(IncidentTechnique).where(IncidentTechnique.incident_pk == incident.id)
    ).scalars().all()
    names = catalog.tactic_names()
    order = catalog.tactic_order()

    stages: dict[str, dict] = {}
    for row in rows:
        if not row.tactic_id:
            continue
        stage = stages.setdefault(
            row.tactic_id,
            {
                "tactic_id": row.tactic_id,
                "tactic": names.get(row.tactic_id, row.tactic_id),
                "order": order.get(row.tactic_id, 99),
                "techniques": [],
                "first_seen": row.first_observed,
                "last_seen": row.last_observed,
                "detected_at": row.detected_at,
                "evidence_event_ids": [],
                "confidence": row.confidence,
            },
        )
        stage["techniques"].append({
            "technique_id": row.technique_id,
            "name": catalog.technique_name(row.technique_id),
            "confidence": row.confidence,
        })
        stage["first_seen"] = min(stage["first_seen"], row.first_observed)
        stage["last_seen"] = max(stage["last_seen"], row.last_observed)
        stage["detected_at"] = min(stage["detected_at"], row.detected_at)
        stage["confidence"] = max(stage["confidence"], row.confidence)
        for event_id in row.evidence_event_ids or []:
            if event_id not in stage["evidence_event_ids"]:
                stage["evidence_event_ids"].append(event_id)

    # Ordered by when each tactic became *detectable*, not by its position in the
    # ATT&CK matrix.  Real intrusions do not walk the matrix left to right — this
    # one performed discovery before establishing persistence — and a timeline
    # that reorders reality to match a framework is a diagram, not evidence.
    #
    # detected_at rather than first_seen, because a sequence rule's evidence
    # reaches back to the session that started the chain: ordering lateral
    # movement by its earliest evidence event would place it before the
    # escalation that enabled it.  Each stage still carries both timestamps and
    # its kill-chain position, so the UI can offer the conventional view too.
    chain = sorted(stages.values(), key=lambda s: (s["detected_at"], s["order"]))
    for stage in chain:
        stage["first_seen"] = stage["first_seen"].isoformat()
        stage["last_seen"] = stage["last_seen"].isoformat()
        stage["detected_at"] = stage["detected_at"].isoformat()
        stage["evidence_event_ids"] = stage["evidence_event_ids"][:25]
    return chain


def _build_correlation_reason(
    incident: Incident,
    alerts: Sequence[Alert],
    events: Sequence[Event],
    confidence: float,
    entity_keys: Sequence[str],
) -> dict:
    """The structured answer to "why was this incident created?".

    The UI renders this verbatim.  Nothing in the panel is generated at display
    time, so the interface cannot claim more than the data supports.
    """
    by_type: dict[str, int] = {}
    for event in events:
        by_type[event.event_type] = by_type.get(event.event_type, 0) + 1

    shared: dict[str, int] = {}
    for alert in alerts:
        for key in set(alert.entity_keys or []):
            shared[key] = shared.get(key, 0) + 1
    linking = sorted(
        [{"entity": k, "alert_count": v} for k, v in shared.items() if v > 1],
        key=lambda item: item["alert_count"],
        reverse=True,
    )[:10]

    previous = dict(incident.correlation_reason or {})
    reason = {
        "method": "shared-entity temporal correlation",
        "window_seconds": settings.CORRELATION_WINDOW_SECONDS,
        "alert_count": len(alerts),
        "event_count": len(events),
        "events_by_type": dict(sorted(by_type.items(), key=lambda kv: kv[1], reverse=True)),
        "linking_entities": linking,
        "contributing_rules": sorted({a.rule_id for a in alerts}),
        "confidence": confidence,
        "duration_seconds": incident.duration_seconds,
    }
    if previous.get("merged_from"):
        reason["merged_from"] = previous["merged_from"]
    return reason


def _build_title(
    attack_chain: Sequence[dict],
    hosts: Sequence[str],
    users: Sequence[str],
    cloud_accounts: Sequence[str],
) -> str:
    stages = " -> ".join(stage["tactic"] for stage in attack_chain) or "Suspicious activity"
    if hosts:
        target = hosts[0] if len(hosts) == 1 else f"{len(hosts)} hosts"
    elif cloud_accounts:
        target = f"cloud account {cloud_accounts[0]}"
    else:
        target = "the environment"
    actor = f" involving {users[0]}" if len(users) == 1 else (f" involving {len(users)} accounts" if users else "")
    return f"{stages} on {target}{actor}"[:255]


def _build_summary(
    incident: Incident,
    alerts: Sequence[Alert],
    events: Sequence[Event],
    attack_chain: Sequence[dict],
) -> str:
    """A deterministic, factual summary.

    Written by template from stored values, not by a language model.  The AI
    assistant can produce a richer narrative on request, but an incident must
    have a trustworthy description even when no AI provider is configured.
    """
    stages = ", then ".join(stage["tactic"].lower() for stage in attack_chain)
    duration = incident.duration_seconds
    duration_text = f"{duration}s" if duration < 120 else f"{duration // 60}m {duration % 60}s"
    hosts = ", ".join(incident.affected_hosts[:3]) or "no host"
    users = ", ".join(incident.affected_users[:3]) or "no account"
    sources = ", ".join(incident.source_ips[:3]) or "no recorded source address"

    parts = [
        f"{len(alerts)} detection(s) correlated into one incident from {len(events)} security event(s) "
        f"over {duration_text}.",
    ]
    if stages:
        parts.append(f"Observed activity progressed through {stages}.")
    parts.append(f"Affected assets: {hosts}. Accounts involved: {users}. Source: {sources}.")
    parts.append(
        f"Correlation confidence {incident.confidence:.0%}; risk score {incident.risk_score:.0f}/100 "
        f"({incident.severity})."
    )
    return " ".join(parts)
