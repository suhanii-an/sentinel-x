"""Cloud security analytics.

Cloud intrusions leave no process, no file and no host telemetry — only an audit
record of an API call.  That changes what "suspicious" means: the unit of
analysis is the *identity*, and the questions are which identities can do
damage, which ones are behaving unlike themselves, and which ones are probing
for permissions they do not have.

Everything here reads the same normalized events as the rest of the platform.
There is no separate cloud data store, no cloud credentials, and no API calls to
any provider — SENTINEL-X consumes audit records, which is exactly how a real
detection pipeline sees cloud activity.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.netutils import is_external
from app.core.timeutils import iso, utcnow
from app.models.alerts import Alert
from app.models.enums import EventStatus, Severity
from app.models.events import Event

#: Weighted factors for cloud identity risk.  Same philosophy as the incident
#: risk model: every contribution is named, weighted and explained.
IDENTITY_RISK_WEIGHTS = {
    "privilege_operations": 0.30,
    "denied_attempts": 0.20,
    "no_mfa": 0.15,
    "external_sources": 0.15,
    "defense_evasion": 0.20,
}

#: Denied calls above this count in the window read as permission probing rather
#: than a misconfigured script.
DENIED_PROBE_THRESHOLD = 3


@dataclass(slots=True)
class IdentityRisk:
    identity: str
    cloud_account: str
    score: float
    band: str
    factors: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity,
            "cloud_account": self.cloud_account,
            "risk_score": self.score,
            "risk_band": self.band,
            "factors": self.factors,
        }


def _cloud_events(db: Session, *, since: dt.datetime | None = None, account: str | None = None):
    stmt = select(Event).where(Event.cloud_account.isnot(None))
    if since is not None:
        stmt = stmt.where(Event.timestamp >= since)
    if account:
        stmt = stmt.where(Event.cloud_account == account)
    return stmt


def account_summary(db: Session, *, window_hours: int = 168) -> list[dict[str, Any]]:
    """One row per cloud account: volume, identities, and what went wrong."""
    since = utcnow() - dt.timedelta(hours=window_hours)
    events = list(db.execute(_cloud_events(db, since=since)).scalars().all())

    accounts: dict[str, dict[str, Any]] = {}
    for event in events:
        entry = accounts.setdefault(event.cloud_account, {
            "cloud_account": event.cloud_account,
            "provider": event.cloud_provider or "aws",
            "regions": set(),
            "identities": set(),
            "services": set(),
            "event_count": 0,
            "failed_count": 0,
            "privilege_operations": 0,
            "defense_evasion_operations": 0,
            "first_seen": event.timestamp,
            "last_seen": event.timestamp,
        })
        meta = event.meta or {}
        entry["event_count"] += 1
        entry["regions"].add(event.cloud_region or "unknown")
        if event.user_ref:
            entry["identities"].add(event.user_ref)
        if event.cloud_service:
            entry["services"].add(event.cloud_service)
        if event.status == EventStatus.FAILURE:
            entry["failed_count"] += 1
        if meta.get("iam_category") in {"privilege_grant", "credential_creation",
                                        "credential_modification", "trust_policy_change"}:
            entry["privilege_operations"] += 1
        if meta.get("iam_category") == "defense_evasion":
            entry["defense_evasion_operations"] += 1
        entry["first_seen"] = min(entry["first_seen"], event.timestamp)
        entry["last_seen"] = max(entry["last_seen"], event.timestamp)

    summaries = []
    for entry in accounts.values():
        summaries.append({
            **entry,
            "regions": sorted(entry["regions"]),
            "identities": sorted(entry["identities"]),
            "identity_count": len(entry["identities"]),
            "services": sorted(entry["services"]),
            "first_seen": iso(entry["first_seen"]),
            "last_seen": iso(entry["last_seen"]),
        })
    summaries.sort(key=lambda a: a["event_count"], reverse=True)
    return summaries


def risky_identities(db: Session, *, window_hours: int = 168, limit: int = 25) -> list[dict[str, Any]]:
    """Rank cloud identities by explainable risk."""
    since = utcnow() - dt.timedelta(hours=window_hours)
    events = list(db.execute(_cloud_events(db, since=since)).scalars().all())

    profiles: dict[tuple[str, str], dict[str, Any]] = {}
    for event in events:
        if not event.user_ref:
            continue
        key = (event.user_ref, event.cloud_account)
        profile = profiles.setdefault(key, {
            "identity": event.user_ref,
            "cloud_account": event.cloud_account,
            "identity_type": (event.meta or {}).get("identity_type"),
            "api_calls": 0,
            "distinct_apis": set(),
            "privilege_operations": 0,
            "defense_evasion_operations": 0,
            "denied": 0,
            "no_mfa_calls": 0,
            "source_ips": set(),
            "external_ips": set(),
            "high_risk_policies": set(),
            "services": set(),
            "first_seen": event.timestamp,
            "last_seen": event.timestamp,
        })
        meta = event.meta or {}
        profile["api_calls"] += 1
        if event.action:
            profile["distinct_apis"].add(event.action)
        if event.cloud_service:
            profile["services"].add(event.cloud_service)
        if meta.get("iam_category") in {"privilege_grant", "credential_creation",
                                        "credential_modification", "trust_policy_change"}:
            profile["privilege_operations"] += 1
        if meta.get("iam_category") == "defense_evasion":
            profile["defense_evasion_operations"] += 1
        if event.status == EventStatus.FAILURE:
            profile["denied"] += 1
        if meta.get("mfa_authenticated") is False:
            profile["no_mfa_calls"] += 1
        if meta.get("high_risk_policy") and meta.get("policy"):
            profile["high_risk_policies"].add(str(meta["policy"]))
        if event.source_ip:
            profile["source_ips"].add(event.source_ip)
            if is_external(event.source_ip):
                profile["external_ips"].add(event.source_ip)
        profile["first_seen"] = min(profile["first_seen"], event.timestamp)
        profile["last_seen"] = max(profile["last_seen"], event.timestamp)

    # Alert context per identity, so the page agrees with the alert queue.
    alert_rows = db.execute(
        select(Alert.user_ref, Alert.severity, func.count())
        .where(Alert.user_ref.isnot(None), Alert.detected_at >= since)
        .group_by(Alert.user_ref, Alert.severity)
    ).all()
    alerts_by_identity: dict[str, dict[str, int]] = {}
    for user_ref, severity, count in alert_rows:
        alerts_by_identity.setdefault(user_ref, {})[severity] = count

    results = []
    for profile in profiles.values():
        risk = _score_identity(profile)
        alert_counts = alerts_by_identity.get(profile["identity"], {})
        results.append({
            "identity": profile["identity"],
            "cloud_account": profile["cloud_account"],
            "identity_type": profile["identity_type"],
            "api_calls": profile["api_calls"],
            "distinct_apis": len(profile["distinct_apis"]),
            "privilege_operations": profile["privilege_operations"],
            "defense_evasion_operations": profile["defense_evasion_operations"],
            "denied_attempts": profile["denied"],
            "no_mfa_calls": profile["no_mfa_calls"],
            "source_ips": sorted(profile["source_ips"]),
            "external_source_ips": sorted(profile["external_ips"]),
            "high_risk_policies": sorted(profile["high_risk_policies"]),
            "services": sorted(profile["services"]),
            "first_seen": iso(profile["first_seen"]),
            "last_seen": iso(profile["last_seen"]),
            "alert_counts": alert_counts,
            **risk.to_dict(),
        })

    results.sort(key=lambda r: r["risk_score"], reverse=True)
    return results[:limit]


def _score_identity(profile: dict[str, Any]) -> IdentityRisk:
    factors: list[dict[str, Any]] = []
    total = 0.0

    def add(name: str, value: float, explanation: str) -> None:
        nonlocal total
        weight = IDENTITY_RISK_WEIGHTS[name]
        value = max(0.0, min(1.0, value))
        contribution = weight * value * 100
        total += contribution
        factors.append({
            "factor": name,
            "weight": round(weight, 2),
            "value": round(value, 3),
            "contribution": round(contribution, 2),
            "explanation": explanation,
        })

    privilege_ops = profile["privilege_operations"]
    add(
        "privilege_operations",
        min(1.0, privilege_ops / 2),
        f"{privilege_ops} operation(s) that widen permissions or create credentials."
        if privilege_ops else "No permission-widening operations observed.",
    )

    denied = profile["denied"]
    add(
        "denied_attempts",
        min(1.0, denied / DENIED_PROBE_THRESHOLD),
        f"{denied} denied API call(s) - repeated denials read as permission probing."
        if denied else "No denied API calls.",
    )

    no_mfa = profile["no_mfa_calls"]
    ratio = no_mfa / profile["api_calls"] if profile["api_calls"] else 0.0
    add(
        "no_mfa",
        ratio,
        f"{no_mfa} of {profile['api_calls']} call(s) were made without MFA."
        if no_mfa else "All observed calls were MFA-authenticated or MFA state was not reported.",
    )

    external = len(profile["external_ips"])
    add(
        "external_sources",
        min(1.0, external / 2),
        f"Activity from {external} address(es) outside private ranges: "
        f"{', '.join(sorted(profile['external_ips'])[:3])}."
        if external else "All activity originated from private address space.",
    )

    evasion = profile["defense_evasion_operations"]
    add(
        "defense_evasion",
        1.0 if evasion else 0.0,
        f"{evasion} operation(s) that disable or modify audit logging."
        if evasion else "No logging or monitoring changes observed.",
    )

    score = round(min(100.0, total), 1)
    return IdentityRisk(
        identity=profile["identity"],
        cloud_account=profile["cloud_account"],
        score=score,
        band=str(Severity.from_score(score)),
        factors=factors,
    )


def iam_changes(db: Session, *, window_hours: int = 168, limit: int = 100) -> list[dict[str, Any]]:
    """Permission-affecting operations, newest first."""
    since = utcnow() - dt.timedelta(hours=window_hours)
    events = list(
        db.execute(
            _cloud_events(db, since=since).order_by(Event.timestamp.desc()).limit(limit * 4)
        ).scalars().all()
    )

    changes = []
    for event in events:
        meta = event.meta or {}
        category = meta.get("iam_category")
        if category in (None, "authentication"):
            continue
        changes.append({
            "event_id": event.event_id,
            "timestamp": iso(event.timestamp),
            "identity": event.user_ref,
            "cloud_account": event.cloud_account,
            "api_call": event.action,
            "service": event.cloud_service,
            "region": event.cloud_region,
            "resource": event.cloud_resource,
            "category": category,
            "risk": meta.get("iam_risk"),
            "policy": meta.get("policy"),
            "high_risk_policy": bool(meta.get("high_risk_policy")),
            "target_principal": meta.get("target_principal"),
            "source_ip": event.source_ip,
            "mfa_authenticated": meta.get("mfa_authenticated"),
            "status": event.status,
            "error_code": meta.get("error_code"),
        })
        if len(changes) >= limit:
            break
    return changes


def identity_activity_graph(db: Session, identity: str, *, window_hours: int = 168) -> dict[str, Any]:
    """identity -> API call -> resource, built from audit records.

    The view the cloud page renders: it answers "what did this identity actually
    touch?" without the analyst reconstructing it from a log table.
    """
    since = utcnow() - dt.timedelta(hours=window_hours)
    events = list(
        db.execute(
            _cloud_events(db, since=since).where(Event.user_ref == identity)
            .order_by(Event.timestamp.asc())
        ).scalars().all()
    )

    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}

    def node(kind: str, value: str, **attrs: Any) -> str:
        node_id = f"{kind}:{value}"
        entry = nodes.setdefault(node_id, {
            "id": node_id, "kind": kind, "label": value, "count": 0, "attributes": {}
        })
        entry["count"] += 1
        entry["attributes"].update({k: v for k, v in attrs.items() if v is not None})
        return node_id

    def edge(source: str, target: str, relation: str, event_id: str) -> None:
        key = (source, target, relation)
        entry = edges.setdefault(key, {
            "id": f"{source}->{target}:{relation}",
            "source": source, "target": target, "relation": relation,
            "count": 0, "event_ids": [],
        })
        entry["count"] += 1
        if len(entry["event_ids"]) < 10:
            entry["event_ids"].append(event_id)

    identity_node = node("identity", identity)
    for event in events:
        meta = event.meta or {}
        if event.source_ip:
            edge(node("ip", event.source_ip), identity_node, "used by", event.event_id)
        api_node = node(
            "api_call", event.action or "unknown",
            service=event.cloud_service, risk=meta.get("iam_risk"),
            category=meta.get("iam_category"), read_only=meta.get("read_only"),
        )
        edge(identity_node, api_node, "denied" if event.status == EventStatus.FAILURE else "called",
             event.event_id)
        if event.cloud_resource:
            edge(api_node, node("resource", event.cloud_resource), "targeted", event.event_id)
        if meta.get("policy"):
            edge(api_node, node("policy", str(meta["policy"]),
                                high_risk=bool(meta.get("high_risk_policy"))),
                 "applied", event.event_id)

    return {
        "identity": identity,
        "window_hours": window_hours,
        "event_count": len(events),
        "nodes": list(nodes.values()),
        "edges": list(edges.values()),
    }


def cloud_overview(db: Session, *, window_hours: int = 168) -> dict[str, Any]:
    accounts = account_summary(db, window_hours=window_hours)
    identities = risky_identities(db, window_hours=window_hours, limit=10)
    changes = iam_changes(db, window_hours=window_hours, limit=25)
    return {
        "window_hours": window_hours,
        "account_count": len(accounts),
        "identity_count": sum(a["identity_count"] for a in accounts),
        "event_count": sum(a["event_count"] for a in accounts),
        "privilege_operations": sum(a["privilege_operations"] for a in accounts),
        "defense_evasion_operations": sum(a["defense_evasion_operations"] for a in accounts),
        "accounts": accounts,
        "risky_identities": identities,
        "recent_iam_changes": changes,
    }
