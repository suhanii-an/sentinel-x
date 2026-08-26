"""Dashboard metrics.

Every figure on the dashboard is computed here from stored records. Nothing is
hard-coded, and where a figure cannot be computed the API returns ``null`` with a
reason rather than a plausible-looking placeholder — an invented 96% detection
rate is worse than an empty tile, because the empty tile is honest.

Two figures deserve their definitions stated, since both are routinely quoted
without one:

*MTTD* is the median event-time gap between the first event of an attack and the
alert that detected it. It measures the detection logic, not the platform's
throughput, and is stable when telemetry is replayed.

*Detection rate* is the recall from the most recent evaluation run against the
labelled dataset. It is not a live measurement and never can be — computing
recall requires ground truth, and live telemetry has none. The API labels it with
the run it came from.
"""

from __future__ import annotations

import datetime as dt
import statistics
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.core.timeutils import iso, utcnow
from app.mitre import catalog
from app.models.alerts import Alert
from app.models.entities import Host, User
from app.models.enums import AlertStatus, IncidentStatus, Severity
from app.models.events import Event
from app.models.incidents import Incident
from app.models.platform import EvaluationRun

logger = get_logger("sentinelx.stats")

OPEN_ALERT_STATUSES = [AlertStatus.NEW, AlertStatus.INVESTIGATING, AlertStatus.ESCALATED]
ACTIVE_INCIDENT_STATUSES = [IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED]


def _median(values: list[float]) -> float | None:
    return round(statistics.median(values), 2) if values else None


def kpis(db: Session, *, window_hours: int = 24) -> dict[str, Any]:
    since = utcnow() - dt.timedelta(hours=window_hours)

    active_incidents = db.execute(
        select(func.count()).select_from(Incident)
        .where(Incident.status.in_(ACTIVE_INCIDENT_STATUSES))
    ).scalar_one()

    critical_incidents = db.execute(
        select(func.count()).select_from(Incident)
        .where(Incident.status.in_(ACTIVE_INCIDENT_STATUSES),
               Incident.severity == Severity.CRITICAL)
    ).scalar_one()

    critical_alerts = db.execute(
        select(func.count()).select_from(Alert)
        .where(Alert.status.in_(OPEN_ALERT_STATUSES),
               Alert.severity.in_([Severity.CRITICAL, Severity.HIGH]))
    ).scalar_one()

    open_alerts = db.execute(
        select(func.count()).select_from(Alert).where(Alert.status.in_(OPEN_ALERT_STATUSES))
    ).scalar_one()

    # A host is "at risk" if it appears in an active incident or carries an open
    # high/critical alert. Defined here rather than implied by a number.
    hosts_in_incidents: set[str] = set()
    for incident in db.execute(
        select(Incident).where(Incident.status.in_(ACTIVE_INCIDENT_STATUSES))
    ).scalars().all():
        hosts_in_incidents.update(incident.affected_hosts or [])

    hosts_with_alerts = {
        row[0] for row in db.execute(
            select(Alert.host_ref).where(
                Alert.host_ref.isnot(None),
                Alert.status.in_(OPEN_ALERT_STATUSES),
                Alert.severity.in_([Severity.CRITICAL, Severity.HIGH]),
            ).distinct()
        ).all()
    }
    hosts_at_risk = sorted(hosts_in_incidents | hosts_with_alerts)

    isolated_hosts = db.execute(
        select(func.count()).select_from(Host).where(Host.is_isolated.is_(True))
    ).scalar_one()
    disabled_accounts = db.execute(
        select(func.count()).select_from(User).where(User.is_disabled.is_(True))
    ).scalar_one()

    events_window = db.execute(
        select(func.count()).select_from(Event).where(Event.ingested_at >= since)
    ).scalar_one()

    # MTTD is measured per *incident*, not per alert.
    #
    # Medianing alert latency answers the wrong question: most alerts come from
    # single-event match rules whose latency is zero by construction, so the
    # median collapses to 0 and the figure stops meaning anything. What an
    # analyst actually wants is "how far into the attack were we before anything
    # fired", which is incident first_seen -> first alert.
    incident_latencies: list[float] = []
    for incident in db.execute(
        select(Incident).where(Incident.created_at >= since)
    ).scalars().all():
        alert_times = [a.detected_at for a in incident.alerts]
        if not alert_times:
            continue
        incident_latencies.append(
            max(0.0, (min(alert_times) - incident.first_seen).total_seconds())
        )
    mttd_seconds = _median(incident_latencies)

    # MTTR: measured only on incidents that actually received a containment action.
    response_times = [
        float(row[0])
        for row in db.execute(
            select(Incident.mttr_seconds).where(Incident.mttr_seconds.isnot(None))
        ).all()
    ]
    mttr_seconds = _median(response_times)

    evaluation = db.execute(
        select(EvaluationRun).where(EvaluationRun.status == "completed")
        .order_by(EvaluationRun.started_at.desc()).limit(1)
    ).scalars().first()

    detection_rate: dict[str, Any] = {
        "value": None,
        "measured": False,
        "explanation": (
            "No evaluation run has been completed. Detection rate requires labelled "
            "ground truth and cannot be computed from live telemetry. Run an evaluation "
            "from the Evaluation page to populate this figure."
        ),
    }
    if evaluation is not None:
        detection_rate = {
            "value": round(evaluation.recall * 100, 1),
            "measured": True,
            "precision": round(evaluation.precision * 100, 1),
            "f1": round(evaluation.f1 * 100, 1),
            "eval_id": evaluation.eval_id,
            "measured_at": iso(evaluation.started_at),
            "dataset_size": evaluation.dataset_size,
            "explanation": (
                f"Event-level recall measured against the labelled dataset "
                f"({evaluation.dataset_size} events, seed {evaluation.dataset_seed}) "
                f"in evaluation run {evaluation.eval_id}."
            ),
        }

    return {
        "window_hours": window_hours,
        "active_incidents": active_incidents,
        "critical_incidents": critical_incidents,
        "critical_alerts": critical_alerts,
        "open_alerts": open_alerts,
        "hosts_at_risk": len(hosts_at_risk),
        "hosts_at_risk_list": hosts_at_risk[:25],
        "isolated_hosts": isolated_hosts,
        "disabled_accounts": disabled_accounts,
        "events_ingested_window": events_window,
        "mttd": {
            "seconds": mttd_seconds,
            "sample_size": len(incident_latencies),
            "definition": (
                "Median event-time gap between an incident's first observed event and its "
                "first alert — how far into an attack the platform was before anything "
                "fired. Measured per incident rather than per alert, because most alerts "
                "come from single-event rules whose latency is zero by construction."
            ),
        },
        "mttr": {
            "seconds": mttr_seconds,
            "sample_size": len(response_times),
            "definition": (
                "Median time from first alert to first containment action, across "
                "incidents where a containment action was taken. Response actions in "
                "this deployment are simulated."
            ),
        },
        "detection_rate": detection_rate,
    }


def severity_distribution(db: Session, *, window_hours: int = 168) -> list[dict[str, Any]]:
    since = utcnow() - dt.timedelta(hours=window_hours)
    rows = db.execute(
        select(Alert.severity, func.count()).where(Alert.detected_at >= since)
        .group_by(Alert.severity)
    ).all()
    counts = dict(rows)
    return [
        {"severity": s.value, "count": counts.get(s.value, 0)}
        for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
    ]


def alert_trend(db: Session, *, hours: int = 24, buckets: int = 24) -> list[dict[str, Any]]:
    """Alert volume by severity over time.

    Bucketed in Python rather than with date_trunc so the same code path works on
    SQLite and Postgres; the volumes involved make the difference irrelevant.
    """
    now = utcnow()
    since = now - dt.timedelta(hours=hours)
    width = dt.timedelta(hours=hours) / buckets

    alerts = db.execute(
        select(Alert.detected_at, Alert.severity).where(Alert.detected_at >= since)
    ).all()

    series = []
    for index in range(buckets):
        start = since + width * index
        end = start + width
        window = [s for t, s in alerts if start <= t < end]
        series.append({
            "bucket_start": iso(start),
            "bucket_end": iso(end),
            "total": len(window),
            "critical": sum(1 for s in window if s == Severity.CRITICAL),
            "high": sum(1 for s in window if s == Severity.HIGH),
            "medium": sum(1 for s in window if s == Severity.MEDIUM),
            "low": sum(1 for s in window if s in (Severity.LOW, Severity.INFO)),
        })
    return series


def technique_distribution(db: Session, *, limit: int = 12) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for row in db.execute(select(Alert.technique_ids)).all():
        for technique_id in row[0] or []:
            counts[technique_id] = counts.get(technique_id, 0) + 1

    order = catalog.tactic_order()
    results = []
    for technique_id, count in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:limit]:
        info = catalog.technique(technique_id)
        primary = None
        if info and info.tactic_ids:
            primary = sorted(info.tactic_ids, key=lambda t: order.get(t, 99))[0]
        results.append({
            "technique_id": technique_id,
            "name": catalog.technique_name(technique_id),
            "tactic_id": primary,
            "tactic": catalog.tactic_names().get(primary or "", None),
            "alert_count": count,
        })
    return results


def risk_distribution(db: Session) -> list[dict[str, Any]]:
    """Incident counts per risk band.

    The bands are half-open and derived from the same thresholds
    ``Severity.from_score`` uses, because risk scores are floats rounded to one
    decimal place and the two must not disagree. Inclusive integer ranges
    (``26 <= s <= 50``) left gaps at 25.4, 50.5 and 75.9: an incident displayed
    as HIGH appeared in no bar at all, and the bars did not sum to the incident
    count. A chart that quietly drops rows is worse than no chart.
    """
    bands = [
        ("0-25 (low)", 0.0, 26.0),
        ("26-50 (medium)", 26.0, 51.0),
        ("51-75 (high)", 51.0, 76.0),
        ("76-100 (critical)", 76.0, float("inf")),
    ]
    scores = [row[0] for row in db.execute(select(Incident.risk_score)).all()]
    distribution = [
        {"band": label, "min": low, "max": (100.0 if high == float("inf") else high),
         "count": sum(1 for s in scores if low <= s < high)}
        for label, low, high in bands
    ]
    # The bands tile [0, inf) with no gap, so this holds by construction. Kept
    # as a logged check rather than an assert because `assert` is stripped
    # under `python -O`, and because a chart quietly losing a row should be
    # reported, not fatal.
    counted = sum(b["count"] for b in distribution)
    if counted != len(scores):  # pragma: no cover - guarded by construction
        logger.error(
            "risk_distribution_lost_rows",
            extra={"counted": counted, "incidents": len(scores)},
        )
    return distribution


def top_entities(db: Session, *, limit: int = 8) -> dict[str, list[dict[str, Any]]]:
    hosts = db.execute(
        select(Alert.host_ref, func.count()).where(Alert.host_ref.isnot(None))
        .group_by(Alert.host_ref).order_by(func.count().desc()).limit(limit)
    ).all()
    users = db.execute(
        select(Alert.user_ref, func.count()).where(Alert.user_ref.isnot(None))
        .group_by(Alert.user_ref).order_by(func.count().desc()).limit(limit)
    ).all()
    ips = db.execute(
        select(Alert.source_ip, func.count()).where(Alert.source_ip.isnot(None))
        .group_by(Alert.source_ip).order_by(func.count().desc()).limit(limit)
    ).all()
    return {
        "hosts": [{"value": h, "alert_count": c} for h, c in hosts],
        "users": [{"value": u, "alert_count": c} for u, c in users],
        "source_ips": [{"value": i, "alert_count": c} for i, c in ips],
    }


def detection_performance(db: Session) -> dict[str, Any] | None:
    """The most recent measured evaluation, or None if none has been run."""
    run = db.execute(
        select(EvaluationRun).where(EvaluationRun.status == "completed")
        .order_by(EvaluationRun.started_at.desc()).limit(1)
    ).scalars().first()
    if run is None:
        return None
    return {
        "eval_id": run.eval_id,
        "measured_at": iso(run.started_at),
        "dataset_name": run.dataset_name,
        "dataset_seed": run.dataset_seed,
        "dataset_size": run.dataset_size,
        "precision": round(run.precision, 4),
        "recall": round(run.recall, 4),
        "f1": round(run.f1, 4),
        "true_positives": run.true_positives,
        "false_positives": run.false_positives,
        "true_negatives": run.true_negatives,
        "false_negatives": run.false_negatives,
        "median_latency_ms": run.median_latency_ms,
        "p95_latency_ms": run.p95_latency_ms,
    }


def dashboard(db: Session, *, window_hours: int = 24) -> dict[str, Any]:
    return {
        "generated_at": iso(utcnow()),
        "kpis": kpis(db, window_hours=window_hours),
        "severity_distribution": severity_distribution(db),
        "alert_trend": alert_trend(db, hours=window_hours),
        "technique_distribution": technique_distribution(db),
        "risk_distribution": risk_distribution(db),
        "top_entities": top_entities(db),
        "detection_performance": detection_performance(db),
    }
