"""Turning detection results into alerts.

Three things happen here that the detection engine deliberately does not do:
deduplication, risk scoring against asset context, and persistence.

Deduplication is the difference between a usable alert queue and an unusable
one.  A brute-force attack that runs for ten minutes produces a threshold match
on every ingestion batch; without suppression the analyst sees forty copies of
one finding.  The dedup key combines rule, entity group and a time bucket, so
repetition inside the window updates the existing alert while a genuinely new
occurrence tomorrow opens a new one.
"""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.ids import alert_id as new_alert_id
from app.core.logging import get_logger
from app.core.timeutils import utcnow
from app.correlation import risk as risk_model
from app.detection.results import DetectionResult
from app.models.alerts import Alert, AlertEvent
from app.models.entities import Host, User
from app.models.enums import AlertStatus
from app.models.iocs import IOCMatch

logger = get_logger("sentinelx.alerts")

#: Statuses that still represent live work.  A new detection matching a resolved
#: or false-positive alert opens a fresh alert rather than reopening a closed one.
OPEN_STATUSES = {AlertStatus.NEW, AlertStatus.INVESTIGATING, AlertStatus.ESCALATED}


def persist_detections(
    db: Session,
    results: Sequence[DetectionResult],
    *,
    simulation_run_pk: int | None = None,
    is_demo: bool = False,
) -> tuple[list[Alert], int]:
    """Persist detection results as alerts.

    Returns ``(created_alerts, suppressed_count)``.
    """
    if not results:
        return [], 0

    host_index = _host_index(db, results)
    user_index = _user_index(db, results)
    ioc_hits = _ioc_hit_index(db, results)

    created: list[Alert] = []
    suppressed = 0
    now = utcnow()

    for result in results:
        rule_dedup_window = int(result.extra.get("dedup_window_seconds", 900))
        key = result.dedup_key(bucket_seconds=rule_dedup_window)

        existing = db.execute(
            select(Alert).where(Alert.dedup_key == key, Alert.status.in_(sorted(OPEN_STATUSES)))
        ).scalars().first()

        if existing is not None:
            _merge_into(db, existing, result)
            suppressed += 1
            continue

        alert = _build_alert(
            result,
            key=key,
            now=now,
            host_index=host_index,
            user_index=user_index,
            ioc_hits=ioc_hits,
            simulation_run_pk=simulation_run_pk,
            is_demo=is_demo,
        )
        db.add(alert)
        db.flush()

        seen: set[int] = set()
        for ref in result.evidence:
            if ref.event.id in seen:
                continue
            seen.add(ref.event.id)
            db.add(AlertEvent(alert_pk=alert.id, event_pk=ref.event.id, role=ref.role, step=ref.step))

        db.flush()
        created.append(alert)

    return created, suppressed


def _build_alert(
    result: DetectionResult,
    *,
    key: str,
    now,
    host_index: dict[str, Host],
    user_index: dict[str, User],
    ioc_hits: dict[int, list[IOCMatch]],
    simulation_run_pk: int | None,
    is_demo: bool,
) -> Alert:
    events = [ref.event for ref in result.evidence]
    primary = result.primary_event()

    host_refs = {e.host_ref for e in events if e.host_ref}
    user_refs = {e.user_ref for e in events if e.user_ref}
    criticalities = [host_index[h].criticality for h in host_refs if h in host_index]
    privileged = any(user_index[u].is_privileged for u in user_refs if u in user_index)

    matched_iocs = [m for e in events for m in ioc_hits.get(e.id, [])]
    ioc_confidence = 0.0
    if result.extra.get("ioc_pk"):
        ioc_confidence = float(result.confidence)

    scored = risk_model.score_alert(
        severity=result.severity,
        confidence=result.confidence,
        asset_criticalities=criticalities,
        privileged_user=privileged,
        behavioural_flags=risk_model.collect_behavioural_flags(events),
        anomaly_score=result.extra.get("anomaly_score"),
        ioc_count=len(matched_iocs) + (1 if result.extra.get("ioc_pk") else 0),
        ioc_confidence=ioc_confidence,
        evidence_count=len(events),
        distinct_tactics=len(set(result.tactics)),
    )

    detection_latency_ms = max(0, int((result.detected_at - result.first_event_at).total_seconds() * 1000))
    ingested = min((e.ingested_at for e in events), default=now)
    processing_latency_ms = max(0, int((now - ingested).total_seconds() * 1000))

    return Alert(
        alert_id=new_alert_id(),
        created_at=now,
        detected_at=result.detected_at,
        first_event_at=result.first_event_at,
        last_event_at=result.last_event_at,
        detection_latency_ms=detection_latency_ms,
        processing_latency_ms=processing_latency_ms,
        rule_id=result.rule_id,
        rule_name=result.rule_name,
        rule_type=result.rule_type,
        title=result.title[:255],
        description=" ".join(result.explanation)[:4000],
        severity=result.severity,
        confidence=result.confidence,
        risk_score=scored.score,
        risk_breakdown=scored.breakdown(),
        status=AlertStatus.NEW,
        host_ref=primary.host_ref,
        user_ref=primary.user_ref,
        source_ip=primary.source_ip,
        technique_ids=list(result.technique_ids),
        tactics=list(result.tactics),
        explanation=list(result.explanation),
        entity_keys=result.entity_keys,
        dedup_key=key,
        simulation_run_pk=simulation_run_pk,
        is_demo=is_demo,
    )


def _merge_into(db: Session, alert: Alert, result: DetectionResult) -> None:
    """Fold a duplicate detection into the alert already tracking it."""
    known = {link.event_pk for link in alert.evidence_links}
    added = 0
    for ref in result.evidence:
        if ref.event.id in known:
            continue
        db.add(AlertEvent(alert_pk=alert.id, event_pk=ref.event.id, role=ref.role, step=ref.step))
        known.add(ref.event.id)
        added += 1

    if result.last_event_at > alert.last_event_at:
        alert.last_event_at = result.last_event_at
        alert.detected_at = max(alert.detected_at, result.detected_at)
    if result.confidence > alert.confidence:
        alert.confidence = result.confidence
    if added:
        alert.explanation = list(alert.explanation) + [
            f"Detection recurred: {added} additional event(s) folded into this alert "
            f"at {utcnow().isoformat()}."
        ]
    db.flush()


def _host_index(db: Session, results: Sequence[DetectionResult]) -> dict[str, Host]:
    refs = {e.host_ref for r in results for e in (ref.event for ref in r.evidence) if e.host_ref}
    if not refs:
        return {}
    rows = db.execute(select(Host).where(Host.host_id.in_(sorted(refs)))).scalars().all()
    return {row.host_id: row for row in rows}


def _user_index(db: Session, results: Sequence[DetectionResult]) -> dict[str, User]:
    refs = {e.user_ref for r in results for e in (ref.event for ref in r.evidence) if e.user_ref}
    if not refs:
        return {}
    rows = db.execute(select(User).where(User.user_id.in_(sorted(refs)))).scalars().all()
    return {row.user_id: row for row in rows}


def _ioc_hit_index(db: Session, results: Sequence[DetectionResult]) -> dict[int, list[IOCMatch]]:
    event_pks = {ref.event.id for r in results for ref in r.evidence if ref.event.id}
    if not event_pks:
        return {}
    rows = db.execute(select(IOCMatch).where(IOCMatch.event_pk.in_(sorted(event_pks)))).scalars().all()
    index: dict[int, list[IOCMatch]] = {}
    for row in rows:
        index.setdefault(row.event_pk, []).append(row)
    return index
