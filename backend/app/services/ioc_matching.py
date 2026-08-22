"""IOC index construction and match recording."""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.timeutils import utcnow
from app.detection.results import DetectionResult, IOCIndex
from app.models.iocs import IOC, IOCMatch


def build_ioc_index(db: Session) -> IOCIndex:
    """Load active indicators into an in-memory lookup.

    The demo dataset is small enough that a full load per detection pass is the
    simplest correct thing.  ``docs/detection-engine.md`` records the threshold at
    which this should become a cached/streamed lookup instead.
    """
    index = IOCIndex()
    rows = db.execute(select(IOC).where(IOC.is_active.is_(True))).scalars().all()
    for row in rows:
        index.by_type_value[(row.ioc_type, row.indicator.strip().lower())] = {
            "pk": row.id,
            "ioc_id": row.ioc_id,
            "indicator": row.indicator,
            "ioc_type": row.ioc_type,
            "source": row.source,
            "confidence": row.confidence,
            "severity": row.severity,
            "description": row.description,
            "tags": row.tags or [],
        }
    return index


def record_ioc_matches(db: Session, results: Sequence[DetectionResult]) -> int:
    """Persist IOC hits discovered during a detection pass.

    Recorded separately from the alert so that indicator telemetry survives alert
    triage: marking an alert as a false positive should not erase the fact that a
    known indicator was observed.
    """
    recorded = 0
    seen: set[tuple[int, int, str]] = set()

    for result in results:
        ioc_pk = result.extra.get("ioc_pk")
        if not ioc_pk:
            continue
        field = result.extra.get("matched_field", "unknown")
        for ref in result.evidence:
            key = (int(ioc_pk), ref.event.id, field)
            if key in seen:
                continue
            seen.add(key)
            exists = db.execute(
                select(IOCMatch.id).where(
                    IOCMatch.ioc_pk == ioc_pk,
                    IOCMatch.event_pk == ref.event.id,
                    IOCMatch.matched_field == field,
                )
            ).scalar_one_or_none()
            if exists:
                continue
            db.add(
                IOCMatch(
                    ioc_pk=int(ioc_pk),
                    event_pk=ref.event.id,
                    matched_field=field,
                    matched_value=str(result.extra.get("ioc_value", ""))[:512],
                    matched_at=utcnow(),
                )
            )
            ioc = db.get(IOC, int(ioc_pk))
            if ioc:
                ioc.match_count += 1
                ioc.last_seen = utcnow()
            recorded += 1

    if recorded:
        db.flush()
    return recorded
