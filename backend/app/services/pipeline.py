"""The end-to-end pipeline.

    raw telemetry -> normalize -> ingest -> detect -> alert -> correlate -> incident

One function, called by every entry point: the ingestion API, the simulators and
the evaluation harness all run *this* code.  There is no separate "demo path"
that behaves differently from the real one, which is what makes the demo
meaningful and the measured metrics honest.

Note what is absent: no AI is involved anywhere in this file.  Detection and
correlation are fully deterministic, and the platform produces incidents whether
or not an LLM provider is configured.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from app.core.errors import InvalidEventError
from app.core.logging import get_logger
from app.core.timeutils import utcnow
from app.correlation.engine import correlate
from app.models.alerts import Alert
from app.models.events import Event
from app.models.incidents import Incident
from app.services.detection_runner import run_detection
from app.services.ingestion import ingest_events
from app.telemetry.registry import normalize
from app.telemetry.schema import NormalizedEvent

logger = get_logger("sentinelx.pipeline")


@dataclass(slots=True)
class PipelineResult:
    events: list[Event] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)
    incidents: list[Incident] = field(default_factory=list)
    suppressed_alerts: int = 0
    rejected: list[dict[str, Any]] = field(default_factory=list)
    ioc_matches: int = 0
    candidate_events: int = 0
    detection_ms: int = 0
    correlation_ms: int = 0
    total_ms: int = 0
    rule_errors: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        return {
            "events_ingested": len(self.events),
            "events_rejected": len(self.rejected),
            "alerts_created": len(self.alerts),
            "alerts_suppressed": self.suppressed_alerts,
            "incidents_touched": len(self.incidents),
            "ioc_matches": self.ioc_matches,
            "detection_ms": self.detection_ms,
            "correlation_ms": self.correlation_ms,
            "total_ms": self.total_ms,
        }


def process_events(
    db: Session,
    normalized: Sequence[NormalizedEvent],
    *,
    simulation_run_pk: int | None = None,
    is_demo: bool = False,
    run_correlation: bool = True,
) -> PipelineResult:
    """Run validated events through ingestion, detection and correlation."""
    started = utcnow()
    result = PipelineResult()
    if not normalized:
        return result

    result.events = ingest_events(
        db, normalized, simulation_run_pk=simulation_run_pk, is_demo=is_demo
    )

    detection_started = utcnow()
    outcome = run_detection(
        db, result.events, simulation_run_pk=simulation_run_pk, is_demo=is_demo
    )
    result.detection_ms = int((utcnow() - detection_started).total_seconds() * 1000)
    result.alerts = outcome.alerts
    result.suppressed_alerts = outcome.suppressed
    result.ioc_matches = outcome.ioc_matches
    result.candidate_events = outcome.candidate_count
    result.rule_errors = outcome.rule_errors

    if run_correlation and outcome.alerts:
        correlation_started = utcnow()
        result.incidents = correlate(
            db, outcome.alerts, simulation_run_pk=simulation_run_pk, is_demo=is_demo
        )
        result.correlation_ms = int((utcnow() - correlation_started).total_seconds() * 1000)

    result.total_ms = int((utcnow() - started).total_seconds() * 1000)
    return result


def process_raw_records(
    db: Session,
    source: str,
    records: Sequence[dict[str, Any]],
    *,
    simulation_run_pk: int | None = None,
    is_demo: bool = False,
    strict: bool = False,
) -> PipelineResult:
    """Normalize source-native records, then run the pipeline.

    Malformed records are collected and reported rather than aborting the batch.
    A single bad line in a log shipper's payload must not cause the other 199
    events — which may be the attack — to be discarded.  ``strict=True`` restores
    all-or-nothing behaviour for callers that want it.
    """
    normalized: list[NormalizedEvent] = []
    rejected: list[dict[str, Any]] = []

    for index, record in enumerate(records):
        try:
            event = normalize(source, record)
        except InvalidEventError as exc:
            if strict:
                raise
            rejected.append({"index": index, "reason": str(exc.message)})
            continue
        if event is None:
            # The source emits records with no security signal; not an error.
            continue
        normalized.append(event)

    result = process_events(
        db, normalized, simulation_run_pk=simulation_run_pk, is_demo=is_demo
    )
    result.rejected = rejected
    if rejected:
        logger.warning("records_rejected", extra={"source": source, "count": len(rejected)})
    return result


def reprocess_incident(db: Session, incident: Incident) -> Incident:
    """Recompute an incident's derived state after a manual change."""
    from app.correlation.engine import refresh_incident

    return refresh_incident(db, incident)
