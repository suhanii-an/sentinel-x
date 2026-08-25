"""Running attack scenarios through the real pipeline.

Two details worth calling out.

*Seeded randomness.*  Every run records the RNG seed it used.  Re-running with
the same seed reproduces the telemetry exactly, which is what makes a simulation
citable in an incident report and makes the evaluation harness repeatable.

*Time anchoring.*  Scenarios are generated twice: once to measure how long the
attack spans in event time, then again anchored so the final event lands at
"now".  A demo whose attack finished four hours ago does not look like a live
SOC, and shifting timestamps after generation would corrupt the raw records that
the normalizers are supposed to parse.
"""

from __future__ import annotations

import datetime as dt
import random
from typing import Any

from sqlalchemy.orm import Session

from app.core.ids import simulation_id
from app.core.logging import get_logger
from app.core.timeutils import parse_timestamp, utcnow
from app.models.enums import SimulationStatus
from app.models.platform import SimulationRun
from app.services.pipeline import PipelineResult, process_events
from app.simulators.base import TelemetryRecord
from app.simulators.environment import DEFAULT_ENVIRONMENT
from app.simulators.registry import get_simulator
from app.telemetry.registry import normalize
from app.telemetry.schema import NormalizedEvent

logger = get_logger("sentinelx.simulation")

#: Gap between the last simulated event and "now".  Small but non-zero, so the
#: data reads as "this just happened" rather than "this is happening in the
#: future", which a strict timestamp validator would reject.
TAIL_SECONDS = 5

TIME_KEYS = ("timestamp", "@timestamp", "start_time", "time", "TimeCreated", "eventTime")


class ScenarioNotFound(KeyError):
    pass


def _record_time(record: TelemetryRecord) -> dt.datetime | None:
    for key in TIME_KEYS:
        value = record.record.get(key)
        if value:
            try:
                return parse_timestamp(value)
            except (ValueError, TypeError):
                continue
    return None


def _span(records: list[TelemetryRecord]) -> float:
    times = [t for t in (_record_time(r) for r in records) if t is not None]
    if len(times) < 2:
        return 0.0
    return (max(times) - min(times)).total_seconds()


def generate_records(
    scenario: str,
    *,
    params: dict[str, Any] | None = None,
    seed: int | None = None,
    anchor_end_at: dt.datetime | None = None,
) -> tuple[list[TelemetryRecord], int, dt.datetime]:
    """Generate a scenario's telemetry, anchored so it ends at ``anchor_end_at``.

    Returns ``(records, seed, start_time)``.
    """
    simulator = get_simulator(scenario)
    if simulator is None:
        raise ScenarioNotFound(scenario)

    seed = seed if seed is not None else random.randint(1, 2**31 - 1)
    params = params or {}
    anchor = anchor_end_at or (utcnow() - dt.timedelta(seconds=TAIL_SECONDS))

    # Pass 1: measure the span with a provisional anchor.
    probe = simulator.generate(DEFAULT_ENVIRONMENT, random.Random(seed), anchor, dict(params))
    span = _span(probe)

    # Pass 2: same seed, so the timings are identical, shifted to end at anchor.
    start = anchor - dt.timedelta(seconds=span)
    records = simulator.generate(DEFAULT_ENVIRONMENT, random.Random(seed), start, dict(params))
    return records, seed, start


def normalize_records(records: list[TelemetryRecord]) -> tuple[list[NormalizedEvent], list[dict[str, Any]]]:
    """Normalize simulated records through the production normalizers."""
    normalized: list[NormalizedEvent] = []
    rejected: list[dict[str, Any]] = []

    for index, record in enumerate(records):
        try:
            event = normalize(record.source, record.record)
        except Exception as exc:
            # A simulator producing telemetry the normalizer cannot parse is a
            # bug in this repository, so it is surfaced rather than swallowed.
            rejected.append({"index": index, "source": record.source, "reason": str(exc)})
            continue
        if event is None:
            continue
        event.label = record.label
        event.label_scenario = record.label_scenario
        normalized.append(event)

    normalized.sort(key=lambda e: e.timestamp)
    return normalized, rejected


def run_scenario(
    db: Session,
    scenario: str,
    *,
    params: dict[str, Any] | None = None,
    seed: int | None = None,
    requested_by: str = "system",
    is_demo: bool = False,
    anchor_end_at: dt.datetime | None = None,
) -> tuple[SimulationRun, PipelineResult]:
    """Generate a scenario and drive it through the full detection pipeline."""
    simulator = get_simulator(scenario)
    if simulator is None:
        raise ScenarioNotFound(scenario)

    started = utcnow()
    run = SimulationRun(
        run_id=simulation_id(),
        scenario=scenario,
        scenario_name=simulator.spec.name,
        status=SimulationStatus.RUNNING,
        started_at=started,
        parameters=dict(params or {}),
        expected_techniques=list(simulator.spec.techniques),
        requested_by=requested_by,
    )
    db.add(run)
    db.flush()

    try:
        records, used_seed, start = generate_records(
            scenario, params=params, seed=seed, anchor_end_at=anchor_end_at
        )
        run.seed = used_seed

        normalized, rejected = normalize_records(records)
        result = process_events(
            db, normalized, simulation_run_pk=run.id, is_demo=is_demo
        )
        result.rejected = rejected

        detected = sorted({t for alert in result.alerts for t in (alert.technique_ids or [])})

        run.status = SimulationStatus.COMPLETED
        run.finished_at = utcnow()
        run.duration_ms = int((run.finished_at - started).total_seconds() * 1000)
        run.event_count = len(result.events)
        run.alert_count = len(result.alerts)
        run.alert_ids = [a.alert_id for a in result.alerts]
        run.incident_ids = sorted({i.incident_id for i in result.incidents})
        run.detected_techniques = detected
        run.stage_log = _build_stage_log(records, normalized, start)
        db.flush()

        logger.info(
            "simulation_completed",
            extra={
                "scenario": scenario,
                "run_id": run.run_id,
                "events": run.event_count,
                "alerts": run.alert_count,
                "incidents": run.incident_ids,
                "seed": used_seed,
            },
        )
        return run, result

    except Exception as exc:
        run.status = SimulationStatus.FAILED
        run.finished_at = utcnow()
        run.error = f"{type(exc).__name__}: {exc}"[:2000]
        db.flush()
        logger.exception("simulation_failed", extra={"scenario": scenario, "run_id": run.run_id})
        raise


def _build_stage_log(
    records: list[TelemetryRecord],
    normalized: list[NormalizedEvent],
    start: dt.datetime,
) -> list[dict[str, Any]]:
    """Per-stage summary, ordered by when each stage began."""
    stages: dict[str, dict[str, Any]] = {}
    for record in records:
        key = record.label_scenario or "unlabelled"
        moment = _record_time(record)
        stage = stages.setdefault(key, {
            "stage": key,
            "record_count": 0,
            "sources": set(),
            "first_seen": moment,
            "last_seen": moment,
        })
        stage["record_count"] += 1
        stage["sources"].add(record.source)
        if moment:
            stage["first_seen"] = min(stage["first_seen"] or moment, moment)
            stage["last_seen"] = max(stage["last_seen"] or moment, moment)

    log = []
    for stage in stages.values():
        log.append({
            "stage": stage["stage"],
            "record_count": stage["record_count"],
            "sources": sorted(stage["sources"]),
            "first_seen": stage["first_seen"].isoformat() if stage["first_seen"] else None,
            "last_seen": stage["last_seen"].isoformat() if stage["last_seen"] else None,
            "offset_seconds": (
                int((stage["first_seen"] - start).total_seconds()) if stage["first_seen"] else 0
            ),
        })
    log.sort(key=lambda s: s["offset_seconds"])
    return log


def coverage_report(run: SimulationRun) -> dict[str, Any]:
    """Compare what a scenario intended to exercise against what actually fired.

    This is how a coverage regression becomes visible instead of being assumed
    away: the UI shows expected techniques the run did not detect.
    """
    expected = set(run.expected_techniques or [])
    detected = set(run.detected_techniques or [])
    return {
        "expected_techniques": sorted(expected),
        "detected_techniques": sorted(detected),
        "covered": sorted(expected & detected),
        "missed": sorted(expected - detected),
        "additional": sorted(detected - expected),
        "coverage_ratio": round(len(expected & detected) / len(expected), 3) if expected else 0.0,
    }
