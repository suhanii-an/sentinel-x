"""The evaluation harness.

Runs the labelled dataset through the **real** pipeline — the same normalizers,
the same detection engine, the same rules, the same alerting logic that live
ingestion uses — and measures what came out.

Isolation matters. The run happens in a temporary database of its own, so
evaluation never pollutes the operational data and the measured numbers are never
influenced by whatever happened to be in the platform already. Only the resulting
``EvaluationRun`` row is written back.

Nothing in this module can produce a number that was not measured. There is no
path by which a metric can be configured, defaulted or seeded, which is the whole
point of shipping an evaluation rather than a claim.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.database import Base
from app.core.ids import evaluation_id as new_evaluation_id
from app.core.logging import get_logger
from app.core.timeutils import utcnow
from app.evaluation.dataset import DEFAULT_SCENARIOS, LabelledDataset, build_dataset
from app.evaluation.metrics import ConfusionMatrix, LatencyStats, summarise
from app.models.alerts import Alert, AlertEvent
from app.models.enums import GroundTruthLabel
from app.models.events import Event
from app.models.platform import EvaluationRun
from app.services.ioc_store import install_indicators
from app.services.pipeline import process_events
from app.services.rule_registry import sync_rules
from app.simulators.base import TelemetryRecord
from app.telemetry.registry import normalize
from app.telemetry.schema import NormalizedEvent

logger = get_logger("sentinelx.evaluation")


@contextlib.contextmanager
def isolated_database() -> Iterator[Session]:
    """A throwaway database for one evaluation run."""
    with tempfile.TemporaryDirectory(prefix="sentinelx-eval-") as directory:
        path = Path(directory) / "evaluation.db"
        engine = create_engine(
            f"sqlite:///{path}", future=True, connect_args={"check_same_thread": False}
        )
        Base.metadata.create_all(bind=engine)
        factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
        session = factory()
        try:
            yield session
        finally:
            session.close()
            engine.dispose()


def _normalize_dataset(records: list[TelemetryRecord]) -> tuple[list[NormalizedEvent], list[str]]:
    normalized: list[NormalizedEvent] = []
    errors: list[str] = []
    for index, record in enumerate(records):
        try:
            event = normalize(record.source, record.record)
        except Exception as exc:
            errors.append(f"record {index} ({record.source}): {exc}")
            continue
        if event is None:
            continue
        event.label = record.label
        event.label_scenario = record.label_scenario
        normalized.append(event)
    normalized.sort(key=lambda e: e.timestamp)
    return normalized, errors


def evaluate(
    *,
    seed: int = 1337,
    benign_days: int = 5,
    scenarios: tuple[str, ...] = DEFAULT_SCENARIOS,
    include_ambiguous: bool = True,
    dataset: LabelledDataset | None = None,
) -> dict[str, Any]:
    """Run an evaluation and return the measured results."""
    started = utcnow()
    dataset = dataset or build_dataset(
        seed=seed, benign_days=benign_days, scenarios=scenarios,
        include_ambiguous=include_ambiguous,
    )
    normalized, normalization_errors = _normalize_dataset(dataset.records)

    with isolated_database() as db:
        sync_rules(db)
        # The indicator store is part of the detection surface: without it the
        # IOC rule is silent and the evaluation reports coverage it does not have.
        install_indicators(db, is_demo=False)
        db.commit()

        # Chronological batches. Processing the dataset as one batch would let
        # stateful rules see the future, which live ingestion never can: a
        # sequence rule would match events that had not happened yet at the point
        # the earlier ones arrived. Replay must respect causality or the measured
        # recall is optimistic.
        batches = _hourly_batches(normalized)
        for batch in batches:
            process_events(db, batch, is_demo=False, run_correlation=True)
            db.commit()

        result = _score(db, dataset, len(batches))

    finished = utcnow()
    result["run"] = {
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "wall_clock_ms": int((finished - started).total_seconds() * 1000),
        "normalization_errors": normalization_errors[:20],
        "normalization_error_count": len(normalization_errors),
    }
    result["dataset"] = dataset.composition()
    logger.info(
        "evaluation_completed",
        extra={
            "precision": result["metrics"]["precision"],
            "recall": result["metrics"]["recall"],
            "f1": result["metrics"]["f1"],
            "events": len(normalized),
        },
    )
    return result


def _hourly_batches(events: list[NormalizedEvent]) -> list[list[NormalizedEvent]]:
    batches: list[list[NormalizedEvent]] = []
    current: list[NormalizedEvent] = []
    bucket: dt.datetime | None = None
    for event in events:
        hour = event.timestamp.replace(minute=0, second=0, microsecond=0)
        if bucket is None or hour == bucket:
            bucket = hour
            current.append(event)
        else:
            batches.append(current)
            current = [event]
            bucket = hour
    if current:
        batches.append(current)
    return batches


def _score(db: Session, dataset: LabelledDataset, batch_count: int) -> dict[str, Any]:
    events = list(db.execute(select(Event)).scalars().all())
    alerts = list(db.execute(select(Alert)).scalars().all())
    links = list(db.execute(select(AlertEvent)).scalars().all())

    alert_by_pk = {a.id: a for a in alerts}
    # Only trigger evidence counts as a detection.
    triggered_by_event: dict[int, list[Alert]] = {}
    for link in links:
        if link.role != "trigger":
            continue
        alert = alert_by_pk.get(link.alert_pk)
        if alert:
            triggered_by_event.setdefault(link.event_pk, []).append(alert)

    matrix = ConfusionMatrix()
    latency = LatencyStats()
    ambiguous_total = ambiguous_alerted = 0

    scenario_stats: dict[str, dict[str, Any]] = {}
    rule_stats: dict[str, dict[str, Any]] = {}

    for event in events:
        detected = event.id in triggered_by_event
        label = event.label

        if label == GroundTruthLabel.MALICIOUS:
            if detected:
                matrix.true_positives += 1
            else:
                matrix.false_negatives += 1
        elif label == GroundTruthLabel.BENIGN:
            if detected:
                matrix.false_positives += 1
            else:
                matrix.true_negatives += 1
        elif label == GroundTruthLabel.AMBIGUOUS:
            ambiguous_total += 1
            if detected:
                ambiguous_alerted += 1

        scenario = event.label_scenario or "unlabelled"
        stats = scenario_stats.setdefault(scenario, {
            "scenario": scenario,
            "label": label or "unlabelled",
            "events": 0, "detected_events": 0,
            "alerts": set(), "rules": set(),
            "first_event": event.timestamp, "first_alert": None,
        })
        stats["events"] += 1
        stats["first_event"] = min(stats["first_event"], event.timestamp)
        if detected:
            stats["detected_events"] += 1
            for alert in triggered_by_event[event.id]:
                stats["alerts"].add(alert.alert_id)
                stats["rules"].add(alert.rule_id)
                if stats["first_alert"] is None or alert.detected_at < stats["first_alert"]:
                    stats["first_alert"] = alert.detected_at

        for alert in triggered_by_event.get(event.id, []):
            rule = rule_stats.setdefault(alert.rule_id, {
                "rule_id": alert.rule_id, "alerts": set(),
                "true_positive_events": 0, "false_positive_events": 0,
                "ambiguous_events": 0,
            })
            rule["alerts"].add(alert.alert_id)
            if label == GroundTruthLabel.MALICIOUS:
                rule["true_positive_events"] += 1
            elif label == GroundTruthLabel.BENIGN:
                rule["false_positive_events"] += 1
            elif label == GroundTruthLabel.AMBIGUOUS:
                rule["ambiguous_events"] += 1

    # Scenario-level detection and latency.
    scenarios_total = scenarios_detected = 0
    per_scenario: list[dict[str, Any]] = []

    for scenario, stats in sorted(scenario_stats.items()):
        detected = bool(stats["alerts"])
        expected = dataset.scenario_windows.get(scenario, {})
        entry: dict[str, Any] = {
            "scenario": scenario,
            "label": stats["label"],
            "events": stats["events"],
            "detected_events": stats["detected_events"],
            "event_recall": round(stats["detected_events"] / stats["events"], 4) if stats["events"] else 0.0,
            "alert_count": len(stats["alerts"]),
            "rules_fired": sorted(stats["rules"]),
            "detected": detected,
        }

        if stats["label"] == GroundTruthLabel.MALICIOUS and scenario in dataset.scenario_windows:
            scenarios_total += 1
            if detected:
                scenarios_detected += 1
            expected_rules = set(expected.get("expected_rules", []))
            entry["expected_rules"] = sorted(expected_rules)
            entry["expected_rules_fired"] = sorted(expected_rules & stats["rules"])
            entry["expected_rules_missed"] = sorted(expected_rules - stats["rules"])
            if stats["first_alert"] is not None:
                delta_ms = (stats["first_alert"] - stats["first_event"]).total_seconds() * 1000
                entry["detection_latency_ms"] = round(max(0.0, delta_ms), 1)
                latency.add(delta_ms)
            else:
                entry["detection_latency_ms"] = None

        per_scenario.append(entry)

    per_rule = []
    for rule_id, stats in sorted(rule_stats.items()):
        tp = stats["true_positive_events"]
        fp = stats["false_positive_events"]
        per_rule.append({
            "rule_id": rule_id,
            "alerts": len(stats["alerts"]),
            "true_positive_events": tp,
            "false_positive_events": fp,
            "ambiguous_events": stats["ambiguous_events"],
            "event_precision": round(tp / (tp + fp), 4) if (tp + fp) else 1.0,
        })
    per_rule.sort(key=lambda r: r["alerts"], reverse=True)

    # Rules that never fired at all: a silent rule is a coverage gap, and it
    # cannot be seen from precision and recall alone.
    from app.models.detections import DetectionRule

    all_rules = {r.rule_id for r in db.execute(select(DetectionRule)).scalars().all()}
    silent_rules = sorted(all_rules - set(rule_stats.keys()))

    metrics = summarise(
        matrix, latency,
        ambiguous_total=ambiguous_total,
        ambiguous_alerted=ambiguous_alerted,
        scenarios_total=scenarios_total,
        scenarios_detected=scenarios_detected,
    )

    return {
        "metrics": metrics,
        "per_scenario": per_scenario,
        "per_rule": per_rule,
        "silent_rules": silent_rules,
        "totals": {
            "events_ingested": len(events),
            "alerts_generated": len(alerts),
            "ingestion_batches": batch_count,
        },
    }


def run_and_store(
    db: Session,
    *,
    seed: int = 1337,
    benign_days: int = 5,
    scenarios: tuple[str, ...] = DEFAULT_SCENARIOS,
    include_ambiguous: bool = True,
    requested_by: str = "system",
) -> EvaluationRun:
    """Run an evaluation and persist the measured result."""
    run = EvaluationRun(
        eval_id=new_evaluation_id(),
        started_at=utcnow(),
        status="running",
        dataset_name="sentinel-x-eval-v1",
        dataset_seed=seed,
        requested_by=requested_by,
        config={
            "seed": seed,
            "benign_days": benign_days,
            "scenarios": list(scenarios),
            "include_ambiguous": include_ambiguous,
        },
    )
    db.add(run)
    db.flush()

    try:
        result = evaluate(
            seed=seed, benign_days=benign_days,
            scenarios=scenarios, include_ambiguous=include_ambiguous,
        )
    except Exception as exc:
        run.status = "failed"
        run.finished_at = utcnow()
        run.error = f"{type(exc).__name__}: {exc}"[:2000]
        db.flush()
        logger.exception("evaluation_failed")
        raise

    metrics = result["metrics"]
    composition = result["dataset"]
    counts = composition["counts"]

    run.status = "completed"
    run.finished_at = utcnow()
    run.dataset_size = result["totals"]["events_ingested"]
    run.benign_count = counts.get("benign", 0)
    run.malicious_count = counts.get("malicious", 0)
    run.ambiguous_count = counts.get("ambiguous", 0)
    run.true_positives = metrics["true_positives"]
    run.false_positives = metrics["false_positives"]
    run.true_negatives = metrics["true_negatives"]
    run.false_negatives = metrics["false_negatives"]
    run.precision = metrics["precision"]
    run.recall = metrics["recall"]
    run.f1 = metrics["f1"]
    run.median_latency_ms = metrics["median_detection_latency_ms"]
    run.p95_latency_ms = metrics["p95_detection_latency_ms"]
    run.per_scenario = result["per_scenario"]
    run.per_rule = result["per_rule"]
    run.config = {**run.config, "silent_rules": result["silent_rules"],
                  "totals": result["totals"], "metrics": metrics,
                  "dataset": composition, "run": result["run"]}
    db.flush()
    return run
