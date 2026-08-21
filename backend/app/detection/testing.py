"""Rule self-tests.

Every rule can ship its own positive and negative cases.  The negative cases
matter more: it is easy to write a rule that fires on the attack, and hard to
write one that does not also fire on the administrator doing their job.  A rule
with only ``match`` tests has not been tested.

These run in three places — the ``/detections`` UI, the pytest suite, and CI — all
through this one function, so what the UI shows is what CI enforced.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any

from app.core.timeutils import utcnow
from app.detection.engine import DetectionEngine
from app.detection.results import BaselineSnapshot, DetectionContext, IOCIndex
from app.detection.rules import RuleDefinition
from app.models.events import Event

#: Fixed base time so a test outcome never depends on when it was run.
TEST_BASE_TIME = dt.datetime(2026, 3, 2, 14, 0, 0, tzinfo=dt.UTC)


@dataclass(slots=True)
class RuleTestResult:
    rule_id: str
    test_name: str
    expected: str
    actual: str
    passed: bool
    detail: str = ""
    matched_count: int = 0


@dataclass(slots=True)
class RuleTestSummary:
    total: int = 0
    passed: int = 0
    failed: int = 0
    results: list[RuleTestResult] = field(default_factory=list)
    rules_without_tests: list[str] = field(default_factory=list)
    rules_without_negative_tests: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.failed == 0


def build_test_event(spec: dict[str, Any], *, index: int, base_time: dt.datetime = TEST_BASE_TIME) -> Event:
    """Build an unpersisted Event from a rule-test event specification.

    Unpersisted on purpose: rule tests must not need a database, so they can run
    in CI in milliseconds and cannot be affected by leftover state.
    """
    offset = float(spec.get("offset_seconds", 0))
    timestamp = base_time + dt.timedelta(seconds=offset)

    event = Event(
        event_id=spec.get("event_id") or f"EVT-TEST-{index:04d}",
        timestamp=timestamp,
        ingested_at=timestamp,
        event_type=spec.get("event_type", "process"),
        source=spec.get("source", "normalized"),
        host_ref=spec.get("host_id") or spec.get("host"),
        user_ref=spec.get("user_id") or spec.get("user"),
        source_ip=spec.get("source_ip"),
        destination_ip=spec.get("destination_ip"),
        destination_port=spec.get("destination_port"),
        protocol=spec.get("protocol"),
        bytes_out=spec.get("bytes_out"),
        process_name=spec.get("process") or spec.get("process_name"),
        process_id=spec.get("process_id"),
        parent_process=spec.get("parent_process"),
        command_line=spec.get("command_line"),
        file_path=spec.get("file_path"),
        file_hash=spec.get("file_hash"),
        cloud_provider=spec.get("cloud_provider"),
        cloud_account=spec.get("cloud_account"),
        cloud_service=spec.get("cloud_service"),
        cloud_resource=spec.get("cloud_resource"),
        cloud_region=spec.get("cloud_region"),
        action=spec.get("action"),
        status=spec.get("status", "unknown"),
        message=spec.get("message"),
        meta=spec.get("metadata") or {},
        raw_event=spec.get("raw_event") or {},
    )
    # The in-memory primary key lets alert-construction code that expects an id
    # run unchanged against test events.
    event.id = -(index + 1)
    return event


def run_rule_tests(
    rule: RuleDefinition,
    *,
    iocs: IOCIndex | None = None,
    baselines: BaselineSnapshot | None = None,
) -> list[RuleTestResult]:
    engine = DetectionEngine([rule.model_copy(update={"enabled": True})])
    results: list[RuleTestResult] = []

    for test in rule.tests:
        events = [build_test_event(spec, index=i) for i, spec in enumerate(test.events)]

        # Fixtures declared by the test take precedence over caller-supplied
        # state, so an anomaly or IOC rule's cases are fully self-describing.
        test_iocs = iocs or IOCIndex()
        if test.iocs:
            test_iocs = IOCIndex()
            for i, spec in enumerate(test.iocs):
                test_iocs.by_type_value[(spec.ioc_type, spec.indicator.strip().lower())] = {
                    "pk": -(i + 1),
                    "ioc_id": spec.ioc_id,
                    "indicator": spec.indicator,
                    "ioc_type": spec.ioc_type,
                    "source": spec.source,
                    "confidence": spec.confidence,
                    "severity": spec.severity,
                    "description": spec.description,
                    "tags": spec.tags,
                }

        test_baselines = baselines or BaselineSnapshot()
        if test.baselines:
            test_baselines = BaselineSnapshot()
            for spec in test.baselines:
                key = (spec.entity_type, spec.entity_ref.lower(), spec.feature)
                test_baselines.entries[key] = spec.value
                test_baselines.counts[key] = spec.observations

        ctx = DetectionContext(
            events=sorted(events, key=lambda e: e.timestamp),
            now=utcnow(),
            iocs=test_iocs,
            baselines=test_baselines,
            new_event_ids={e.event_id for e in events},
        )
        try:
            detections = engine.evaluate(ctx)
            actual = "match" if detections else "no_match"
            detail = ""
            if detections:
                detail = detections[0].explanation[0] if detections[0].explanation else ""
        except Exception as exc:  # a rule that crashes is a failed test
            actual = "error"
            detections = []
            detail = f"{type(exc).__name__}: {exc}"

        results.append(
            RuleTestResult(
                rule_id=rule.id,
                test_name=test.name,
                expected=test.expect,
                actual=actual,
                passed=actual == test.expect,
                detail=detail,
                matched_count=len(detections),
            )
        )
    return results


def run_all_rule_tests(rules: list[RuleDefinition]) -> RuleTestSummary:
    summary = RuleTestSummary()
    for rule in rules:
        if not rule.tests:
            summary.rules_without_tests.append(rule.id)
            continue
        if not any(t.expect == "no_match" for t in rule.tests):
            summary.rules_without_negative_tests.append(rule.id)
        for result in run_rule_tests(rule):
            summary.total += 1
            summary.results.append(result)
            if result.passed:
                summary.passed += 1
            else:
                summary.failed += 1
    return summary
