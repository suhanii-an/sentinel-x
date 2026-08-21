"""The detection engine.

Pure evaluation: rules plus a context in, detection results out.  No database, no
side effects, no clock reads beyond ``ctx.now``.  Everything stateful —
persistence, deduplication, alerting — lives in the services layer.

That separation is what makes the evaluation harness trustworthy.  The same
``evaluate()`` call that runs on live ingestion runs against the labelled
dataset, so measured precision and recall describe the real detection logic
rather than a test double of it.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from app.core.logging import get_logger
from app.detection.detectors import anomaly, ioc, match, sequence, threshold
from app.detection.results import DetectionContext, DetectionResult
from app.detection.rules import RuleDefinition, load_rules
from app.models.enums import RuleType

logger = get_logger("sentinelx.detection")

DETECTORS: dict[str, Callable[[RuleDefinition, DetectionContext], list[DetectionResult]]] = {
    RuleType.MATCH: match.run,
    RuleType.THRESHOLD: threshold.run,
    RuleType.SEQUENCE: sequence.run,
    RuleType.IOC: ioc.run,
    RuleType.ANOMALY: anomaly.run,
}


class DetectionEngine:
    def __init__(self, rules: list[RuleDefinition]):
        self.rules = rules

    @classmethod
    def from_disk(cls, rules_dir: Path) -> tuple[DetectionEngine, list[str]]:
        rules, errors = load_rules(rules_dir)
        return cls(rules), errors

    @property
    def rule_ids(self) -> list[str]:
        return [r.id for r in self.rules]

    def rule(self, rule_id: str) -> RuleDefinition | None:
        return next((r for r in self.rules if r.id == rule_id), None)

    def evaluate(
        self,
        ctx: DetectionContext,
        *,
        only_rule_ids: set[str] | None = None,
    ) -> list[DetectionResult]:
        """Run every enabled rule against the context."""
        results: list[DetectionResult] = []

        for rule in self.rules:
            if not rule.enabled:
                continue
            if only_rule_ids is not None and rule.id not in only_rule_ids:
                continue
            detector = DETECTORS.get(str(rule.type))
            if detector is None:  # pragma: no cover - guarded by rule schema
                continue
            try:
                produced = detector(rule, ctx)
                for result in produced:
                    # Suppression policy belongs to the rule, but it is applied by
                    # the alerting layer — carry it across on the result.
                    result.extra.setdefault("dedup_window_seconds", rule.dedup_window_seconds)
                results.extend(produced)
            except Exception:
                # One broken rule must never take down the detection pass for
                # every other rule.  The failure is logged loudly and the rule is
                # reported as errored via the API.
                logger.exception("rule_evaluation_failed", extra={"rule_id": rule.id})

        # Deterministic order: newest first, then by rule id so two runs over the
        # same data produce byte-identical output (required by evaluation).
        results.sort(key=lambda r: (r.detected_at, r.rule_id), reverse=True)
        return results
