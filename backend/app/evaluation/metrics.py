"""Detection metrics.

Definitions are stated explicitly because "precision" means nothing in a
detection context until you say what a positive *is*.

Unit of analysis: **one event**.

- TP — a malicious event that is trigger evidence for at least one alert.
- FN — a malicious event that no alert triggered on.
- FP — a benign event that is trigger evidence for at least one alert.
- TN — a benign event that no alert triggered on.

Two choices worth defending:

*Trigger evidence only.*  Alerts also carry context events. Counting those as
detections would credit a rule for every benign event that happened to sit in the
same window, inflating recall and destroying the meaning of precision.

*Ambiguous events are excluded.*  They are neither positives nor negatives — that
is what ambiguous means — and are reported separately as false-positive pressure.
Folding them into either class would be a claim about ground truth that cannot be
defended, in whichever direction it flattered the numbers.

Scenario-level detection rate is reported alongside, because the operationally
important question is "was the attack caught?", not "was every one of its events
individually flagged?". Event-level recall is the harsher measure; both are shown.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ConfusionMatrix:
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0

    @property
    def precision(self) -> float:
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def recall(self) -> float:
        denominator = self.true_positives + self.false_negatives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return (2 * p * r / (p + r)) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        total = (self.true_positives + self.false_positives
                 + self.true_negatives + self.false_negatives)
        return (self.true_positives + self.true_negatives) / total if total else 0.0

    @property
    def false_positive_rate(self) -> float:
        denominator = self.false_positives + self.true_negatives
        return self.false_positives / denominator if denominator else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
        }


@dataclass(slots=True)
class LatencyStats:
    samples_ms: list[float] = field(default_factory=list)

    def add(self, milliseconds: float) -> None:
        self.samples_ms.append(max(0.0, float(milliseconds)))

    def to_dict(self) -> dict[str, Any]:
        if not self.samples_ms:
            return {"count": 0, "median_ms": 0.0, "mean_ms": 0.0, "p95_ms": 0.0,
                    "min_ms": 0.0, "max_ms": 0.0}
        ordered = sorted(self.samples_ms)
        index = max(0, min(len(ordered) - 1, int(round(0.95 * (len(ordered) - 1)))))
        return {
            "count": len(ordered),
            "median_ms": round(statistics.median(ordered), 1),
            "mean_ms": round(statistics.fmean(ordered), 1),
            "p95_ms": round(ordered[index], 1),
            "min_ms": round(ordered[0], 1),
            "max_ms": round(ordered[-1], 1),
        }


def summarise(
    matrix: ConfusionMatrix,
    latency: LatencyStats,
    *,
    ambiguous_total: int,
    ambiguous_alerted: int,
    scenarios_total: int,
    scenarios_detected: int,
) -> dict[str, Any]:
    latency_stats = latency.to_dict()
    return {
        **matrix.to_dict(),
        "event_latency": latency_stats,
        "median_detection_latency_ms": latency_stats["median_ms"],
        "p95_detection_latency_ms": latency_stats["p95_ms"],
        "median_detection_latency_seconds": round(latency_stats["median_ms"] / 1000, 2),
        "scenario_detection_rate": (
            round(scenarios_detected / scenarios_total, 4) if scenarios_total else 0.0
        ),
        "scenarios_total": scenarios_total,
        "scenarios_detected": scenarios_detected,
        "ambiguous_total": ambiguous_total,
        "ambiguous_alerted": ambiguous_alerted,
        "ambiguous_alert_rate": (
            round(ambiguous_alerted / ambiguous_total, 4) if ambiguous_total else 0.0
        ),
        "definitions": {
            "unit": "one security event",
            "positive": "the event is trigger evidence for at least one alert",
            "true_positive": "malicious-labelled event that triggered an alert",
            "false_positive": "benign-labelled event that triggered an alert",
            "false_negative": "malicious-labelled event no alert triggered on",
            "true_negative": "benign-labelled event no alert triggered on",
            "ambiguous": (
                "benign activity that legitimately resembles an attack; excluded from "
                "precision and recall, reported separately as false-positive pressure"
            ),
            "detection_latency": (
                "event time from the first malicious event of a scenario to the first "
                "alert detecting it; measured in event time so it is stable under replay"
            ),
        },
    }
