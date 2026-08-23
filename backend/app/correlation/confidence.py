"""Attack-chain confidence.

Distinct from risk.  Risk answers "how much should I care?"; confidence answers
"how sure am I that these alerts are one attack rather than a coincidence?"  An
incident can be high-risk and low-confidence — that combination is exactly what
an analyst most needs to see, and averaging the two into a single number would
hide it.

Model
-----
::

    confidence = 0.30 x detection_confidence
               + 0.20 x evidence_volume
               + 0.15 x entity_consistency
               + 0.15 x temporal_consistency
               + 0.15 x technique_breadth
               + 0.05 x indicator_corroboration

Every term is in [0, 1].  The result is capped at 0.98: a correlation heuristic
should never present itself as certainty.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

WEIGHTS = {
    "detection_confidence": 0.30,
    "evidence_volume": 0.20,
    "entity_consistency": 0.15,
    "temporal_consistency": 0.15,
    "technique_breadth": 0.15,
    "indicator_corroboration": 0.05,
}

MAX_CONFIDENCE = 0.98
#: Evidence count at which volume saturates.
VOLUME_SATURATION = 25
#: Distinct tactics representing a complete intrusion chain.
BREADTH_SATURATION = 5
#: Gap between consecutive alerts beyond which temporal cohesion is zero.
MAX_COHESIVE_GAP_SECONDS = 3600


@dataclass(slots=True)
class ConfidenceComponent:
    factor: str
    weight: float
    value: float
    contribution: float
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "factor": self.factor,
            "weight": round(self.weight, 3),
            "value": round(self.value, 3),
            "contribution": round(self.contribution, 4),
            "explanation": self.explanation,
        }


@dataclass(slots=True)
class ConfidenceScore:
    value: float
    components: list[ConfidenceComponent]

    def breakdown(self) -> list[dict[str, Any]]:
        return [c.to_dict() for c in self.components]


def _component(factor: str, value: float, explanation: str) -> ConfidenceComponent:
    weight = WEIGHTS[factor]
    value = max(0.0, min(1.0, value))
    return ConfidenceComponent(
        factor=factor,
        weight=weight,
        value=value,
        contribution=weight * value,
        explanation=explanation,
    )


def compute_confidence(
    *,
    alert_confidences: Sequence[float],
    event_count: int,
    entity_key_sets: Sequence[Sequence[str]],
    alert_times: Sequence[Any],
    distinct_tactics: int,
    ioc_match_count: int,
) -> ConfidenceScore:
    components: list[ConfidenceComponent] = []
    alert_count = max(1, len(alert_confidences))

    mean_confidence = sum(alert_confidences) / alert_count if alert_confidences else 0.0
    components.append(_component(
        "detection_confidence", mean_confidence,
        f"Mean confidence of the {alert_count} contributing detection(s) is {mean_confidence:.0%}.",
    ))

    volume = math.log1p(max(0, event_count)) / math.log1p(VOLUME_SATURATION)
    components.append(_component(
        "evidence_volume", volume,
        f"{event_count} correlated event(s) supporting the incident.",
    ))

    # Entity consistency: the share of alerts touching the single most common
    # entity.  A campaign converges on the same host, account or address; a
    # coincidental cluster does not.
    counts: dict[str, int] = {}
    for keys in entity_key_sets:
        for key in set(keys):
            counts[key] = counts.get(key, 0) + 1
    if counts:
        best_key, best_count = max(counts.items(), key=lambda kv: kv[1])
        consistency = best_count / alert_count
        detail = (
            f"{best_count} of {alert_count} alert(s) involve {best_key}."
            if alert_count > 1
            else f"Single alert centred on {best_key}; no cross-alert corroboration yet."
        )
        if alert_count == 1:
            consistency = 0.5
    else:
        consistency = 0.0
        detail = "No shared entity identified across the contributing alerts."
    components.append(_component("entity_consistency", consistency, detail))

    # Temporal consistency: intrusions are contiguous.  A long quiet gap between
    # alerts is evidence that two unrelated things were merged.
    times = sorted(t for t in alert_times if t is not None)
    if len(times) > 1:
        gaps = [(times[i + 1] - times[i]).total_seconds() for i in range(len(times) - 1)]
        largest = max(gaps)
        temporal = max(0.0, 1.0 - (largest / MAX_COHESIVE_GAP_SECONDS))
        detail = (
            f"Largest gap between consecutive alerts is {int(largest)}s "
            f"(cohesion threshold {MAX_COHESIVE_GAP_SECONDS}s)."
        )
    else:
        temporal = 0.5
        detail = "Only one alert timestamp; temporal cohesion cannot be assessed."
    components.append(_component("temporal_consistency", temporal, detail))

    breadth = min(1.0, distinct_tactics / BREADTH_SATURATION)
    components.append(_component(
        "technique_breadth", breadth,
        f"Activity spans {distinct_tactics} ATT&CK tactic(s) "
        f"({BREADTH_SATURATION} represents a full intrusion chain).",
    ))

    ioc_value = 1.0 if ioc_match_count else 0.0
    components.append(_component(
        "indicator_corroboration", ioc_value,
        f"{ioc_match_count} threat-intelligence indicator match(es)."
        if ioc_match_count else "No threat-intelligence corroboration.",
    ))

    total = min(MAX_CONFIDENCE, sum(c.contribution for c in components))
    return ConfidenceScore(value=round(total, 3), components=components)
