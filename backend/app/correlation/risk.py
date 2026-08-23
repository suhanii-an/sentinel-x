"""Explainable risk scoring.

A risk score that cannot be decomposed is a number an analyst has no reason to
trust.  Every score produced here comes with the exact contribution of every
component, and the UI renders that breakdown rather than the bare figure.

Model
-----
::

    risk = 100 x clamp01(
          0.30 x severity
        + 0.20 x detection_confidence
        + 0.15 x asset_criticality
        + 0.15 x behavioural_deviation
        + 0.10 x indicator_corroboration
        + 0.10 x correlation_strength
    )

Bands: 0-25 LOW, 26-50 MEDIUM, 51-75 HIGH, 76-100 CRITICAL.

The weights encode a position worth defending in an interview: *what* fired
(severity) and *how sure the detection is* (confidence) dominate, because those
are properties of the evidence.  Asset value and behavioural deviation modulate
the result — a critical finding on a lab box is not a critical finding on a
domain controller — and indicator hits and correlation breadth contribute least
individually because each is easy to game or to coincide with.

Every term is in [0, 1], so the weights are directly comparable and the total is
bounded without normalisation tricks.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from app.models.enums import SEVERITY_WEIGHT, Severity

WEIGHTS: dict[str, float] = {
    "severity": 0.30,
    "confidence": 0.20,
    "asset": 0.15,
    "behavioural": 0.15,
    "indicator": 0.10,
    "correlation": 0.10,
}

#: Enrichment flags that indicate intrinsically suspicious behaviour.  Produced
#: by the normalizers, consumed here — the risk model never re-parses telemetry.
BEHAVIOURAL_FLAGS: dict[str, tuple[float, str]] = {
    "uid_zero": (1.00, "account created with UID 0"),
    "high_risk_policy": (0.95, "high-privilege cloud policy referenced"),
    "privileged_group": (0.85, "membership change on a privileged group"),
    "persistence_path": (0.80, "write to a persistence location"),
    "setuid": (0.80, "setuid bit present"),
    "elevated": (0.55, "privilege elevation performed"),
    "internal_lateral_candidate": (0.60, "internal connection over a remote-admin protocol"),
    "sensitive_file": (0.65, "access to a credential-bearing file"),
    "invalid_user": (0.35, "authentication attempt against a non-existent account"),
    "outbound_external": (0.30, "outbound connection to external address space"),
}

#: Evidence volume at which correlation strength saturates.
CORRELATION_SATURATION = 20
#: Distinct ATT&CK tactics at which breadth saturates (a full intrusion chain).
TACTIC_SATURATION = 5
#: Asset weight used when the host is unknown to the inventory.
UNKNOWN_ASSET_WEIGHT = 0.40


@dataclass(slots=True)
class RiskComponent:
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
            "contribution": round(self.contribution, 2),
            "explanation": self.explanation,
        }


@dataclass(slots=True)
class RiskScore:
    score: float
    components: list[RiskComponent]

    @property
    def band(self) -> str:
        return str(Severity.from_score(self.score))

    def breakdown(self) -> list[dict[str, Any]]:
        return [c.to_dict() for c in self.components]


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def _component(factor: str, value: float, explanation: str) -> RiskComponent:
    weight = WEIGHTS[factor]
    value = _clamp01(value)
    return RiskComponent(
        factor=factor,
        weight=weight,
        value=value,
        contribution=round(weight * value * 100, 2),
        explanation=explanation,
    )


# --------------------------------------------------------------------------
# Component calculators
# --------------------------------------------------------------------------
def severity_component(severity: str) -> RiskComponent:
    value = SEVERITY_WEIGHT.get(severity, 0.3)
    return _component("severity", value, f"Detection severity is {severity} (weight {value:.2f}).")


def confidence_component(confidence: float) -> RiskComponent:
    return _component(
        "confidence", confidence,
        f"Detection confidence {confidence:.0%}, derived from rule confidence and runtime signal strength.",
    )


def asset_component(criticalities: Sequence[int], *, privileged_user: bool = False) -> RiskComponent:
    if not criticalities:
        value = UNKNOWN_ASSET_WEIGHT
        detail = "No inventory record for the affected asset; default weight applied."
    else:
        top = max(criticalities)
        value = top / 5.0
        detail = f"Highest affected asset criticality is {top}/5."
    if privileged_user:
        value = min(1.0, value + 0.15)
        detail += " A privileged account is involved (+0.15)."
    return _component("asset", value, detail)


def behavioural_component(
    flags: Iterable[str],
    *,
    anomaly_score: float | None = None,
) -> RiskComponent:
    flag_list = sorted(set(flags))
    strongest = 0.0
    reasons: list[str] = []
    for flag in flag_list:
        weight, reason = BEHAVIOURAL_FLAGS.get(flag, (0.0, ""))
        if weight > strongest:
            strongest = weight
        if reason:
            reasons.append(reason)

    value = strongest
    if anomaly_score is not None:
        value = max(value, anomaly_score)
        reasons.insert(0, f"behavioural anomaly score {anomaly_score:.2f}")

    if not reasons:
        return _component("behavioural", 0.0, "No behavioural deviation indicators on the evidence.")
    # Report at most three reasons; the full set is on the evidence itself.
    return _component("behavioural", value, "Behavioural indicators: " + "; ".join(reasons[:3]) + ".")


def indicator_component(ioc_count: int, *, best_confidence: float = 0.0) -> RiskComponent:
    if ioc_count == 0:
        return _component("indicator", 0.0, "No threat-intelligence indicator matched this evidence.")
    value = min(1.0, best_confidence if best_confidence else 0.6)
    return _component(
        "indicator", value,
        f"{ioc_count} indicator match(es); highest feed confidence {value:.0%}.",
    )


def correlation_component(evidence_count: int, *, distinct_tactics: int = 0, alert_count: int = 1) -> RiskComponent:
    volume = math.log1p(max(0, evidence_count)) / math.log1p(CORRELATION_SATURATION)
    breadth = min(1.0, distinct_tactics / TACTIC_SATURATION) if distinct_tactics else 0.0
    # Volume alone is weak evidence of a campaign; breadth across kill-chain
    # stages is what distinguishes an intrusion from a noisy host.
    value = _clamp01(0.55 * volume + 0.45 * breadth)
    detail = f"{evidence_count} correlated event(s) across {alert_count} alert(s)"
    if distinct_tactics:
        detail += f" spanning {distinct_tactics} ATT&CK tactic(s)"
    return _component("correlation", value, detail + ".")


def combine(components: Sequence[RiskComponent]) -> RiskScore:
    total = sum(c.contribution for c in components)
    return RiskScore(score=round(min(100.0, max(0.0, total)), 1), components=list(components))


# --------------------------------------------------------------------------
# High-level entry points
# --------------------------------------------------------------------------
def score_alert(
    *,
    severity: str,
    confidence: float,
    asset_criticalities: Sequence[int],
    privileged_user: bool,
    behavioural_flags: Iterable[str],
    anomaly_score: float | None,
    ioc_count: int,
    ioc_confidence: float,
    evidence_count: int,
    distinct_tactics: int,
) -> RiskScore:
    return combine([
        severity_component(severity),
        confidence_component(confidence),
        asset_component(asset_criticalities, privileged_user=privileged_user),
        behavioural_component(behavioural_flags, anomaly_score=anomaly_score),
        indicator_component(ioc_count, best_confidence=ioc_confidence),
        correlation_component(evidence_count, distinct_tactics=distinct_tactics, alert_count=1),
    ])


def score_incident(
    *,
    severity: str,
    confidence: float,
    asset_criticalities: Sequence[int],
    privileged_user: bool,
    behavioural_flags: Iterable[str],
    anomaly_score: float | None,
    ioc_count: int,
    ioc_confidence: float,
    event_count: int,
    alert_count: int,
    distinct_tactics: int,
) -> RiskScore:
    return combine([
        severity_component(severity),
        confidence_component(confidence),
        asset_component(asset_criticalities, privileged_user=privileged_user),
        behavioural_component(behavioural_flags, anomaly_score=anomaly_score),
        indicator_component(ioc_count, best_confidence=ioc_confidence),
        correlation_component(event_count, distinct_tactics=distinct_tactics, alert_count=alert_count),
    ])


def collect_behavioural_flags(events: Iterable[Any]) -> list[str]:
    """Extract known behavioural flags from event metadata."""
    found: set[str] = set()
    for event in events:
        meta = getattr(event, "meta", None) or {}
        for flag in BEHAVIOURAL_FLAGS:
            if meta.get(flag):
                found.add(flag)
        if meta.get("argument_indicators"):
            found.add("sensitive_file" if "credential_file_access" in meta["argument_indicators"] else "elevated")
    return sorted(found)
