"""Behavioural anomaly detectors.

Two rules govern this module.

**No unexplained verdicts.**  Every anomaly is a weighted sum of named factors,
and every factor that contributed produces a sentence an analyst can read and
disagree with.  "Risk 0.78" is not a detection; "logged in from an address this
account has never used, outside its observed 08:00-19:00 window, to a host it has
never touched" is.

**A single novel attribute is not an anomaly.**  The default factor threshold
requires at least two independent signals to agree.  Alerting on every new source
IP produces an unusable queue, which is the practical reason most "AI-powered"
anomaly detection gets switched off in real SOCs.

This is explicitly *statistical baselining*, not machine learning.  The platform
does not claim otherwise anywhere in the UI or the documentation.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from app.core.netutils import is_external
from app.detection.conditions import matches
from app.detection.results import DetectionContext, DetectionResult, EvidenceRef, render_title
from app.detection.rules import RuleDefinition
from app.models.enums import EventStatus, EventType, Severity
from app.models.events import Event


@dataclass(slots=True)
class Factor:
    name: str
    weight: float
    explanation: str


def _is_public(ip: str | None) -> bool:
    """External to the organisation. See app/core/netutils for why this is not
    ``ipaddress.is_private``."""
    return is_external(ip)


def _score(factors: list[Factor]) -> float:
    return round(min(1.0, sum(f.weight for f in factors)), 3)


def _severity_for(rule: RuleDefinition, score: float, escalate_at: float) -> str:
    """Escalate one band when the factor score is decisive."""
    if score < escalate_at:
        return str(rule.severity)
    order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    current = Severity(str(rule.severity))
    if current in order and order.index(current) < len(order) - 1:
        return str(order[order.index(current) + 1])
    return str(current)


def _is_off_hours(
    known_hours: dict[str, int],
    observation_count: int,
    hour: int,
    min_observations: int,
    params: dict[str, Any],
) -> bool:
    """Whether an hour falls outside an account's observed activity window.

    Two refinements over "this exact hour has never been seen", both of which the
    evaluation harness forced:

    *Range, not membership.* An account seen at 09:00 and 11:00 but never at
    10:00 is not behaving anomalously at 10:00. Comparing against the observed
    range catches 02:13 against a 09:00-18:00 pattern — the case that matters —
    without firing on gaps inside a normal working day.

    *Minimum hour coverage.* An account observed at only two distinct hours has
    not demonstrated a schedule, so "outside its hours" claims more than the data
    supports. Below the coverage threshold the factor stays silent.

    *Always-on accounts.* An identity already active across most of the day has
    no meaningful off-hours, so the factor is suppressed entirely.
    """
    if not known_hours or observation_count < min_observations:
        return False
    min_distinct = int(params.get("min_distinct_hours", 4))
    if len(known_hours) < min_distinct:
        return False

    observed = sorted(int(h) for h in known_hours)
    low, high = observed[0], observed[-1]
    max_span = int(params.get("max_active_span_hours", 18))
    if (high - low) > max_span:
        return False
    return not (low <= hour <= high)


def _build(
    rule: RuleDefinition,
    event: Event,
    factors: list[Factor],
    score: float,
    params: dict[str, Any],
    detector_name: str,
) -> DetectionResult:
    escalate_at = float(params.get("escalate_severity_at", 0.80))
    explanation = [
        f"Behavioural anomaly score {score:.2f} from {len(factors)} independent factor(s) "
        f"(threshold {float(params.get('threshold', 0.45)):.2f})."
    ] + [f.explanation for f in factors]

    return DetectionResult(
        rule_id=rule.id,
        rule_name=rule.name,
        rule_type=str(rule.type),
        severity=_severity_for(rule, score, escalate_at),
        confidence=round(min(0.95, 0.40 + score * 0.55), 3),
        title=render_title(rule, event, [], ()),
        explanation=explanation,
        evidence=[EvidenceRef(event=event, role="trigger")],
        detected_at=event.timestamp,
        first_event_at=event.timestamp,
        last_event_at=event.timestamp,
        group_fields=["user", "source_ip"],
        group_key=((event.user_ref or "").lower(), (event.source_ip or "").lower()),
        technique_ids=list(rule.mitre.techniques),
        tactics=list(rule.mitre.tactics),
        extra={
            "detector": detector_name,
            "anomaly_score": score,
            "factors": [{"name": f.name, "weight": f.weight, "reason": f.explanation} for f in factors],
        },
    )


# --------------------------------------------------------------------------
# Detector: anomalous authentication
# --------------------------------------------------------------------------
def anomalous_authentication(rule: RuleDefinition, ctx: DetectionContext) -> list[DetectionResult]:
    params = rule.anomaly.params if rule.anomaly else {}
    min_obs = int(params.get("min_observations", 8))
    threshold = float(params.get("threshold", 0.45))
    weights = {
        "new_source_ip": float(params.get("weight_new_source_ip", 0.30)),
        "external_source": float(params.get("weight_external_source", 0.25)),
        "off_hours": float(params.get("weight_off_hours", 0.25)),
        "new_host": float(params.get("weight_new_host", 0.20)),
    }

    results: list[DetectionResult] = []
    for event in ctx.events:
        if ctx.new_event_ids and event.event_id not in ctx.new_event_ids:
            continue
        if event.event_type != EventType.AUTHENTICATION or event.status != EventStatus.SUCCESS:
            continue
        if rule.selection and not matches(event, rule.selection):
            continue
        if not event.user_ref:
            continue

        ip_baseline, ip_count = ctx.baselines.get("user", event.user_ref, "source_ips")
        hour_baseline, hour_count = ctx.baselines.get("user", event.user_ref, "login_hours")
        host_baseline, host_count = ctx.baselines.get("user", event.user_ref, "hosts")

        # With too little history, "unusual" is meaningless — silence beats a
        # guess.  This is the single most important line in the module.
        if max(ip_count, hour_count, host_count) < min_obs:
            continue

        factors: list[Factor] = []
        known_ips: dict[str, int] = ip_baseline.get("ips", {}) if ip_baseline else {}
        known_hours: dict[str, int] = hour_baseline.get("hours", {}) if hour_baseline else {}
        known_hosts: dict[str, int] = host_baseline.get("hosts", {}) if host_baseline else {}

        if event.source_ip and ip_count >= min_obs and event.source_ip.lower() not in known_ips:
            factors.append(Factor(
                "new_source_ip", weights["new_source_ip"],
                f"Source address {event.source_ip} has not been seen for account '{event.user_ref}' "
                f"in {ip_count} prior authentications ({len(known_ips)} known address(es)).",
            ))
            if _is_public(event.source_ip) and known_ips and not any(_is_public(ip) for ip in known_ips):
                factors.append(Factor(
                    "external_source", weights["external_source"],
                    f"{event.source_ip} is a public address; every prior authentication for this "
                    "account originated from private address space.",
                ))

        if _is_off_hours(known_hours, hour_count, event.timestamp.hour, min_obs, params):
            observed = sorted(int(h) for h in known_hours)
            factors.append(Factor(
                "off_hours", weights["off_hours"],
                f"Authentication at {event.timestamp.strftime('%H:%M')} UTC falls outside this "
                f"account's observed activity window ({observed[0]:02d}:00-{observed[-1]:02d}:59 UTC, "
                f"{hour_count} observations across {len(observed)} distinct hours).",
            ))

        if event.host_ref and host_count >= min_obs and event.host_ref.lower() not in known_hosts:
            factors.append(Factor(
                "new_host", weights["new_host"],
                f"Account '{event.user_ref}' has not authenticated to {event.host_ref} before "
                f"({len(known_hosts)} host(s) in baseline).",
            ))

        score = _score(factors)
        if score >= threshold and factors:
            results.append(_build(rule, event, factors, score, params, "anomalous_authentication"))
    return results


# --------------------------------------------------------------------------
# Detector: unusual cloud API activity for an identity
# --------------------------------------------------------------------------
def unusual_cloud_api_for_identity(rule: RuleDefinition, ctx: DetectionContext) -> list[DetectionResult]:
    params = rule.anomaly.params if rule.anomaly else {}
    min_obs = int(params.get("min_observations", 10))
    threshold = float(params.get("threshold", 0.50))
    weights = {
        "new_api": float(params.get("weight_new_api", 0.35)),
        "high_risk_api": float(params.get("weight_high_risk_api", 0.30)),
        "off_hours": float(params.get("weight_off_hours", 0.20)),
        "new_source_ip": float(params.get("weight_new_source_ip", 0.20)),
        "no_mfa": float(params.get("weight_no_mfa", 0.15)),
    }

    results: list[DetectionResult] = []
    for event in ctx.events:
        if ctx.new_event_ids and event.event_id not in ctx.new_event_ids:
            continue
        if not event.cloud_account or not event.user_ref:
            continue
        if rule.selection and not matches(event, rule.selection):
            continue

        api_baseline, api_count = ctx.baselines.get("user", event.user_ref, "cloud_apis")
        hour_baseline, hour_count = ctx.baselines.get("user", event.user_ref, "cloud_hours")
        ip_baseline, ip_count = ctx.baselines.get("user", event.user_ref, "source_ips")

        if api_count < min_obs:
            continue

        meta = event.meta or {}
        known_apis: dict[str, int] = api_baseline.get("apis", {}) if api_baseline else {}
        known_hours: dict[str, int] = hour_baseline.get("hours", {}) if hour_baseline else {}
        known_ips: dict[str, int] = ip_baseline.get("ips", {}) if ip_baseline else {}

        factors: list[Factor] = []
        api = (event.action or "").lower()

        if api and api not in known_apis:
            factors.append(Factor(
                "new_api", weights["new_api"],
                f"Identity '{event.user_ref}' has never called {event.action} in "
                f"{api_count} prior control-plane operations ({len(known_apis)} distinct APIs).",
            ))

        if meta.get("iam_risk") in {"high", "critical"}:
            factors.append(Factor(
                "high_risk_api", weights["high_risk_api"],
                f"{event.action} is classified {meta['iam_risk']} risk "
                f"(category: {meta.get('iam_category', 'unknown')}).",
            ))
            if meta.get("high_risk_policy"):
                factors.append(Factor(
                    "admin_policy", 0.10,
                    f"The operation references a high-privilege policy: {meta.get('policy')}.",
                ))

        if _is_off_hours(known_hours, hour_count, event.timestamp.hour, min_obs, params):
            observed = sorted(int(h) for h in known_hours)
            factors.append(Factor(
                "off_hours", weights["off_hours"],
                f"Call made at {event.timestamp.strftime('%H:%M')} UTC, outside this identity's "
                f"observed window ({observed[0]:02d}:00-{observed[-1]:02d}:59 UTC).",
            ))

        if event.source_ip and known_ips and event.source_ip.lower() not in known_ips:
            factors.append(Factor(
                "new_source_ip", weights["new_source_ip"],
                f"Originating address {event.source_ip} is not in this identity's baseline "
                f"({len(known_ips)} known address(es)).",
            ))

        if meta.get("mfa_authenticated") is False:
            factors.append(Factor(
                "no_mfa", weights["no_mfa"],
                "The session was not MFA-authenticated.",
            ))

        score = _score(factors)
        if score >= threshold and factors:
            results.append(_build(rule, event, factors, score, params, "unusual_cloud_api_for_identity"))
    return results


#: Named detectors a rule may reference.  A rule can only *select* from this map;
#: it can never supply an import path or executable content.
ANOMALY_DETECTORS: dict[str, Callable[[RuleDefinition, DetectionContext], list[DetectionResult]]] = {
    "anomalous_authentication": anomalous_authentication,
    "unusual_cloud_api_for_identity": unusual_cloud_api_for_identity,
}


def run(rule: RuleDefinition, ctx: DetectionContext) -> list[DetectionResult]:
    if rule.anomaly is None:
        return []
    detector = ANOMALY_DETECTORS.get(rule.anomaly.detector)
    if detector is None:
        return []
    return detector(rule, ctx)
