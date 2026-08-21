"""Match detector: one event, one condition, one alert.

The simplest rule type, and the right one whenever a single observation is itself
sufficient evidence — a new account created with UID 0, a CloudTrail
``StopLogging`` call, a file written to ``/etc/cron.d``.  No state, no window.
"""

from __future__ import annotations

from app.detection.conditions import matches
from app.detection.fields import describe_group, group_key, resolve
from app.detection.results import DetectionContext, DetectionResult, EvidenceRef, render_title
from app.detection.rules import RuleDefinition


def run(rule: RuleDefinition, ctx: DetectionContext) -> list[DetectionResult]:
    results: list[DetectionResult] = []

    for event in ctx.events:
        # Only fire on newly ingested telemetry: history is context, not a trigger.
        if ctx.new_event_ids and event.event_id not in ctx.new_event_ids:
            continue
        if not matches(event, rule.selection):
            continue

        # An ungrouped match rule is still grouped — by the event itself, which
        # is what makes its dedup key unique. The field list and the key are
        # derived together so they can never disagree in length; they did once,
        # and the title renderer quietly dropped every placeholder as a result.
        group_fields = rule.group_by or ["event_id"]
        key = group_key(event, rule.group_by) if rule.group_by else (event.event_id,)

        explanation = [_explain(rule, event)]
        if rule.group_by:
            explanation.append(f"Grouped by {describe_group(rule.group_by, key)}.")

        results.append(
            DetectionResult(
                rule_id=rule.id,
                rule_name=rule.name,
                rule_type=str(rule.type),
                severity=str(rule.severity),
                confidence=rule.confidence,
                title=render_title(rule, event, group_fields, key),
                explanation=explanation,
                evidence=[EvidenceRef(event=event, role="trigger")],
                detected_at=event.timestamp,
                first_event_at=event.timestamp,
                last_event_at=event.timestamp,
                group_fields=group_fields,
                group_key=key,
                technique_ids=list(rule.mitre.techniques),
                tactics=list(rule.mitre.tactics),
            )
        )
    return results


def _explain(rule: RuleDefinition, event) -> str:
    """Turn the rule's own selection into a sentence about this event.

    Written from the observed values rather than restating the rule text, so the
    analyst reads what happened, not what the rule looks for.
    """
    parts: list[str] = []
    for field_name in ("host", "user", "source_ip", "process", "file_path", "cloud_account"):
        value = resolve(event, field_name)
        if value:
            parts.append(f"{field_name}={value}")
    detail = ", ".join(parts) if parts else event.event_id
    return f"{rule.name}: matched {event.event_type}/{event.action or 'event'} ({detail})."
