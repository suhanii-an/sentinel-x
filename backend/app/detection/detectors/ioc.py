"""IOC detector: known-bad value matching.

Indicator matching is the cheapest detection there is and the least durable —
attackers rotate infrastructure faster than feeds update.  It earns its place as
*corroboration*: an IOC hit alongside behavioural detections raises confidence in
the incident, and on its own it is a lead rather than a conclusion.  That is why
IOC alerts carry the indicator's own confidence rather than the rule's.
"""

from __future__ import annotations

from app.detection.conditions import matches
from app.detection.fields import resolve
from app.detection.results import DetectionContext, DetectionResult, EvidenceRef, render_title
from app.detection.rules import RuleDefinition

#: Which indicator type a given event field can carry.
FIELD_IOC_TYPES: dict[str, str] = {
    "source_ip": "ip",
    "destination_ip": "ip",
    "file_hash": "hash",
    "host": "hostname",
    "host_id": "hostname",
    "user": "username",
    "user_id": "username",
    "cloud_resource": "url",
    "file_path": "url",
}


def run(rule: RuleDefinition, ctx: DetectionContext) -> list[DetectionResult]:
    spec = rule.ioc
    if spec is None or not ctx.iocs.by_type_value:
        return []

    allowed_types = set(spec.types) if spec.types else None
    results: list[DetectionResult] = []

    for event in ctx.events:
        if ctx.new_event_ids and event.event_id not in ctx.new_event_ids:
            continue
        if rule.selection and not matches(event, rule.selection):
            continue

        for field_name in spec.fields:
            ioc_type = FIELD_IOC_TYPES.get(field_name)
            if ioc_type is None or (allowed_types and ioc_type not in allowed_types):
                continue
            value = resolve(event, field_name)
            record = ctx.iocs.lookup(ioc_type, value)
            if record is None:
                continue

            explanation = [
                f"Event field {field_name}={value} matches known indicator "
                f"{record['ioc_id']} ({record['ioc_type']}).",
                f"Indicator source: {record['source']}; feed confidence {record['confidence']:.0%}.",
            ]
            if record.get("description"):
                explanation.append(str(record["description"]))
            if record.get("tags"):
                explanation.append(f"Indicator tags: {', '.join(record['tags'])}.")

            results.append(
                DetectionResult(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    rule_type=str(rule.type),
                    # Severity and confidence come from the indicator itself: a
                    # low-confidence feed hit must not present as a certainty.
                    severity=record.get("severity") or str(rule.severity),
                    confidence=round(min(0.99, float(record["confidence"]) * rule.confidence + 0.1), 3),
                    title=render_title(rule, event, [], ()) if rule.title_template
                    else f"Known indicator observed: {value}",
                    explanation=explanation,
                    evidence=[EvidenceRef(event=event, role="trigger")],
                    detected_at=event.timestamp,
                    first_event_at=event.timestamp,
                    last_event_at=event.timestamp,
                    group_fields=[field_name],
                    group_key=(str(value).lower(),),
                    technique_ids=list(rule.mitre.techniques),
                    tactics=list(rule.mitre.tactics),
                    extra={
                        "ioc_id": record["ioc_id"],
                        "ioc_type": record["ioc_type"],
                        "ioc_value": record["indicator"],
                        "matched_field": field_name,
                        "ioc_pk": record["pk"],
                    },
                )
            )
    return results
