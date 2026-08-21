"""Threshold detector: "N of these, from the same entity, within T seconds".

The workhorse of authentication monitoring.  Two design decisions matter:

*Grouping is mandatory.*  An ungrouped threshold counts unrelated activity across
the whole estate and fires constantly.  The rule schema rejects it.

*Optional distinctness.*  ``distinct_field``/``distinct_count`` separates
credential *stuffing* (many failures, many accounts, one source) from a user who
simply mistyped their password eight times.  Same event count, different attack,
different rule.
"""

from __future__ import annotations

from collections import defaultdict

from app.detection.conditions import matches
from app.detection.fields import describe_group, group_key, resolve
from app.detection.results import DetectionContext, DetectionResult, EvidenceRef, render_title
from app.detection.rules import RuleDefinition
from app.models.events import Event


def run(rule: RuleDefinition, ctx: DetectionContext) -> list[DetectionResult]:
    spec = rule.threshold
    if spec is None:
        return []

    groups: dict[tuple, list[Event]] = defaultdict(list)
    for event in ctx.events:
        if matches(event, rule.selection):
            groups[group_key(event, rule.group_by)].append(event)

    results: list[DetectionResult] = []
    for key, events in groups.items():
        events.sort(key=lambda e: e.timestamp)
        window = _find_window(events, spec.count, spec.window_seconds, spec.distinct_field, spec.distinct_count)
        if window is None:
            continue

        # A window made entirely of previously-seen events was already alerted
        # on during an earlier ingestion; re-firing would double-count.
        if ctx.new_event_ids and not any(e.event_id in ctx.new_event_ids for e in window):
            continue

        first, last = window[0].timestamp, window[-1].timestamp
        span = max(1, int((last - first).total_seconds()))
        trigger = window[-1]

        explanation = [
            f"{len(window)} matching {trigger.event_type} events for {describe_group(rule.group_by, key)} "
            f"within {span}s (threshold: {spec.count} in {spec.window_seconds}s).",
            f"Window: {first.isoformat()} to {last.isoformat()}.",
        ]
        if spec.distinct_field:
            distinct = _distinct_values(window, spec.distinct_field)
            explanation.append(
                f"Spanned {len(distinct)} distinct values of {spec.distinct_field} "
                f"(required: {spec.distinct_count}): {', '.join(sorted(str(d) for d in distinct)[:8])}."
            )

        # Volume above the threshold is genuine additional signal, but it is
        # bounded so one noisy window cannot manufacture certainty.
        overshoot = min(0.15, 0.03 * (len(window) - spec.count))
        confidence = min(0.99, rule.confidence + max(0.0, overshoot))

        results.append(
            DetectionResult(
                rule_id=rule.id,
                rule_name=rule.name,
                rule_type=str(rule.type),
                severity=str(rule.severity),
                confidence=round(confidence, 3),
                title=render_title(rule, trigger, rule.group_by, key),
                explanation=explanation,
                evidence=[EvidenceRef(event=e, role="trigger") for e in window],
                detected_at=last,
                first_event_at=first,
                last_event_at=last,
                group_fields=list(rule.group_by),
                group_key=key,
                technique_ids=list(rule.mitre.techniques),
                tactics=list(rule.mitre.tactics),
                extra={"match_count": len(window), "threshold": spec.count, "window_seconds": spec.window_seconds},
            )
        )
    return results


def _distinct_values(events: list[Event], field_name: str) -> set:
    values = set()
    for event in events:
        value = resolve(event, field_name)
        if value is not None:
            values.add(str(value).lower())
    return values


def _find_window(
    events: list[Event],
    count: int,
    window_seconds: int,
    distinct_field: str | None,
    distinct_count: int | None,
) -> list[Event] | None:
    """Earliest time window satisfying both the count and distinctness criteria.

    Two-pointer scan over timestamp-sorted events: O(n) rather than O(n^2), which
    matters because this runs once per rule per group on every ingestion.
    """
    if len(events) < count:
        return None

    left = 0
    for right in range(len(events)):
        while (events[right].timestamp - events[left].timestamp).total_seconds() > window_seconds:
            left += 1
        window = events[left : right + 1]
        if len(window) < count:
            continue
        if (
            distinct_field
            and distinct_count
            and len(_distinct_values(window, distinct_field)) < distinct_count
        ):
            continue

        # The threshold is satisfied. Extend the window to every remaining event
        # that still falls inside it, rather than stopping at the minimum needed.
        # Eleven failed logins in one window is one alert carrying eleven pieces
        # of evidence, not an alert carrying the first five - and an analyst who
        # sees five when eleven occurred is working from an incomplete picture.
        end = right
        while (
            end + 1 < len(events)
            and (events[end + 1].timestamp - events[left].timestamp).total_seconds() <= window_seconds
        ):
            end += 1
        return events[left : end + 1]
    return None
