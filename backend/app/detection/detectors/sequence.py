"""Sequence detector: ordered behaviour, not isolated events.

This is where detection stops being log-matching and starts describing attacks.
Five failed logins are noise.  Five failed logins *followed by a success from the
same source* is a successful brute force, and only a rule that understands order
can say so.

Matching is greedy from each viable anchor.  Greedy is the right trade here: a
sequence rule needs to answer "did this pattern occur?", not "what is the optimal
assignment of events to steps", and the anchor loop already recovers the cases
where an early greedy choice would have been wrong.
"""

from __future__ import annotations

from collections import defaultdict

from app.detection.conditions import matches
from app.detection.fields import describe_group, group_key, resolve
from app.detection.results import DetectionContext, DetectionResult, EvidenceRef, render_title
from app.detection.rules import RuleDefinition, SequenceStep
from app.models.events import Event

#: Bound on anchor attempts per group.  Prevents a pathological group (one entity
#: with tens of thousands of matching events) from dominating a detection pass.
MAX_ANCHORS = 200


def run(rule: RuleDefinition, ctx: DetectionContext) -> list[DetectionResult]:
    if len(rule.steps) < 2 or not rule.window_seconds:
        return []

    groups: dict[tuple, list[Event]] = defaultdict(list)
    for event in ctx.events:
        groups[group_key(event, rule.group_by)].append(event)

    results: list[DetectionResult] = []
    for key, events in groups.items():
        events.sort(key=lambda e: e.timestamp)
        matched = _match_sequence(events, rule.steps, rule.window_seconds, rule)
        if matched is None:
            continue

        all_events = [ev for _, step_events in matched for ev in step_events]
        if ctx.new_event_ids and not any(e.event_id in ctx.new_event_ids for e in all_events):
            continue

        first = all_events[0].timestamp
        last = all_events[-1].timestamp
        span = max(1, int((last - first).total_seconds()))

        chain = " -> ".join(f"{name} (x{len(evts)})" for name, evts in matched)
        explanation = [
            f"Observed ordered sequence for {describe_group(rule.group_by, key)}: {chain}.",
            f"Complete sequence spanned {span}s (window: {rule.window_seconds}s), "
            f"{first.isoformat()} to {last.isoformat()}.",
        ]
        for name, evts in matched:
            sample = evts[0]
            explanation.append(
                f"Step '{name}': {len(evts)} event(s), first at {sample.timestamp.isoformat()} "
                f"({sample.event_type}/{sample.action or 'event'} on {sample.host_ref or sample.cloud_account or 'n/a'})."
            )

        # A tighter sequence is stronger evidence of a single automated actor
        # than one spread across the whole permitted window.
        tightness = 1.0 - min(1.0, span / rule.window_seconds)
        confidence = min(0.99, rule.confidence + 0.10 * tightness)

        results.append(
            DetectionResult(
                rule_id=rule.id,
                rule_name=rule.name,
                rule_type=str(rule.type),
                severity=str(rule.severity),
                confidence=round(confidence, 3),
                title=render_title(rule, all_events[-1], rule.group_by, key),
                explanation=explanation,
                evidence=[
                    EvidenceRef(event=ev, role="trigger", step=name)
                    for name, evts in matched
                    for ev in evts
                ],
                detected_at=last,
                first_event_at=first,
                last_event_at=last,
                group_fields=list(rule.group_by),
                group_key=key,
                technique_ids=list(rule.mitre.techniques),
                tactics=list(rule.mitre.tactics),
                extra={
                    "steps": [{"name": name, "count": len(evts)} for name, evts in matched],
                    "span_seconds": span,
                },
            )
        )
    return results


def _match_sequence(
    events: list[Event],
    steps: list[SequenceStep],
    window_seconds: int,
    rule: RuleDefinition,
) -> list[tuple[str, list[Event]]] | None:
    """Find the first complete ordered match satisfying the rule's constraints."""
    first_step = steps[0]
    anchors = [i for i, e in enumerate(events) if matches(e, first_step.selection)][:MAX_ANCHORS]

    for anchor in anchors:
        attempt = _attempt_from(events, anchor, steps, window_seconds)
        if attempt is not None and _satisfies_constraints(attempt, rule):
            return attempt
    return None


def _satisfies_constraints(matched: list[tuple[str, list[Event]]], rule: RuleDefinition) -> bool:
    """Apply cross-step requirements the per-event conditions cannot express."""
    if not rule.constraints:
        return True
    all_events = [ev for _, evts in matched for ev in evts]
    for constraint in rule.constraints:
        values = {
            str(resolve(ev, constraint.distinct_field)).lower()
            for ev in all_events
            if resolve(ev, constraint.distinct_field) is not None
        }
        if len(values) < constraint.min_distinct:
            return False
    return True


def _attempt_from(
    events: list[Event],
    anchor: int,
    steps: list[SequenceStep],
    window_seconds: int,
) -> list[tuple[str, list[Event]]] | None:
    start_time = events[anchor].timestamp
    cursor = anchor
    previous_time = start_time
    matched: list[tuple[str, list[Event]]] = []

    for index, step in enumerate(steps):
        collected: list[Event] = []
        scan = cursor if index == 0 else cursor + 1
        gap_limit = step.max_gap_seconds

        for position in range(scan, len(events)):
            event = events[position]
            if (event.timestamp - start_time).total_seconds() > window_seconds:
                break
            if not matches(event, step.selection):
                continue
            if gap_limit is not None and (event.timestamp - previous_time).total_seconds() > gap_limit:
                break
            collected.append(event)
            cursor = position
            if len(collected) >= step.min_count:
                break

        if len(collected) < step.min_count:
            if step.optional:
                continue
            return None

        previous_time = collected[-1].timestamp
        matched.append((step.name, collected))

    # Guard against a rule whose required steps were all optional-skipped.
    if not matched:
        return None
    return _expand_evidence(events, matched, steps, start_time, window_seconds)


def _expand_evidence(
    events: list[Event],
    matched: list[tuple[str, list[Event]]],
    steps: list[SequenceStep],
    start_time,
    window_seconds: int,
) -> list[tuple[str, list[Event]]]:
    """Attach every event belonging to a step, not just the minimum required.

    Greedy matching stops as soon as a step is satisfied, which is correct for
    deciding *whether* the sequence occurred and wrong for presenting it. If nine
    authentication failures preceded the success, the analyst needs all nine on
    the alert — the four that happened to satisfy ``min_count`` are not the
    finding, they are an implementation detail of the matcher.

    Each step claims matching events up to the moment the next step began, so no
    event is attributed to two stages.
    """
    if not matched:
        return matched

    step_by_name = {step.name: step for step in steps}
    boundaries = []
    for index, (name, step_events) in enumerate(matched):
        step_start = step_events[0].timestamp
        next_start = matched[index + 1][1][0].timestamp if index + 1 < len(matched) else None
        boundaries.append((name, step_start, next_start, step_events[-1].timestamp))

    expanded: list[tuple[str, list[Event]]] = []
    claimed: set[int] = set()

    for index, (name, step_start, next_start, step_last) in enumerate(boundaries):
        step = step_by_name[name]
        collected: list[Event] = []
        for event in events:
            if id(event) in claimed or event.timestamp < step_start:
                continue
            if (event.timestamp - start_time).total_seconds() > window_seconds:
                break
            if next_start is not None and event.timestamp >= next_start:
                break
            if next_start is None and event.timestamp > step_last:
                break
            if matches(event, step.selection):
                collected.append(event)
                claimed.add(id(event))
        expanded.append((name, collected or matched[index][1]))

    return expanded
