"""Detection results and the context detectors run against.

Detectors never touch the database.  Everything they need — the candidate events,
the IOC index, the behavioural baselines — is assembled by the engine and handed
over as plain data.  That keeps every detector unit-testable with three lines of
setup and, more importantly, makes detection deterministic: the same inputs
always produce the same result, which is a precondition for meaningful
evaluation.
"""

from __future__ import annotations

import datetime as dt
import hashlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from app.detection.fields import resolve
from app.models.events import Event

if TYPE_CHECKING:
    from app.detection.rules import RuleDefinition


@dataclass(slots=True)
class EvidenceRef:
    """One event supporting a detection."""

    event: Event
    role: str = "trigger"       # trigger | context
    step: str | None = None      # sequence step name, when applicable


@dataclass(slots=True)
class IOCIndex:
    """Lookup of active indicators, keyed by (type, lowercased value)."""

    by_type_value: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)

    def lookup(self, ioc_type: str, value: Any) -> dict[str, Any] | None:
        if value is None:
            return None
        return self.by_type_value.get((ioc_type, str(value).strip().lower()))

    def __len__(self) -> int:  # pragma: no cover
        return len(self.by_type_value)


@dataclass(slots=True)
class BaselineSnapshot:
    """Behavioural baselines, keyed by (entity_type, entity_ref, feature)."""

    entries: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)
    counts: dict[tuple[str, str, str], int] = field(default_factory=dict)

    def get(self, entity_type: str, entity_ref: str | None, feature: str) -> tuple[dict[str, Any], int]:
        if not entity_ref:
            return {}, 0
        key = (entity_type, entity_ref.lower(), feature)
        return self.entries.get(key, {}), self.counts.get(key, 0)


@dataclass(slots=True)
class DetectionContext:
    """Everything a detector is allowed to see."""

    events: list[Event]
    now: dt.datetime
    iocs: IOCIndex = field(default_factory=IOCIndex)
    baselines: BaselineSnapshot = field(default_factory=BaselineSnapshot)
    #: Public event IDs from the batch currently being ingested.  A stateful rule
    #: may look back over history, but it must only *fire* on something new —
    #: otherwise every ingestion re-detects the whole database.
    new_event_ids: set[str] = field(default_factory=set)


@dataclass(slots=True)
class DetectionResult:
    rule_id: str
    rule_name: str
    rule_type: str
    severity: str
    confidence: float
    title: str
    explanation: list[str]
    evidence: list[EvidenceRef]
    detected_at: dt.datetime
    first_event_at: dt.datetime
    last_event_at: dt.datetime
    group_fields: list[str]
    group_key: tuple
    technique_ids: list[str]
    tactics: list[str]
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def trigger_events(self) -> list[Event]:
        return [e.event for e in self.evidence if e.role == "trigger"]

    @property
    def entity_keys(self) -> list[str]:
        keys: set[str] = set()
        for ref in self.evidence:
            event = ref.event
            if event.host_ref:
                keys.add(f"host:{event.host_ref}")
            if event.user_ref:
                keys.add(f"user:{event.user_ref}")
            if event.source_ip:
                keys.add(f"ip:{event.source_ip}")
            if event.destination_ip:
                keys.add(f"ip:{event.destination_ip}")
            if event.cloud_account:
                keys.add(f"cloud:{event.cloud_account}")
        return sorted(keys)

    def dedup_key(self, *, bucket_seconds: int) -> str:
        """Stable identity for "this detection, on this entity, in this period".

        Bucketing the timestamp means a brute-force attack that continues for an
        hour produces a handful of alerts rather than one per event, without
        suppressing a genuinely new occurrence tomorrow.
        """
        bucket = 0
        if bucket_seconds > 0:
            bucket = int(self.detected_at.timestamp() // bucket_seconds)
        payload = f"{self.rule_id}|{'|'.join(str(k) for k in self.group_key)}|{bucket}"
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]
        return f"{self.rule_id}:{digest}"

    def primary_event(self) -> Event:
        triggers = self.trigger_events
        return triggers[-1] if triggers else self.evidence[-1].event


class _SafeFormat(dict):
    """``format_map`` helper: unknown placeholders render as ``(unknown)``
    instead of raising, so a rule typo degrades a title rather than losing the
    alert entirely."""

    def __missing__(self, key: str) -> str:  # pragma: no cover - trivial
        return "(unknown)"


def render_title(rule: RuleDefinition, event: Event, group_fields: list[str], group_key: tuple) -> str:
    if not rule.title_template:
        return rule.name
    values = _SafeFormat()
    # Group-key values first, then the triggering event's own values, which take
    # precedence: group keys are case-normalised for matching, and a title
    # reading "linux-03" when the host is named "LINUX-03" looks like a bug.
    for field_name, key_value in zip(group_fields, group_key, strict=True):
        values[field_name.replace("metadata.", "")] = key_value if key_value is not None else "(unknown)"
    for name in ("host", "user", "source_ip", "destination_ip", "process", "action",
                 "status", "event_type", "cloud_account", "cloud_service", "file_path"):
        value = resolve(event, name)
        if value is not None:
            values[name] = value
        elif name not in values:
            values[name] = "(unknown)"
    try:
        return rule.title_template.format_map(values)[:255]
    except (ValueError, IndexError):
        return rule.name
