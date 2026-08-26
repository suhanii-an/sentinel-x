"""The hunt query language.

This module exists to make one guarantee: **no caller — analyst, API client or
language model — can express a database query that this schema does not
describe.**

A hunt is a validated document, not a string.  Field names are checked against an
allow-list, operators against a fixed set, and values against per-field type
rules.  The query builder then constructs a parameterised SQLAlchemy statement
from that document.  There is no code path anywhere in SENTINEL-X that
concatenates caller-supplied text into SQL, and the natural-language interface is
deliberately built on top of *this* type rather than beside it:

    natural language -> HuntQuery (validated) -> safe builder -> database

not

    natural language -> SQL -> database

The second form is what makes "AI-powered SIEM search" features dangerous, and
avoiding it costs nothing in capability.
"""

from __future__ import annotations

import datetime as dt
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.timeutils import parse_timestamp, utcnow

Dataset = Literal["events", "alerts", "incidents"]

#: Queryable fields per dataset.  Anything absent is unqueryable by construction.
ALLOWED_FIELDS: dict[str, set[str]] = {
    "events": {
        "event_id", "timestamp", "event_type", "source", "host", "user",
        "source_ip", "destination_ip", "destination_port", "protocol", "bytes_out",
        "process", "process_id", "parent_process", "command_line", "file_path",
        "file_hash", "cloud_provider", "cloud_account", "cloud_service",
        "cloud_resource", "cloud_region", "action", "status", "message",
        "label", "label_scenario", "is_demo",
    },
    "alerts": {
        "alert_id", "detected_at", "created_at", "rule_id", "rule_type", "severity",
        "status", "confidence", "risk_score", "host", "user", "source_ip", "title",
        "technique_id", "is_demo",
    },
    "incidents": {
        "incident_id", "first_seen", "last_seen", "severity", "status",
        "confidence", "risk_score", "title", "technique_id", "host", "user",
        "source_ip", "is_demo",
    },
}

#: Fields whose values are timestamps.
TIME_FIELDS = {"timestamp", "detected_at", "created_at", "first_seen", "last_seen"}
NUMERIC_FIELDS = {
    "destination_port", "bytes_out", "process_id", "confidence", "risk_score",
}
BOOLEAN_FIELDS = {"is_demo"}

OPERATORS = {
    "eq", "ne", "in", "not_in", "contains", "not_contains",
    "startswith", "endswith", "gt", "gte", "lt", "lte", "exists",
}

#: Operators that are meaningless (and misleading) on non-text columns.
TEXT_ONLY_OPERATORS = {"contains", "not_contains", "startswith", "endswith"}

MAX_FILTERS = 20
MAX_IN_VALUES = 100
MAX_LIMIT = 1000
MAX_VALUE_LENGTH = 512


#: (dataset, field) pairs stored as JSON arrays. Queryable by containment,
#: not orderable. Mirrors JSON_ARRAY_FIELDS in the builder; kept here as plain
#: data so the DSL does not import the builder.
UNSORTABLE_FIELDS = {
    ("alerts", "technique_id"),
    ("incidents", "technique_id"),
    ("incidents", "host"),
    ("incidents", "user"),
    ("incidents", "source_ip"),
}


def _coerce_one(value: Any, field: str) -> Any:
    """Convert one filter value to the type its column actually holds."""
    if field in TIME_FIELDS:
        if isinstance(value, dt.datetime):
            return value
        return parse_timestamp(str(value))
    if field in NUMERIC_FIELDS:
        if isinstance(value, bool):
            raise ValueError("a boolean is not a number")
        if isinstance(value, (int, float)):
            return value
        text = str(value).strip()
        return float(text) if ("." in text or "e" in text.lower()) else int(text)
    if field in BOOLEAN_FIELDS:
        if isinstance(value, bool):
            return value
        text = str(value).strip().lower()
        if text in {"true", "1", "yes"}:
            return True
        if text in {"false", "0", "no"}:
            return False
        raise ValueError(f"'{value}' is not a boolean")
    return value


def _coerce_value(item: HuntFilter, field: str, where: str) -> None:
    """Coerce a filter's value in place, or refuse the query.

    Without this a perfectly valid-looking query — ``timestamp gt
    "2026-01-01T00:00:00Z"`` — validates, reaches the database as a string, and
    comes back as a 500 from the driver. The UI offers every field and every
    operator, so any analyst could trip it. Values are typed here, at the
    validation boundary, so a bad one is a 400 that says which field and why.
    """
    if item.operator == "exists" or field not in (TIME_FIELDS | NUMERIC_FIELDS | BOOLEAN_FIELDS):
        return
    try:
        if isinstance(item.value, list):
            item.value = [_coerce_one(v, field) for v in item.value]
        else:
            item.value = _coerce_one(item.value, field)
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"{where}: value {item.value!r} is not valid for field '{field}' ({exc})"
        ) from None


class HuntFilter(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: str = Field(max_length=128)
    operator: str = "eq"
    value: Any = None

    @field_validator("operator")
    @classmethod
    def _known_operator(cls, v: str) -> str:
        if v not in OPERATORS:
            raise ValueError(f"unsupported operator '{v}' (supported: {', '.join(sorted(OPERATORS))})")
        return v

    @model_validator(mode="after")
    def _check_value(self) -> HuntFilter:
        if self.operator == "exists":
            self.value = bool(self.value) if self.value is not None else True
            return self

        if self.operator in {"in", "not_in"}:
            if not isinstance(self.value, list):
                raise ValueError(f"operator '{self.operator}' requires a list value")
            if not self.value:
                raise ValueError(f"operator '{self.operator}' requires a non-empty list")
            if len(self.value) > MAX_IN_VALUES:
                raise ValueError(f"'{self.operator}' accepts at most {MAX_IN_VALUES} values")
        elif self.value is None:
            raise ValueError(f"operator '{self.operator}' requires a value")

        for item in (self.value if isinstance(self.value, list) else [self.value]):
            if isinstance(item, str) and len(item) > MAX_VALUE_LENGTH:
                raise ValueError(f"filter values are limited to {MAX_VALUE_LENGTH} characters")
        return self


class TimeRange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    start: dt.datetime | None = None
    end: dt.datetime | None = None
    #: Convenience form: "last N minutes/hours/days" relative to now.
    last_minutes: int | None = Field(default=None, ge=1, le=60 * 24 * 365)

    @field_validator("start", "end", mode="before")
    @classmethod
    def _parse(cls, v: Any) -> Any:
        return parse_timestamp(v) if isinstance(v, str) else v

    @model_validator(mode="after")
    def _resolve(self) -> TimeRange:
        if self.last_minutes is not None:
            self.end = self.end or utcnow()
            self.start = self.end - dt.timedelta(minutes=self.last_minutes)
        if self.start and self.end and self.start > self.end:
            raise ValueError("time range start must be before end")
        return self


class HuntStep(BaseModel):
    """One stage of a sequence hunt."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64)
    filters: list[HuntFilter] = Field(default_factory=list, max_length=MAX_FILTERS)
    min_count: int = Field(default=1, ge=1, le=1000)


class SequenceHunt(BaseModel):
    """Ordered multi-stage hunt, correlated on entity fields.

    This is what makes the hunt interface useful rather than a search box:
    "failed logins followed by a successful login from the same source" is a
    question about *order*, and no amount of field filtering can express it.
    """

    model_config = ConfigDict(extra="forbid")

    steps: list[HuntStep] = Field(min_length=2, max_length=5)
    within_seconds: int = Field(default=900, ge=1, le=86_400)
    #: Entity fields the stages must agree on.
    correlate_on: list[str] = Field(default_factory=lambda: ["source_ip"], max_length=3)

    @field_validator("correlate_on")
    @classmethod
    def _correlatable(cls, v: list[str]) -> list[str]:
        allowed = {"host", "user", "source_ip", "destination_ip", "cloud_account", "process"}
        for field_name in v:
            if field_name not in allowed:
                raise ValueError(
                    f"cannot correlate on '{field_name}' (allowed: {', '.join(sorted(allowed))})"
                )
        if not v:
            raise ValueError("a sequence hunt must correlate on at least one field")
        return v


class HuntQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dataset: Dataset = "events"
    filters: list[HuntFilter] = Field(default_factory=list, max_length=MAX_FILTERS)
    logic: Literal["and", "or"] = "and"
    time_range: TimeRange | None = None
    sequence: SequenceHunt | None = None

    order_by: str | None = None
    order: Literal["asc", "desc"] = "desc"
    limit: Annotated[int, Field(ge=1, le=MAX_LIMIT)] = 100
    offset: Annotated[int, Field(ge=0, le=100_000)] = 0

    #: Free-text description, carried through for display and audit.  Never used
    #: to build the query.
    description: str = Field(default="", max_length=500)

    @model_validator(mode="after")
    def _validate_fields(self) -> HuntQuery:
        allowed = ALLOWED_FIELDS[self.dataset]

        def check(filters: list[HuntFilter], where: str) -> None:
            for item in filters:
                name = item.field
                if name.startswith("metadata."):
                    if self.dataset != "events":
                        raise ValueError(f"{where}: metadata filters are only available on events")
                    key = name.split(".", 1)[1]
                    if not key or not key.replace("_", "").replace("-", "").isalnum():
                        raise ValueError(f"{where}: invalid metadata key '{key}'")
                    continue
                if name not in allowed:
                    raise ValueError(
                        f"{where}: '{name}' is not queryable on {self.dataset}. "
                        f"Available: {', '.join(sorted(allowed))}"
                    )
                if item.operator in TEXT_ONLY_OPERATORS and name in (TIME_FIELDS | NUMERIC_FIELDS | BOOLEAN_FIELDS):
                    raise ValueError(
                        f"{where}: operator '{item.operator}' cannot be applied to non-text field '{name}'"
                    )
                _coerce_value(item, name, where)

        check(self.filters, "filters")
        if self.sequence:
            if self.dataset != "events":
                raise ValueError("sequence hunts are only supported on the events dataset")
            for step in self.sequence.steps:
                check(step.filters, f"sequence step '{step.name}'")
            for field_name in self.sequence.correlate_on:
                if field_name not in allowed:
                    raise ValueError(f"cannot correlate on '{field_name}' for dataset {self.dataset}")

        if self.order_by is not None:
            if self.order_by not in allowed:
                raise ValueError(f"cannot order by '{self.order_by}' on {self.dataset}")
            # Some queryable fields are stored as JSON arrays and are matched by
            # containment rather than compared. Sorting by one is not
            # expressible, and letting the validator accept what the builder
            # then refuses produces a 400 that contradicts the validator which
            # just approved it.
            if (self.dataset, self.order_by) in UNSORTABLE_FIELDS:
                raise ValueError(
                    f"'{self.order_by}' is stored as a list on {self.dataset} and cannot be "
                    "sorted on. Order by a scalar field instead."
                )

        if self.order_by is None:
            self.order_by = {
                "events": "timestamp",
                "alerts": "detected_at",
                "incidents": "last_seen",
            }[self.dataset]
        return self

    def describe(self) -> str:
        """Plain-language rendering of the query, shown back to the analyst.

        Important for the natural-language path: the analyst must be able to see
        what the system understood before trusting the results.
        """
        parts: list[str] = [f"Search {self.dataset}"]
        if self.time_range and self.time_range.start:
            parts.append(
                f"between {self.time_range.start.isoformat()} and "
                f"{(self.time_range.end or utcnow()).isoformat()}"
            )
        if self.filters:
            joiner = f" {self.logic.upper()} "
            rendered = joiner.join(
                f"{f.field} {f.operator} {f.value!r}" for f in self.filters
            )
            parts.append(f"where {rendered}")
        if self.sequence:
            chain = " then ".join(
                f"{s.name} (x{s.min_count})" for s in self.sequence.steps
            )
            parts.append(
                f"as an ordered sequence [{chain}] within {self.sequence.within_seconds}s, "
                f"correlated on {', '.join(self.sequence.correlate_on)}"
            )
        parts.append(f"ordered by {self.order_by} {self.order}, limit {self.limit}")
        return "; ".join(parts) + "."
