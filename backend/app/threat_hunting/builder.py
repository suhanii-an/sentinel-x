"""Safe query construction.

Every statement is built from SQLAlchemy column objects resolved through an
explicit mapping.  Caller-supplied strings only ever reach the database as bound
parameters, never as SQL text.  There is no ``text()`` call in this module and
there should never be one.

The ``COLUMNS`` maps are the security boundary: a field that is not in them
cannot be selected, filtered or ordered by, regardless of what the DSL validator
did or did not catch.  Two independent checks, because the cost of the second one
is a dictionary lookup.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import Select, Text, and_, cast, func, or_, select
from sqlalchemy.orm import InstrumentedAttribute, Session

from app.core.errors import UnsafeQueryError
from app.models.alerts import Alert
from app.models.events import Event
from app.models.incidents import Incident
from app.threat_hunting.dsl import HuntFilter, HuntQuery, TimeRange

EVENT_COLUMNS: dict[str, InstrumentedAttribute] = {
    "event_id": Event.event_id,
    "timestamp": Event.timestamp,
    "event_type": Event.event_type,
    "source": Event.source,
    "host": Event.host_ref,
    "user": Event.user_ref,
    "source_ip": Event.source_ip,
    "destination_ip": Event.destination_ip,
    "destination_port": Event.destination_port,
    "protocol": Event.protocol,
    "bytes_out": Event.bytes_out,
    "process": Event.process_name,
    "process_id": Event.process_id,
    "parent_process": Event.parent_process,
    "command_line": Event.command_line,
    "file_path": Event.file_path,
    "file_hash": Event.file_hash,
    "cloud_provider": Event.cloud_provider,
    "cloud_account": Event.cloud_account,
    "cloud_service": Event.cloud_service,
    "cloud_resource": Event.cloud_resource,
    "cloud_region": Event.cloud_region,
    "action": Event.action,
    "status": Event.status,
    "message": Event.message,
    "label": Event.label,
    "label_scenario": Event.label_scenario,
    "is_demo": Event.is_demo,
}

ALERT_COLUMNS: dict[str, InstrumentedAttribute] = {
    "alert_id": Alert.alert_id,
    "detected_at": Alert.detected_at,
    "created_at": Alert.created_at,
    "rule_id": Alert.rule_id,
    "rule_type": Alert.rule_type,
    "severity": Alert.severity,
    "status": Alert.status,
    "confidence": Alert.confidence,
    "risk_score": Alert.risk_score,
    "host": Alert.host_ref,
    "user": Alert.user_ref,
    "source_ip": Alert.source_ip,
    "title": Alert.title,
    "is_demo": Alert.is_demo,
}

INCIDENT_COLUMNS: dict[str, InstrumentedAttribute] = {
    "incident_id": Incident.incident_id,
    "first_seen": Incident.first_seen,
    "last_seen": Incident.last_seen,
    "severity": Incident.severity,
    "status": Incident.status,
    "confidence": Incident.confidence,
    "risk_score": Incident.risk_score,
    "title": Incident.title,
    "is_demo": Incident.is_demo,
}

COLUMNS: dict[str, dict[str, InstrumentedAttribute]] = {
    "events": EVENT_COLUMNS,
    "alerts": ALERT_COLUMNS,
    "incidents": INCIDENT_COLUMNS,
}

MODELS = {"events": Event, "alerts": Alert, "incidents": Incident}
TIME_COLUMN = {"events": Event.timestamp, "alerts": Alert.detected_at, "incidents": Incident.last_seen}

#: Fields stored as JSON arrays; matched by containment rather than equality.
JSON_ARRAY_FIELDS = {
    ("alerts", "technique_id"): Alert.technique_ids,
    ("incidents", "technique_id"): Incident.technique_ids,
    ("incidents", "host"): Incident.affected_hosts,
    ("incidents", "user"): Incident.affected_users,
    ("incidents", "source_ip"): Incident.source_ips,
}


#: Every spelling a JSON boolean can take across the supported backends.
_BOOLEAN_FORMS = {
    True: ["true", "1", "True"],
    False: ["false", "0", "False"],
}


def _is_boolean_like(value: Any) -> bool:
    return isinstance(value, bool) or (
        isinstance(value, str) and value.strip().lower() in {"true", "false"}
    )


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() == "true"


def _column(dataset: str, field: str):
    table = COLUMNS.get(dataset)
    if table is None:
        raise UnsafeQueryError(f"Unknown dataset '{dataset}'.")
    column = table.get(field)
    if column is None:
        raise UnsafeQueryError(f"Field '{field}' is not queryable on {dataset}.")
    return column


def _metadata_expression(key: str):
    """Compare against a key inside the normalized metadata document.

    ``Event.meta[key].as_string()`` renders as ``json_extract`` on SQLite and
    ``->>`` on Postgres, with the key bound as a parameter in both cases.
    """
    if not key or not key.replace("_", "").replace("-", "").isalnum():
        raise UnsafeQueryError(f"Invalid metadata key '{key}'.")
    # The explicit CAST matters. SQLite's json_extract returns a value with its
    # original storage class - integer 1 for a JSON true - and SQLite will not
    # compare an integer to a text literal. Without the cast, the same filter
    # silently returns nothing on SQLite while working on Postgres, which is the
    # worst possible failure mode for a security query.
    return cast(Event.meta[key].as_string(), Text)


def _apply_operator(column, operator: str, value: Any):
    """Turn one validated filter into a SQLAlchemy condition.

    Equality and membership on text are case-insensitive, matching the
    detection engine's condition language and for the same reason: security
    telemetry is not case-consistent, and ``ADMINISTRATOR``, ``Administrator``
    and ``administrator`` are the same principal. An analyst hunting for
    ``alice`` should not miss the event that recorded ``Alice``.

    It also keeps this path and the in-memory sequence matcher in agreement.
    They diverged once — the in-memory path lowercased and this one did not, so
    the *same* filter matched in a sequence hunt and not in a simple hunt — and
    `tests/test_hunting.py` now compares the two directly.
    """
    if operator == "eq":
        return _ci(column, value, equal=True)
    if operator == "ne":
        return _ci(column, value, equal=False)
    if operator == "in":
        if all(isinstance(v, str) for v in value):
            return func.lower(column).in_([v.lower() for v in value])
        return column.in_(value)
    if operator == "not_in":
        if all(isinstance(v, str) for v in value):
            return func.lower(column).notin_([v.lower() for v in value])
        return column.notin_(value)
    if operator == "contains":
        # ``escape`` prevents a caller's % or _ from becoming a wildcard.
        return column.ilike(f"%{_escape_like(value)}%", escape="\\")
    if operator == "not_contains":
        return ~column.ilike(f"%{_escape_like(value)}%", escape="\\")
    if operator == "startswith":
        return column.ilike(f"{_escape_like(value)}%", escape="\\")
    if operator == "endswith":
        return column.ilike(f"%{_escape_like(value)}", escape="\\")
    if operator == "gt":
        return column > value
    if operator == "gte":
        return column >= value
    if operator == "lt":
        return column < value
    if operator == "lte":
        return column <= value
    if operator == "exists":
        return column.isnot(None) if value else column.is_(None)
    raise UnsafeQueryError(f"Unsupported operator '{operator}'.")


def _ci(column, value: Any, *, equal: bool):
    """Case-insensitive comparison for text, exact comparison for everything else."""
    if isinstance(value, str):
        condition = func.lower(column) == value.lower()
    else:
        condition = column == value
    return condition if equal else ~condition


def _escape_like(value: Any) -> str:
    text = str(value)
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def build_condition(dataset: str, item: HuntFilter):
    if item.field.startswith("metadata."):
        if dataset != "events":
            raise UnsafeQueryError("Metadata filters are only available on events.")
        column = _metadata_expression(item.field.split(".", 1)[1])
        value = item.value
        # JSON booleans extract as text, and the representation is dialect
        # specific: Postgres yields "true"/"false", SQLite yields 1/0. Matching
        # a single spelling would make the same hunt return different results on
        # different backends, so boolean comparisons are expanded to cover both.
        if _is_boolean_like(value) and item.operator in {"eq", "ne"}:
            candidates = _BOOLEAN_FORMS[_as_bool(value)]
            condition = column.in_(candidates)
            return condition if item.operator == "eq" else ~condition
        return _apply_operator(column, item.operator, value)

    json_array = JSON_ARRAY_FIELDS.get((dataset, item.field))
    if json_array is not None:
        return _json_array_condition(json_array, item)

    return _apply_operator(_column(dataset, item.field), item.operator, item.value)


def _json_array_condition(column, item: HuntFilter):
    """Match a value inside a JSON array column.

    Implemented as a string containment test on the serialised array so it works
    identically on SQLite and Postgres.  The trade-off is documented rather than
    hidden: this is a scan, not an index lookup, and ``docs/detection-engine.md``
    notes that a production deployment would use a GIN index and the ``@>``
    operator on Postgres.
    """
    values = item.value if isinstance(item.value, list) else [item.value]
    clauses = [
        column.cast(Text).ilike(f'%"{_escape_like(v)}"%', escape="\\") for v in values
    ]
    if item.operator in {"eq", "in", "contains"}:
        return or_(*clauses)
    if item.operator in {"ne", "not_in", "not_contains"}:
        return and_(*[~c for c in clauses])
    raise UnsafeQueryError(
        f"Operator '{item.operator}' is not supported on list field '{item.field}'."
    )


def apply_time_range(stmt: Select, dataset: str, time_range: TimeRange | None) -> Select:
    if time_range is None:
        return stmt
    column = TIME_COLUMN[dataset]
    if time_range.start:
        stmt = stmt.where(column >= time_range.start)
    if time_range.end:
        stmt = stmt.where(column <= time_range.end)
    return stmt


def build_select(query: HuntQuery) -> Select:
    """Compile a validated hunt query into a parameterised SELECT."""
    model = MODELS[query.dataset]
    stmt = select(model)

    if query.filters:
        conditions = [build_condition(query.dataset, f) for f in query.filters]
        stmt = stmt.where(and_(*conditions) if query.logic == "and" else or_(*conditions))

    stmt = apply_time_range(stmt, query.dataset, query.time_range)

    order_column = _column(query.dataset, query.order_by or "timestamp")
    stmt = stmt.order_by(order_column.desc() if query.order == "desc" else order_column.asc())
    return stmt.limit(query.limit).offset(query.offset)


def build_count(query: HuntQuery) -> Select:
    model = MODELS[query.dataset]
    stmt = select(func.count()).select_from(model)
    if query.filters:
        conditions = [build_condition(query.dataset, f) for f in query.filters]
        stmt = stmt.where(and_(*conditions) if query.logic == "and" else or_(*conditions))
    return apply_time_range(stmt, query.dataset, query.time_range)


def explain(query: HuntQuery, db: Session) -> str:
    """Render the compiled SQL for display.

    Shown in the UI so an analyst can see exactly what ran — useful for trust,
    and essential when reviewing a query the natural-language interface produced.
    """
    stmt = build_select(query)
    return str(stmt.compile(db.get_bind(), compile_kwargs={"literal_binds": False}))
