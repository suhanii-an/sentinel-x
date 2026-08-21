"""Field addressing for detection rules.

Rules refer to fields by short, stable, analyst-friendly names (``user``, not
``user_ref``).  That indirection is deliberate: it decouples rule content from
the ORM column names, so a schema refactor does not invalidate every rule file.

``metadata.*`` reaches into the normalizer-produced metadata dictionary, which is
where source-specific enrichment lives (``metadata.logon_type``,
``metadata.iam_risk``, ``metadata.persistence_mechanism``).
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from app.models.events import Event

#: rule field name -> ORM attribute
FIELD_MAP: dict[str, str] = {
    "event_id": "event_id",
    "timestamp": "timestamp",
    "event_type": "event_type",
    "source": "source",
    "host": "host_ref",
    "host_id": "host_ref",
    "user": "user_ref",
    "user_id": "user_ref",
    "source_ip": "source_ip",
    "destination_ip": "destination_ip",
    "destination_port": "destination_port",
    "protocol": "protocol",
    "bytes_out": "bytes_out",
    "process": "process_name",
    "process_name": "process_name",
    "process_id": "process_id",
    "parent_process": "parent_process",
    "command_line": "command_line",
    "file_path": "file_path",
    "file_hash": "file_hash",
    "cloud_provider": "cloud_provider",
    "cloud_account": "cloud_account",
    "cloud_service": "cloud_service",
    "cloud_resource": "cloud_resource",
    "cloud_region": "cloud_region",
    "action": "action",
    "status": "status",
    "message": "message",
}

#: Fields a rule may group or correlate on.  Restricted on purpose: grouping by
#: a free-text field such as ``command_line`` would produce one group per event
#: and silently disable the threshold.
GROUPABLE_FIELDS = {
    "host", "host_id", "user", "user_id", "source_ip", "destination_ip",
    "cloud_account", "process", "process_name", "event_type", "action",
    "source", "status", "destination_port", "cloud_service",
}


class UnknownFieldError(ValueError):
    pass


def resolve(event: Event, field: str) -> Any:
    """Read ``field`` from an event, supporting ``metadata.`` paths."""
    if field.startswith("metadata."):
        node: Any = event.meta or {}
        for part in field.split(".")[1:]:
            if not isinstance(node, dict) or part not in node:
                return None
            node = node[part]
        return node
    if field.startswith("raw."):
        node = event.raw_event or {}
        for part in field.split(".")[1:]:
            if not isinstance(node, dict) or part not in node:
                return None
            node = node[part]
        return node

    attr = FIELD_MAP.get(field)
    if attr is None:
        raise UnknownFieldError(
            f"Unknown detection field '{field}'. Known fields: {', '.join(sorted(FIELD_MAP))}, "
            "or a 'metadata.*' / 'raw.*' path."
        )
    return getattr(event, attr, None)


def group_key(event: Event, fields: list[str]) -> tuple:
    """Build the grouping tuple for threshold/sequence rules.

    ``None`` values are preserved rather than collapsed, so events missing the
    grouping field form their own group instead of being silently merged with
    unrelated activity.
    """
    return tuple(_normalize_key(resolve(event, f)) for f in fields)


def _normalize_key(value: Any) -> Any:
    if isinstance(value, str):
        return value.lower()
    if isinstance(value, dt.datetime):
        return value.isoformat()
    if isinstance(value, (list, dict)):
        return str(value)
    return value


def describe_group(fields: list[str], key: tuple) -> str:
    """Render a group key for an analyst-facing explanation line."""
    parts = [f"{f}={v if v is not None else '(none)'}" for f, v in zip(fields, key, strict=True)]
    return ", ".join(parts)
