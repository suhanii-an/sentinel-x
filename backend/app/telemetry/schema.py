"""The normalized event contract.

This is the single schema every detection rule is written against.  Adding a new
log source means writing a normalizer, not touching a rule.

Validation here is a security control, not a formality: ingestion is the one
endpoint that accepts attacker-influenced data by design (logs describe what an
attacker did, and attackers choose some of the strings in them).  So every field
is length-bounded, IPs are parsed rather than pattern-matched, and unbounded
nesting is rejected before the payload reaches the database.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.timeutils import parse_timestamp, utcnow
from app.models.enums import EventStatus, EventType, TelemetrySource

# Caps chosen to be comfortably larger than any legitimate record while still
# bounding memory.  A 2 MB "command line" is not telemetry, it is an attack.
MAX_STRING = 2048
MAX_COMMAND_LINE = 8192
MAX_METADATA_KEYS = 64
MAX_METADATA_DEPTH = 6
MAX_RAW_BYTES = 64 * 1024


def _valid_ip(value: str) -> str:
    """Parse and canonicalise an IP address.

    Parsing rather than regex-matching means "127.0.0.1 ; DROP TABLE" cannot
    masquerade as an address, and IPv6 forms are normalised consistently.
    """
    return str(ipaddress.ip_address(value.strip()))


def _depth(obj: Any, current: int = 0) -> int:
    if current > MAX_METADATA_DEPTH:
        return current
    if isinstance(obj, dict):
        return max((_depth(v, current + 1) for v in obj.values()), default=current)
    if isinstance(obj, list):
        return max((_depth(v, current + 1) for v in obj), default=current)
    return current


class NormalizedEvent(BaseModel):
    """A single security event in SENTINEL-X's canonical form."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    event_id: str | None = Field(default=None, max_length=64)
    timestamp: dt.datetime
    event_type: EventType
    source: TelemetrySource = TelemetrySource.NORMALIZED

    host_id: str | None = Field(default=None, max_length=128)
    user_id: str | None = Field(default=None, max_length=128)

    source_ip: str | None = Field(default=None, max_length=64)
    destination_ip: str | None = Field(default=None, max_length=64)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = Field(default=None, max_length=16)
    bytes_out: int | None = Field(default=None, ge=0)

    process: str | None = Field(default=None, max_length=255)
    process_id: int | None = Field(default=None, ge=0)
    parent_process: str | None = Field(default=None, max_length=255)
    command_line: str | None = Field(default=None, max_length=MAX_COMMAND_LINE)
    file_path: str | None = Field(default=None, max_length=MAX_STRING)
    file_hash: str | None = Field(default=None, max_length=128)

    cloud_provider: str | None = Field(default=None, max_length=32)
    cloud_account: str | None = Field(default=None, max_length=128)
    cloud_service: str | None = Field(default=None, max_length=64)
    cloud_resource: str | None = Field(default=None, max_length=MAX_STRING)
    cloud_region: str | None = Field(default=None, max_length=48)

    action: str | None = Field(default=None, max_length=128)
    status: EventStatus = EventStatus.UNKNOWN
    message: str | None = Field(default=None, max_length=MAX_STRING)

    metadata: dict[str, Any] = Field(default_factory=dict)
    raw_event: dict[str, Any] = Field(default_factory=dict)

    # Evaluation-only ground truth.  Ignored by the detection engine.
    label: str | None = Field(default=None, max_length=16)
    label_scenario: str | None = Field(default=None, max_length=64)

    @field_validator("timestamp", mode="before")
    @classmethod
    def _parse_ts(cls, v: Any) -> dt.datetime:
        if isinstance(v, (str, dt.datetime)):
            return parse_timestamp(v)
        raise ValueError("timestamp must be an ISO-8601 string or datetime")

    @field_validator("timestamp")
    @classmethod
    def _bound_ts(cls, v: dt.datetime) -> dt.datetime:
        # A timestamp far in the future would poison every time-window
        # computation in the platform, so it is rejected rather than clamped.
        if v > utcnow() + dt.timedelta(hours=24):
            raise ValueError("timestamp is more than 24h in the future")
        if v.year < 2000:
            raise ValueError("timestamp predates the supported range")
        return v

    @field_validator("source_ip", "destination_ip", mode="before")
    @classmethod
    def _check_ip(cls, v: Any) -> Any:
        if v in (None, "", "-"):
            return None
        try:
            return _valid_ip(str(v))
        except ValueError as exc:
            raise ValueError(f"invalid IP address: {v!r}") from exc

    @field_validator("host_id", "user_id", mode="before")
    @classmethod
    def _blank_to_none(cls, v: Any) -> Any:
        if v is None:
            return None
        text = str(v).strip()
        return text or None

    @field_validator("metadata")
    @classmethod
    def _check_metadata(cls, v: dict[str, Any]) -> dict[str, Any]:
        if len(v) > MAX_METADATA_KEYS:
            raise ValueError(f"metadata has more than {MAX_METADATA_KEYS} keys")
        if _depth(v) > MAX_METADATA_DEPTH:
            raise ValueError(f"metadata nests deeper than {MAX_METADATA_DEPTH} levels")
        return v

    @model_validator(mode="after")
    def _require_an_entity(self) -> NormalizedEvent:
        """An event with no host, user, IP or cloud account cannot be correlated
        to anything, so it is not useful telemetry — reject it at the edge rather
        than storing an orphan."""
        if not any([self.host_id, self.user_id, self.source_ip, self.cloud_account]):
            raise ValueError(
                "event must identify at least one entity (host_id, user_id, source_ip or cloud_account)"
            )
        return self

    def entity_keys(self) -> list[str]:
        """Namespaced entity identifiers used by the correlation engine."""
        keys: list[str] = []
        if self.host_id:
            keys.append(f"host:{self.host_id}")
        if self.user_id:
            keys.append(f"user:{self.user_id}")
        if self.source_ip:
            keys.append(f"ip:{self.source_ip}")
        if self.destination_ip:
            keys.append(f"ip:{self.destination_ip}")
        if self.cloud_account:
            keys.append(f"cloud:{self.cloud_account}")
        return keys


class RawTelemetry(BaseModel):
    """A source-native record awaiting normalization."""

    model_config = ConfigDict(extra="forbid")

    source: TelemetrySource
    record: dict[str, Any]

    @field_validator("record")
    @classmethod
    def _bound_record(cls, v: dict[str, Any]) -> dict[str, Any]:
        import json

        if len(json.dumps(v, default=str)) > MAX_RAW_BYTES:
            raise ValueError(f"raw record exceeds {MAX_RAW_BYTES} bytes")
        if _depth(v) > MAX_METADATA_DEPTH + 2:
            raise ValueError("raw record is nested too deeply")
        return v
