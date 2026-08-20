"""Normalizer contract.

A normalizer is a pure function from one source-native record to zero or one
:class:`NormalizedEvent`.  Pure, because normalization must be testable in
isolation and must never depend on database state — a subtle but important
property: if normalization could read the database, replaying historical
telemetry would produce different results than live ingestion did.
"""

from __future__ import annotations

import datetime as dt
from abc import ABC, abstractmethod
from typing import Any

from app.core.timeutils import parse_timestamp, utcnow
from app.models.enums import TelemetrySource
from app.telemetry.schema import NormalizedEvent


class NormalizationError(ValueError):
    """The record could not be mapped onto the canonical schema."""


class Normalizer(ABC):
    source: TelemetrySource

    @abstractmethod
    def normalize(self, record: dict[str, Any]) -> NormalizedEvent | None:
        """Return the canonical event, or ``None`` for records this source emits
        that carry no security signal (heartbeats, rotation markers)."""

    # ------------------------------------------------------------- helpers
    @staticmethod
    def first(record: dict[str, Any], *keys: str, default: Any = None) -> Any:
        for key in keys:
            if key in record and record[key] not in (None, ""):
                return record[key]
        return default

    @staticmethod
    def timestamp(record: dict[str, Any], *keys: str) -> dt.datetime:
        for key in keys:
            value = record.get(key)
            if value:
                try:
                    return parse_timestamp(value)
                except (ValueError, TypeError):
                    continue
        # Falling back to ingestion time is honest but lossy, so it is recorded
        # in metadata by the caller rather than silently assumed to be accurate.
        return utcnow()

    @staticmethod
    def truncate(value: Any, limit: int) -> str | None:
        if value is None:
            return None
        text = str(value)
        return text[:limit] if len(text) > limit else text
