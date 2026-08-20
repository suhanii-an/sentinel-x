"""Normalizer registry and dispatch."""

from __future__ import annotations

from typing import Any

from app.core.errors import InvalidEventError
from app.models.enums import TelemetrySource
from app.telemetry.normalizers.base import NormalizationError, Normalizer
from app.telemetry.normalizers.cloud_audit import CloudAuditNormalizer
from app.telemetry.normalizers.edr_process import EDRProcessNormalizer
from app.telemetry.normalizers.file_integrity import FileIntegrityNormalizer
from app.telemetry.normalizers.linux_auth import LinuxAuthNormalizer
from app.telemetry.normalizers.network_flow import NetworkFlowNormalizer
from app.telemetry.normalizers.windows_security import WindowsSecurityNormalizer
from app.telemetry.schema import NormalizedEvent

_NORMALIZERS: dict[str, Normalizer] = {
    TelemetrySource.LINUX_AUTH: LinuxAuthNormalizer(),
    TelemetrySource.WINDOWS_SECURITY: WindowsSecurityNormalizer(),
    TelemetrySource.EDR_PROCESS: EDRProcessNormalizer(),
    TelemetrySource.LINUX_AUDITD: EDRProcessNormalizer(),  # same ECS-ish shape
    TelemetrySource.NETWORK_FLOW: NetworkFlowNormalizer(),
    TelemetrySource.FILE_INTEGRITY: FileIntegrityNormalizer(),
    TelemetrySource.CLOUD_AUDIT: CloudAuditNormalizer(),
}


def supported_sources() -> list[str]:
    return sorted(_NORMALIZERS.keys())


def normalize(source: str, record: dict[str, Any]) -> NormalizedEvent | None:
    """Normalize one source-native record.

    Returns ``None`` when the source legitimately emits records with no security
    meaning.  Raises :class:`InvalidEventError` when the record is malformed —
    the distinction matters, because a silently dropped malformed record is a
    detection gap nobody notices.
    """
    normalizer = _NORMALIZERS.get(source)
    if normalizer is None:
        raise InvalidEventError(f"No normalizer registered for source '{source}'.")
    try:
        event = normalizer.normalize(record)
    except NormalizationError as exc:
        raise InvalidEventError(str(exc)) from exc
    except (ValueError, TypeError, KeyError) as exc:
        raise InvalidEventError(f"Record could not be normalized: {exc}") from exc
    if event is not None:
        event.source = TelemetrySource(source)
    return event
