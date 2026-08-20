"""Network flow telemetry.

Flow records are the only source that routinely carries *both* endpoints, which
makes them the backbone of lateral-movement reconstruction: the
``host -> destination_ip`` edges in the attack graph come from here.
"""

from __future__ import annotations

from typing import Any

from app.core.netutils import is_internal, parse
from app.models.enums import EventStatus, EventType, TelemetrySource
from app.telemetry.normalizers.base import NormalizationError, Normalizer
from app.telemetry.schema import NormalizedEvent

#: Ports that carry remote-administration protocols.  A connection to one of
#: these between two internal hosts is the signature shape of lateral movement.
REMOTE_ADMIN_PORTS = {
    22: "ssh", 23: "telnet", 445: "smb", 135: "rpc", 139: "netbios",
    3389: "rdp", 5985: "winrm_http", 5986: "winrm_https", 5900: "vnc",
}

COMMON_C2_PORTS = {80: "http", 443: "https", 8080: "http_alt", 8443: "https_alt", 53: "dns"}


def _is_private(ip: str | None) -> bool | None:
    """Internal to the organisation, or None when the address is absent/invalid.

    Uses the platform's own classification rather than ``ipaddress.is_private``,
    which counts documentation ranges as private and would mark every simulated
    external address as internal. See app/core/netutils.
    """
    if not ip:
        return None
    if parse(ip) is None:
        return None
    return is_internal(ip)


class NetworkFlowNormalizer(Normalizer):
    source = TelemetrySource.NETWORK_FLOW

    def normalize(self, record: dict[str, Any]) -> NormalizedEvent | None:
        src = self.first(record, "src_ip", "source_ip", "source.ip")
        dst = self.first(record, "dst_ip", "destination_ip", "destination.ip")
        if not src and not dst:
            raise NormalizationError("network_flow record has no source or destination IP")

        ts = self.timestamp(record, "start_time", "@timestamp", "timestamp")
        port = self._int(self.first(record, "dst_port", "destination_port", "destination.port"))
        action = str(self.first(record, "action", default="allow")).lower()

        meta: dict[str, Any] = {
            "bytes_in": self._int(self.first(record, "bytes_in", "source.bytes")),
            "packets": self._int(record.get("packets")),
            "duration_ms": self._int(record.get("duration_ms")),
            "direction": record.get("direction"),
            "source_is_private": _is_private(src),
            "destination_is_private": _is_private(dst),
        }
        if port in REMOTE_ADMIN_PORTS:
            meta["service"] = REMOTE_ADMIN_PORTS[port]
            meta["remote_admin_protocol"] = True
        elif port in COMMON_C2_PORTS:
            meta["service"] = COMMON_C2_PORTS[port]

        # Internal -> internal on an admin port: the lateral-movement shape.
        if meta["source_is_private"] and meta["destination_is_private"] and meta.get("remote_admin_protocol"):
            meta["internal_lateral_candidate"] = True
        # Internal -> external: egress worth examining for C2/exfiltration.
        if meta["source_is_private"] and meta["destination_is_private"] is False:
            meta["outbound_external"] = True

        return NormalizedEvent(
            timestamp=ts,
            event_type=EventType.NETWORK,
            source=self.source,
            host_id=self.truncate(self.first(record, "host", "hostname", "host_id"), 128),
            user_id=self.truncate(self.first(record, "user", "user_id"), 128),
            source_ip=src,
            destination_ip=dst,
            destination_port=port,
            protocol=self.truncate(self.first(record, "proto", "protocol", "network.transport"), 16),
            bytes_out=self._int(self.first(record, "bytes_out", "destination.bytes", "bytes")),
            process=self.truncate(self.first(record, "process", "process.name"), 255),
            action=self.truncate(action, 128),
            status=EventStatus.SUCCESS if action in ("allow", "accept", "established") else EventStatus.FAILURE,
            metadata={k: v for k, v in meta.items() if v is not None},
            raw_event=record,
        )

    @staticmethod
    def _int(value: Any) -> int | None:
        try:
            return int(value) if value not in (None, "") else None
        except (TypeError, ValueError):
            return None
