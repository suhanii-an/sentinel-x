"""Endpoint process telemetry in an ECS-shaped envelope.

Modelled on the Elastic Common Schema layout most EDR exports use, so the
normalizer exercises the realistic problem: deeply nested source documents
flattened into the canonical event.

Discovery classification happens here rather than in a rule because "is
``/usr/bin/whoami`` a discovery command?" is a property of the *command*, not of
any one detection.  Rules consume ``metadata.discovery_category`` and stay
readable.
"""

from __future__ import annotations

from typing import Any

from app.models.enums import EventStatus, EventType, TelemetrySource
from app.telemetry.normalizers.base import NormalizationError, Normalizer
from app.telemetry.schema import MAX_COMMAND_LINE, NormalizedEvent

#: Commands whose whole purpose is enumeration.  Grouped by what they enumerate
#: so a rule can require breadth ("three different discovery categories in two
#: minutes") instead of raw count, which is far less false-positive prone.
DISCOVERY_COMMANDS: dict[str, str] = {
    # account / identity
    "whoami": "account", "id": "account", "groups": "account",
    "getent": "account", "lastlog": "account", "last": "account", "w": "account",
    "net": "account", "net1": "account", "dsquery": "account",
    # system
    "uname": "system", "hostnamectl": "system", "lscpu": "system",
    "systeminfo": "system", "ver": "system", "lsb_release": "system",
    # network
    "ifconfig": "network", "ip": "network", "netstat": "network",
    "ss": "network", "arp": "network", "route": "network",
    "nmap": "network", "ipconfig": "network",
    # permissions / privilege surface
    "sudo": "permission", "visudo": "permission", "find": "permission",
    "getcap": "permission", "crontab": "permission",
}

#: Shells and interpreters — Execution (T1059) signal.
INTERPRETERS = {
    "bash", "sh", "zsh", "dash", "ksh", "python", "python3", "perl", "ruby",
    "powershell", "pwsh", "cmd", "wscript", "cscript", "node",
}

#: Argument patterns that make an otherwise-ordinary binary interesting.
SUSPICIOUS_ARGS = (
    ("-perm -4000", "suid_enumeration"),
    ("-perm -u=s", "suid_enumeration"),
    ("/etc/shadow", "credential_file_access"),
    ("/etc/sudoers", "sudoers_access"),
    ("id_rsa", "private_key_access"),
    (".ssh/authorized_keys", "authorized_keys_access"),
    ("-enc ", "encoded_command"),
    ("-EncodedCommand", "encoded_command"),
    ("base64 -d", "encoded_command"),
    ("curl ", "remote_download"),
    ("wget ", "remote_download"),
    ("nc -e", "reverse_shell"),
    ("/dev/tcp/", "reverse_shell"),
)


def _dig(record: dict[str, Any], path: str, default: Any = None) -> Any:
    """Read ``a.b.c`` from nested dicts, tolerating flat ``"a.b.c"`` keys too."""
    if path in record:
        return record[path]
    node: Any = record
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node if node not in ("", None) else default


class EDRProcessNormalizer(Normalizer):
    source = TelemetrySource.EDR_PROCESS

    def normalize(self, record: dict[str, Any]) -> NormalizedEvent | None:
        name = _dig(record, "process.name") or _dig(record, "process_name")
        if not name:
            raise NormalizationError("edr_process record has no process.name")

        ts = self.timestamp(record, "@timestamp", "timestamp", "event.created")
        host = _dig(record, "host.name") or _dig(record, "agent.hostname") or _dig(record, "host_id")
        user = _dig(record, "user.name") or _dig(record, "user_id")
        cmdline = _dig(record, "process.command_line") or _dig(record, "command_line") or ""
        parent = _dig(record, "process.parent.name") or _dig(record, "parent_process")
        action = _dig(record, "event.action", "process_created")
        outcome = str(_dig(record, "event.outcome", "success")).lower()

        base_name = str(name).rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
        if base_name.endswith(".exe"):
            base_name = base_name[:-4]

        meta: dict[str, Any] = {
            "executable": _dig(record, "process.executable"),
            "working_directory": _dig(record, "process.working_directory"),
            "parent_pid": _dig(record, "process.parent.pid"),
            "integrity_level": _dig(record, "process.integrity_level"),
            "base_name": base_name,
        }

        if category := DISCOVERY_COMMANDS.get(base_name):
            meta["discovery_category"] = category
        if base_name in INTERPRETERS:
            meta["interpreter"] = True

        haystack = f"{cmdline} {name}"
        indicators = sorted({label for token, label in SUSPICIOUS_ARGS if token in haystack})
        if indicators:
            meta["argument_indicators"] = indicators

        # An event is Discovery-typed when the command exists to enumerate.
        event_type = EventType.DISCOVERY if "discovery_category" in meta else EventType.PROCESS

        return NormalizedEvent(
            timestamp=ts,
            event_type=event_type,
            source=self.source,
            host_id=self.truncate(host, 128),
            user_id=self.truncate(user, 128),
            process=self.truncate(name, 255),
            process_id=self._int(_dig(record, "process.pid")),
            parent_process=self.truncate(parent, 255),
            command_line=self.truncate(cmdline, MAX_COMMAND_LINE),
            file_hash=self.truncate(_dig(record, "process.hash.sha256"), 128),
            action=self.truncate(action, 128),
            status=EventStatus.SUCCESS if outcome in ("success", "allowed") else EventStatus.FAILURE,
            message=self.truncate(_dig(record, "message"), 2048),
            metadata={k: v for k, v in meta.items() if v not in (None, "")},
            raw_event=record,
        )

    @staticmethod
    def _int(value: Any) -> int | None:
        try:
            return int(value) if value not in (None, "") else None
        except (TypeError, ValueError):
            return None
