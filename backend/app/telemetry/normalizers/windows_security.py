"""Windows Security channel telemetry.

Windows encodes meaning in numeric Event IDs; the mapping table below is the
whole normalizer.  Keeping it as data rather than a chain of ``if`` statements
means adding coverage for a new Event ID is a one-line change.
"""

from __future__ import annotations

from typing import Any

from app.models.enums import EventStatus, EventType, TelemetrySource
from app.telemetry.normalizers.base import NormalizationError, Normalizer
from app.telemetry.schema import MAX_COMMAND_LINE, NormalizedEvent

# event_id -> (event_type, action, status)
EVENT_MAP: dict[int, tuple[EventType, str, EventStatus]] = {
    4624: (EventType.AUTHENTICATION, "login", EventStatus.SUCCESS),
    4625: (EventType.AUTHENTICATION, "login", EventStatus.FAILURE),
    4634: (EventType.AUTHENTICATION, "logoff", EventStatus.SUCCESS),
    4648: (EventType.AUTHENTICATION, "explicit_credential_login", EventStatus.SUCCESS),
    4672: (EventType.PRIVILEGE, "special_privileges_assigned", EventStatus.SUCCESS),
    4673: (EventType.PRIVILEGE, "privileged_service_called", EventStatus.SUCCESS),
    4688: (EventType.PROCESS, "process_created", EventStatus.SUCCESS),
    4689: (EventType.PROCESS, "process_terminated", EventStatus.SUCCESS),
    4720: (EventType.ACCOUNT, "account_created", EventStatus.SUCCESS),
    4722: (EventType.ACCOUNT, "account_enabled", EventStatus.SUCCESS),
    4724: (EventType.ACCOUNT, "password_reset", EventStatus.SUCCESS),
    4728: (EventType.ACCOUNT, "group_member_added", EventStatus.SUCCESS),
    4732: (EventType.ACCOUNT, "group_member_added", EventStatus.SUCCESS),
    4738: (EventType.ACCOUNT, "account_changed", EventStatus.SUCCESS),
    4776: (EventType.AUTHENTICATION, "credential_validation", EventStatus.SUCCESS),
    4798: (EventType.DISCOVERY, "local_group_enumerated", EventStatus.SUCCESS),
    4799: (EventType.DISCOVERY, "local_group_enumerated", EventStatus.SUCCESS),
    5140: (EventType.NETWORK, "network_share_accessed", EventStatus.SUCCESS),
    5145: (EventType.NETWORK, "network_share_checked", EventStatus.SUCCESS),
    7045: (EventType.SERVICE, "service_installed", EventStatus.SUCCESS),
    4698: (EventType.SCHEDULED_TASK, "scheduled_task_created", EventStatus.SUCCESS),
}

# Logon types worth distinguishing: 3 = network, 10 = RemoteInteractive (RDP).
LOGON_TYPES = {
    2: "interactive", 3: "network", 4: "batch", 5: "service",
    7: "unlock", 8: "network_cleartext", 9: "new_credentials",
    10: "remote_interactive", 11: "cached_interactive",
}

# Substatus codes on 4625 that explain *why* authentication failed.
FAILURE_REASONS = {
    "0xc0000064": "user_does_not_exist",
    "0xc000006a": "bad_password",
    "0xc0000234": "account_locked_out",
    "0xc0000072": "account_disabled",
    "0xc0000071": "password_expired",
    "0xc000006d": "bad_credentials",
    "0xc000006e": "account_restriction",
}

PRIVILEGED_GROUPS = {
    "administrators", "domain admins", "enterprise admins",
    "schema admins", "account operators", "backup operators",
}


class WindowsSecurityNormalizer(Normalizer):
    source = TelemetrySource.WINDOWS_SECURITY

    def normalize(self, record: dict[str, Any]) -> NormalizedEvent | None:
        raw_id = self.first(record, "EventID", "event_id", "EventCode")
        try:
            event_id = int(raw_id)
        except (TypeError, ValueError) as exc:
            raise NormalizationError("windows_security record has no numeric EventID") from exc

        mapping = EVENT_MAP.get(event_id)
        if mapping is None:
            # Unmapped Windows IDs are noise for this platform's rule set; the
            # honest move is to drop them rather than mint meaningless events.
            return None
        event_type, action, status = mapping

        ts = self.timestamp(record, "TimeCreated", "@timestamp", "timestamp", "EventTime")
        host = self.first(record, "Computer", "host", "hostname", "ComputerName")
        user = self.first(record, "TargetUserName", "SubjectUserName", "user", "AccountName")
        src_ip = self.first(record, "IpAddress", "SourceNetworkAddress", "source_ip")
        if src_ip in ("-", "::1", ""):
            src_ip = None

        meta: dict[str, Any] = {"windows_event_id": event_id}

        logon_type = record.get("LogonType")
        if logon_type not in (None, ""):
            try:
                lt = int(logon_type)
                meta["logon_type"] = lt
                meta["logon_type_name"] = LOGON_TYPES.get(lt, str(lt))
            except (TypeError, ValueError):
                pass

        if event_id == 4625:
            sub = str(record.get("SubStatus") or record.get("Status") or "").lower()
            meta["failure_reason"] = FAILURE_REASONS.get(sub, sub or "unknown")

        if event_id == 4672:
            privileges = record.get("PrivilegeList") or ""
            meta["privileges"] = [p.strip() for p in str(privileges).replace("\n", " ").split() if p.strip()]
            meta["elevated"] = True

        if event_id in (4728, 4732):
            group = str(self.first(record, "TargetUserName", "GroupName", default="")).lower()
            member = self.first(record, "MemberName", "MemberSid")
            meta["group"] = group
            meta["privileged_group"] = group in PRIVILEGED_GROUPS
            meta["member"] = member
            # On 4728/4732 TargetUserName is the *group*; the member is the principal.
            if member:
                user = str(member).split(",")[0].replace("CN=", "") or user

        if event_id == 7045:
            meta["service_name"] = record.get("ServiceName")
            meta["service_start_type"] = record.get("StartType")

        if event_id == 4698:
            meta["task_name"] = record.get("TaskName")

        return NormalizedEvent(
            timestamp=ts,
            event_type=event_type,
            source=self.source,
            host_id=self.truncate(host, 128),
            user_id=self.truncate(user, 128),
            source_ip=src_ip,
            destination_port=self._int(record.get("IpPort")),
            process=self.truncate(self.first(record, "NewProcessName", "ProcessName"), 255),
            process_id=self._int(record.get("NewProcessId") or record.get("ProcessId")),
            parent_process=self.truncate(record.get("ParentProcessName"), 255),
            command_line=self.truncate(record.get("CommandLine"), MAX_COMMAND_LINE),
            file_path=self.truncate(record.get("ObjectName") or record.get("ShareName"), 2048),
            action=action,
            status=status,
            message=self.truncate(record.get("Message"), 2048),
            metadata=meta,
            raw_event=record,
        )

    @staticmethod
    def _int(value: Any) -> int | None:
        if value in (None, ""):
            return None
        try:
            text = str(value)
            return int(text, 16) if text.lower().startswith("0x") else int(text)
        except (TypeError, ValueError):
            return None
