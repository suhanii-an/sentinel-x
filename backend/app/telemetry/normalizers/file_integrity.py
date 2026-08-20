"""File integrity monitoring telemetry.

Persistence is, almost always, a file appearing somewhere specific.  This
normalizer's job is to recognise *where*: a new file in ``/etc/cron.d`` is a
different class of event from a new file in ``/tmp``, and the rules should be
able to say so without carrying a path table of their own.
"""

from __future__ import annotations

from typing import Any

from app.models.enums import EventStatus, EventType, TelemetrySource
from app.telemetry.normalizers.base import NormalizationError, Normalizer
from app.telemetry.schema import NormalizedEvent

#: Directory prefix -> persistence mechanism it implements.
PERSISTENCE_PATHS: list[tuple[str, str]] = [
    ("/etc/cron.d", "cron"),
    ("/etc/cron.daily", "cron"),
    ("/etc/cron.hourly", "cron"),
    ("/var/spool/cron", "cron"),
    ("/etc/crontab", "cron"),
    ("/etc/systemd/system", "systemd_service"),
    ("/lib/systemd/system", "systemd_service"),
    ("/usr/lib/systemd/system", "systemd_service"),
    ("/etc/init.d", "init_script"),
    ("/etc/rc.local", "init_script"),
    ("/etc/profile.d", "shell_profile"),
    ("/etc/bash.bashrc", "shell_profile"),
    ("/root/.bashrc", "shell_profile"),
    ("/root/.ssh/authorized_keys", "ssh_authorized_keys"),
    (".ssh/authorized_keys", "ssh_authorized_keys"),
    ("/etc/ld.so.preload", "library_preload"),
    ("/etc/passwd", "account_file"),
    ("/etc/shadow", "credential_file"),
    ("/etc/sudoers", "sudoers"),
    ("/etc/sudoers.d", "sudoers"),
    ("C:\\Windows\\System32\\Tasks", "scheduled_task"),
    ("Start Menu\\Programs\\Startup", "startup_folder"),
]

SENSITIVE_READS = {"/etc/shadow", "/etc/sudoers", "/etc/passwd"}


class FileIntegrityNormalizer(Normalizer):
    source = TelemetrySource.FILE_INTEGRITY

    def normalize(self, record: dict[str, Any]) -> NormalizedEvent | None:
        path = self.first(record, "path", "file_path", "file.path", "target")
        if not path:
            raise NormalizationError("file_integrity record has no path")
        path = str(path)

        ts = self.timestamp(record, "time", "@timestamp", "timestamp")
        action = str(self.first(record, "action", "event_type", default="modify")).lower()

        meta: dict[str, Any] = {
            "mode": record.get("mode"),
            "owner": record.get("owner"),
            "size": record.get("size"),
            "previous_hash": record.get("previous_hash"),
        }

        for prefix, mechanism in PERSISTENCE_PATHS:
            if path.startswith(prefix) or prefix in path:
                meta["persistence_mechanism"] = mechanism
                meta["persistence_path"] = True
                break

        if path in SENSITIVE_READS:
            meta["sensitive_file"] = True

        mode = str(record.get("mode") or "")
        # setuid bit in an octal mode string, e.g. "4755".
        if mode and len(mode) >= 4 and mode[-4] in {"4", "6", "7"}:
            meta["setuid"] = True

        return NormalizedEvent(
            timestamp=ts,
            event_type=EventType.FILE,
            source=self.source,
            host_id=self.truncate(self.first(record, "host", "hostname", "host_id"), 128),
            user_id=self.truncate(self.first(record, "user", "user_id", "owner"), 128),
            process=self.truncate(self.first(record, "process", "process_name"), 255),
            file_path=self.truncate(path, 2048),
            file_hash=self.truncate(self.first(record, "hash_sha256", "sha256", "file.hash.sha256"), 128),
            action=self.truncate(action, 128),
            status=EventStatus.SUCCESS,
            message=self.truncate(record.get("message"), 2048),
            metadata={k: v for k, v in meta.items() if v not in (None, "")},
            raw_event=record,
        )
