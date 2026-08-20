"""Linux authentication telemetry (``/var/log/auth.log`` style).

Real auth logs are semi-structured prose, which is precisely why a normalization
layer earns its keep: the detection rules should never contain an sshd regex.

Handled programs: sshd, sudo, su, useradd, usermod, groupadd, passwd, systemd.
Unrecognised lines produce an event with ``action="unparsed"`` rather than being
dropped — losing telemetry silently is worse than keeping an unclassified record,
because the raw line is still evidence.
"""

from __future__ import annotations

import re
from typing import Any

from app.models.enums import EventStatus, EventType, TelemetrySource
from app.telemetry.normalizers.base import NormalizationError, Normalizer
from app.telemetry.schema import MAX_COMMAND_LINE, MAX_STRING, NormalizedEvent

# --- sshd ------------------------------------------------------------------
RE_SSH_FAILED = re.compile(
    r"Failed (?P<method>password|publickey|keyboard-interactive/pam) for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
RE_SSH_ACCEPTED = re.compile(
    r"Accepted (?P<method>password|publickey|keyboard-interactive/pam) for (?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)
RE_SSH_INVALID_USER = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")
RE_SSH_DISCONNECT = re.compile(
    r"(?:Received disconnect|Connection closed) (?:from )?(?:authenticating user (?P<user>\S+) )?(?P<ip>[\d.:a-fA-F]+)"
)
RE_MAX_AUTH = re.compile(r"error: maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")

# --- sudo / su -------------------------------------------------------------
RE_SUDO_OK = re.compile(
    r"^\s*(?P<user>\S+)\s*:\s*TTY=(?P<tty>\S*)\s*;\s*PWD=(?P<pwd>\S*)\s*;\s*USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.+)$"
)
RE_SUDO_FAIL = re.compile(r"^\s*(?P<user>\S+)\s*:\s*(?P<reason>user NOT in sudoers|\d+ incorrect password attempts?)")
RE_SU_OK = re.compile(r"\(to (?P<target>\S+)\) (?P<user>\S+) on (?P<tty>\S+)")
RE_SESSION_OPEN = re.compile(r"session opened for user (?P<target>\S+?)(?:\(uid=\d+\))? by (?:(?P<user>\S+?))?\(uid=(?P<byuid>\d+)\)")

# --- account management ----------------------------------------------------
RE_USERADD = re.compile(r"new user: name=(?P<user>[^,]+), UID=(?P<uid>\d+), GID=(?P<gid>\d+)", re.IGNORECASE)
RE_GROUP_ADD = re.compile(r"add '(?P<user>[^']+)' to group '(?P<group>[^']+)'")
RE_PASSWD_CHANGE = re.compile(r"password changed for (?P<user>\S+)")

PRIVILEGED_GROUPS = {"sudo", "wheel", "admin", "root", "adm"}


class LinuxAuthNormalizer(Normalizer):
    source = TelemetrySource.LINUX_AUTH

    def normalize(self, record: dict[str, Any]) -> NormalizedEvent | None:
        message = self.first(record, "message", "msg", "line", default="")
        if not isinstance(message, str):
            raise NormalizationError("linux_auth record has no string 'message'")

        host = self.first(record, "host", "hostname", "host_id")
        program = str(self.first(record, "program", "process", "syslog_program", default="")).lower()
        ts = self.timestamp(record, "timestamp", "@timestamp", "time")
        pid = record.get("pid")

        base: dict[str, Any] = {
            "timestamp": ts,
            "source": self.source,
            "host_id": self.truncate(host, 128),
            "process": self.truncate(program or None, 255),
            "process_id": pid if isinstance(pid, int) else None,
            "message": self.truncate(message, MAX_STRING),
            "raw_event": record,
        }

        built = (
            self._ssh(message, base)
            or self._sudo(program, message, base)
            or self._accounts(program, message, base)
        )
        if built is not None:
            return built

        # Unclassified but retained.
        return NormalizedEvent(
            **base,
            event_type=EventType.AUTHENTICATION,
            action="unparsed",
            status=EventStatus.UNKNOWN,
            metadata={"normalizer": "linux_auth", "parsed": False, "program": program},
        )

    # ------------------------------------------------------------------ ssh
    def _ssh(self, message: str, base: dict[str, Any]) -> NormalizedEvent | None:
        if m := RE_SSH_FAILED.search(message):
            return NormalizedEvent(
                **base,
                event_type=EventType.AUTHENTICATION,
                user_id=m.group("user"),
                source_ip=m.group("ip"),
                destination_port=int(m.group("port")),
                action="login",
                status=EventStatus.FAILURE,
                metadata={
                    "auth_method": m.group("method"),
                    "service": "ssh",
                    "invalid_user": "invalid user" in message,
                },
            )
        if m := RE_SSH_ACCEPTED.search(message):
            return NormalizedEvent(
                **base,
                event_type=EventType.AUTHENTICATION,
                user_id=m.group("user"),
                source_ip=m.group("ip"),
                destination_port=int(m.group("port")),
                action="login",
                status=EventStatus.SUCCESS,
                metadata={"auth_method": m.group("method"), "service": "ssh"},
            )
        if m := RE_MAX_AUTH.search(message):
            return NormalizedEvent(
                **base,
                event_type=EventType.AUTHENTICATION,
                user_id=m.group("user"),
                source_ip=m.group("ip"),
                action="login",
                status=EventStatus.FAILURE,
                metadata={"service": "ssh", "reason": "max_auth_attempts"},
            )
        if m := RE_SSH_INVALID_USER.search(message):
            return NormalizedEvent(
                **base,
                event_type=EventType.AUTHENTICATION,
                user_id=m.group("user"),
                source_ip=m.group("ip"),
                action="login",
                status=EventStatus.FAILURE,
                metadata={"service": "ssh", "invalid_user": True},
            )
        if m := RE_SSH_DISCONNECT.search(message):
            return NormalizedEvent(
                **base,
                event_type=EventType.AUTHENTICATION,
                user_id=m.group("user"),
                source_ip=m.group("ip"),
                action="disconnect",
                status=EventStatus.UNKNOWN,
                metadata={"service": "ssh"},
            )
        return None

    # ----------------------------------------------------------------- sudo
    def _sudo(self, program: str, message: str, base: dict[str, Any]) -> NormalizedEvent | None:
        if program not in {"sudo", "su", "sshd", "systemd-logind", "login"}:
            return None

        if program == "sudo":
            if m := RE_SUDO_OK.match(message):
                target = m.group("target")
                cmd = m.group("cmd")
                return NormalizedEvent(
                    **base,
                    event_type=EventType.PRIVILEGE,
                    user_id=m.group("user"),
                    action="sudo",
                    status=EventStatus.SUCCESS,
                    command_line=self.truncate(cmd, MAX_COMMAND_LINE),
                    metadata={
                        "target_user": target,
                        "tty": m.group("tty"),
                        "cwd": m.group("pwd"),
                        "elevated": target in {"root", "0"},
                    },
                )
            if m := RE_SUDO_FAIL.match(message):
                return NormalizedEvent(
                    **base,
                    event_type=EventType.PRIVILEGE,
                    user_id=m.group("user"),
                    action="sudo",
                    status=EventStatus.FAILURE,
                    metadata={"reason": m.group("reason")},
                )

        if program == "su" and (m := RE_SU_OK.search(message)):
            failed = "FAILED" in message.upper()
            return NormalizedEvent(
                **base,
                event_type=EventType.PRIVILEGE,
                user_id=m.group("user"),
                action="su",
                status=EventStatus.FAILURE if failed else EventStatus.SUCCESS,
                metadata={"target_user": m.group("target"), "tty": m.group("tty"),
                          "elevated": m.group("target") == "root"},
            )

        if m := RE_SESSION_OPEN.search(message):
            return NormalizedEvent(
                **base,
                event_type=EventType.AUTHENTICATION,
                user_id=m.group("target"),
                action="session_open",
                status=EventStatus.SUCCESS,
                metadata={"opened_by_uid": m.group("byuid"), "service": program},
            )
        return None

    # ------------------------------------------------------------- accounts
    def _accounts(self, program: str, message: str, base: dict[str, Any]) -> NormalizedEvent | None:
        if m := RE_USERADD.search(message):
            uid = int(m.group("uid"))
            return NormalizedEvent(
                **base,
                event_type=EventType.ACCOUNT,
                user_id=m.group("user"),
                action="account_created",
                status=EventStatus.SUCCESS,
                metadata={"uid": uid, "gid": int(m.group("gid")),
                          # uid 0 for a *new* account is a textbook backdoor.
                          "uid_zero": uid == 0, "tool": program},
            )
        if m := RE_GROUP_ADD.search(message):
            group = m.group("group")
            return NormalizedEvent(
                **base,
                event_type=EventType.ACCOUNT,
                user_id=m.group("user"),
                action="group_member_added",
                status=EventStatus.SUCCESS,
                metadata={"group": group, "privileged_group": group.lower() in PRIVILEGED_GROUPS,
                          "tool": program},
            )
        if m := RE_PASSWD_CHANGE.search(message):
            return NormalizedEvent(
                **base,
                event_type=EventType.ACCOUNT,
                user_id=m.group("user"),
                action="password_changed",
                status=EventStatus.SUCCESS,
                metadata={"tool": program},
            )
        return None
