"""Scenario: privilege escalation.

**No exploitation occurs.**  This scenario emits the telemetry a successful
escalation produces — a search for setuid binaries, a sudo capability check, then
a root shell recorded in auth.log.  No privilege is actually changed, no exploit
code exists in this repository, and nothing is executed on the host running
SENTINEL-X.

The Windows variant emits Event ID 4672 with sensitive privileges, which is the
equivalent signal on that platform.
"""

from __future__ import annotations

import datetime as dt
import random
from typing import Any

from app.models.enums import GroundTruthLabel
from app.simulators.base import (
    ScenarioSpec,
    Simulator,
    TelemetryRecord,
    edr_process,
    file_event,
    jitter,
    linux_auth,
    windows_security,
)
from app.simulators.environment import Environment

SCENARIO_KEY = "privilege_escalation"


class PrivilegeEscalationSimulator(Simulator):
    spec = ScenarioSpec(
        key=SCENARIO_KEY,
        name="Privilege Escalation",
        description=(
            "A session enumerates its privilege surface - searching for setuid binaries and "
            "checking sudo rights - and then elevates to root. No exploit is executed: the "
            "scenario produces the log records such an escalation leaves behind."
        ),
        expected_telemetry=(
            "A filesystem search for setuid binaries",
            "A sudo capability check",
            "An auth.log record showing a root shell obtained via sudo",
            "A world-writable setuid binary appearing on disk",
        ),
        expected_detections=(
            "PRIVESC_SUID_ENUM_001",
            "PRIVESC_SUDO_CHAIN_001",
        ),
        techniques=("T1548", "T1548.001", "T1548.003", "T1068"),
        tactics=("TA0004",),
        default_params={
            "target_host": "LINUX-03",
            "target_user": "admin",
            "include_windows": False,
        },
    )

    def generate(
        self,
        env: Environment,
        rng: random.Random,
        start: dt.datetime,
        params: dict[str, Any],
    ) -> list[TelemetryRecord]:
        host = self.param(params, "target_host", "LINUX-03")
        user = self.param(params, "target_user", "admin")
        include_windows = bool(self.param(params, "include_windows", False))

        records: list[TelemetryRecord] = []
        moment = start
        pid = rng.randint(10000, 10500)

        records.append(edr_process(
            moment, host, user, "/usr/bin/find", "find / -perm -4000 -type f 2>/dev/null",
            pid=pid, parent="bash", parent_pid=pid - 1,
            label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
        ))
        moment += dt.timedelta(seconds=jitter(rng, 12))

        records.append(edr_process(
            moment, host, user, "/usr/bin/sudo", "sudo -l",
            pid=pid + 3, parent="bash", parent_pid=pid - 1,
            label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
        ))
        moment += dt.timedelta(seconds=jitter(rng, 8))

        records.append(edr_process(
            moment, host, user, "/usr/bin/getcap", "getcap -r / 2>/dev/null",
            pid=pid + 6, parent="bash", parent_pid=pid - 1,
            label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
        ))
        moment += dt.timedelta(seconds=jitter(rng, 15))

        # The escalation itself, as auth.log records it.
        records.append(linux_auth(
            moment, host, "sudo",
            f"  {user} : TTY=pts/1 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/bash",
            pid=pid + 9, label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
        ))
        moment += dt.timedelta(seconds=jitter(rng, 2))

        records.append(linux_auth(
            moment, host, "sudo",
            "pam_unix(sudo:session): session opened for user root(uid=0) by "
            f"{user}(uid=1000)",
            pid=pid + 9, label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
        ))
        moment += dt.timedelta(seconds=jitter(rng, 20))

        # A setuid shell dropped on disk - the classic way to keep root cheaply.
        records.append(file_event(
            moment, host, "root", "/usr/local/bin/.cache-helper", "create",
            mode="4755", sha256="c" * 64, process="cp",
            label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
        ))

        if include_windows:
            moment += dt.timedelta(seconds=jitter(rng, 30))
            win_host = "WIN-APP-01"
            records.append(windows_security(
                moment, win_host, 4672, target_user="svc-sql",
                extra={"PrivilegeList": "SeDebugPrivilege SeTcbPrivilege SeImpersonatePrivilege"},
                label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
            ))

        return records
