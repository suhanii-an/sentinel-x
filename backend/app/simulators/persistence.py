"""Scenario: persistence.

**Nothing is installed anywhere.**  The scenario emits the file-integrity and
account-management records that persistence mechanisms produce.  No cron entry,
systemd unit, SSH key or user account is created on any real system.

Four mechanisms are covered because a platform that only detects cron has a
detection gap it cannot see.
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
    file_event,
    jitter,
    linux_auth,
    windows_security,
)
from app.simulators.environment import Environment

SCENARIO_KEY = "persistence"


class PersistenceSimulator(Simulator):
    spec = ScenarioSpec(
        key=SCENARIO_KEY,
        name="Persistence Establishment",
        description=(
            "An actor with root establishes several independent footholds: a cron entry, a "
            "systemd service, an SSH authorized_keys addition, and a backdoor account with "
            "UID 0 added to a privileged group. Redundancy is deliberate - real intrusions "
            "rarely rely on a single mechanism."
        ),
        expected_telemetry=(
            "File creation under /etc/cron.d",
            "A systemd unit file written to /etc/systemd/system",
            "A modification to root's authorized_keys",
            "Account creation with UID 0 and addition to the sudo group",
        ),
        expected_detections=(
            "PERSISTENCE_SCHEDULED_TASK_001",
            "PERSISTENCE_BACKDOOR_ACCOUNT_001",
            "PRIVESC_GROUP_CHANGE_001",
        ),
        techniques=(
            "T1053", "T1053.003", "T1543", "T1543.002",
            "T1098", "T1098.004", "T1136", "T1136.001",
        ),
        tactics=("TA0003", "TA0004"),
        default_params={
            "target_host": "LINUX-03",
            "backdoor_account": "svc-telemetry",
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
        backdoor = self.param(params, "backdoor_account", "svc-telemetry")
        include_windows = bool(self.param(params, "include_windows", False))

        records: list[TelemetryRecord] = []
        moment = start

        records.append(file_event(
            moment, host, "root", "/etc/cron.d/system-telemetry", "create",
            mode="0644", sha256="a" * 64, process="bash",
            label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
        ))
        moment += dt.timedelta(seconds=jitter(rng, 14))

        records.append(file_event(
            moment, host, "root", "/etc/systemd/system/telemetry-sync.service", "create",
            mode="0644", sha256="b" * 64, process="bash",
            label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
        ))
        moment += dt.timedelta(seconds=jitter(rng, 11))

        records.append(file_event(
            moment, host, "root", "/root/.ssh/authorized_keys", "modify",
            mode="0600", sha256="d" * 64, process="bash",
            label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
        ))
        moment += dt.timedelta(seconds=jitter(rng, 17))

        records.append(linux_auth(
            moment, host, "useradd",
            f"new user: name={backdoor}, UID=0, GID=0, home=/home/{backdoor}, "
            "shell=/bin/bash, from=/dev/pts/1",
            label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
        ))
        moment += dt.timedelta(seconds=jitter(rng, 4))

        records.append(linux_auth(
            moment, host, "usermod",
            f"add '{backdoor}' to group 'sudo'",
            label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
        ))
        moment += dt.timedelta(seconds=jitter(rng, 3))

        records.append(linux_auth(
            moment, host, "passwd",
            f"password changed for {backdoor}",
            label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
        ))

        if include_windows:
            moment += dt.timedelta(seconds=jitter(rng, 25))
            records.append(windows_security(
                moment, "WIN-APP-01", 7045, target_user="svc-sql",
                extra={"ServiceName": "WinTelemetrySvc", "StartType": "auto",
                       "ImagePath": "C:\\Windows\\Temp\\wts.exe"},
                label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
            ))
            moment += dt.timedelta(seconds=jitter(rng, 8))
            records.append(windows_security(
                moment, "WIN-APP-01", 4732, target_user="Administrators",
                extra={"MemberName": "CN=svc-telemetry,CN=Users,DC=corp,DC=internal"},
                label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
            ))

        return records
