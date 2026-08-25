"""Scenario: host and account discovery.

Every command here is one an administrator runs.  The scenario is built to
exercise that fact: it produces enumeration across several distinct categories in
a short window, which is the only thing that distinguishes reconnaissance from
routine work, and it is exactly what ACCOUNT_DISCOVERY_001 requires.
"""

from __future__ import annotations

import datetime as dt
import random
from typing import Any

from app.models.enums import GroundTruthLabel
from app.simulators.base import ScenarioSpec, Simulator, TelemetryRecord, edr_process, jitter
from app.simulators.environment import Environment

SCENARIO_KEY = "account_discovery"

#: (executable, command line) pairs ordered the way an operator works: identity
#: first, then the machine, then the network, then the privilege surface.
DISCOVERY_SEQUENCE: tuple[tuple[str, str], ...] = (
    ("/usr/bin/whoami", "whoami"),
    ("/usr/bin/id", "id"),
    ("/usr/bin/hostname", "hostname -f"),
    ("/usr/bin/uname", "uname -a"),
    ("/usr/bin/cat", "cat /etc/passwd"),
    ("/usr/bin/getent", "getent passwd"),
    ("/usr/bin/groups", "groups"),
    ("/usr/bin/last", "last -n 25"),
    ("/usr/bin/netstat", "netstat -antp"),
    ("/usr/bin/ip", "ip addr show"),
    ("/usr/bin/arp", "arp -a"),
    ("/usr/bin/sudo", "sudo -l"),
)


class DiscoverySimulator(Simulator):
    spec = ScenarioSpec(
        key=SCENARIO_KEY,
        name="Account and Host Discovery",
        description=(
            "A session runs a burst of enumeration commands covering identity, system, "
            "network and privilege information - the situational awareness an operator "
            "gathers immediately after gaining access."
        ),
        expected_telemetry=(
            "Endpoint process-creation records for enumeration utilities",
            "Commands spanning at least three distinct discovery categories",
            "A read of /etc/passwd",
        ),
        expected_detections=("ACCOUNT_DISCOVERY_001",),
        techniques=("T1087", "T1087.001", "T1082", "T1033", "T1069"),
        tactics=("TA0007",),
        default_params={
            "target_host": "LINUX-03",
            "target_user": "admin",
            "command_count": 9,
            "interval_seconds": 9,
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
        count = int(self.param(params, "command_count", 9))
        interval = float(self.param(params, "interval_seconds", 9))

        records: list[TelemetryRecord] = []
        moment = start
        pid = rng.randint(9500, 9900)
        shell_pid = pid - 1

        for index, (executable, command_line) in enumerate(DISCOVERY_SEQUENCE[:count]):
            records.append(edr_process(
                moment, host, user, executable, command_line,
                pid=pid + index * 2, parent="bash", parent_pid=shell_pid,
                label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
            ))
            moment += dt.timedelta(seconds=jitter(rng, interval))

        return records
