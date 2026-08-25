"""Scenario: valid-account abuse.

The hardest class to detect, because every event is a *success*.  The signal is
not in any single record — it is the difference between this session and what the
account normally does, which is why this scenario depends on the baseline history
the seed script establishes.  Running it against an empty database will
correctly produce no anomaly alert, and that is the honest behaviour.
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
)
from app.simulators.environment import Environment

SCENARIO_KEY = "credential_abuse"


class CredentialAbuseSimulator(Simulator):
    spec = ScenarioSpec(
        key=SCENARIO_KEY,
        name="Valid Account Abuse",
        description=(
            "Stolen credentials are used to authenticate successfully from an address the "
            "account has never used, outside its normal hours. The session then reads "
            "credential material to enable further movement. Detection depends on the "
            "account having enough history for a baseline - without it the anomaly rule "
            "deliberately stays silent."
        ),
        expected_telemetry=(
            "A successful authentication from an address absent from the account's baseline",
            "Session establishment outside the account's observed activity hours",
            "Process execution reading credential-bearing files",
        ),
        expected_detections=("VALID_ACCOUNT_ABUSE_001", "CREDENTIAL_FILE_ACCESS_001"),
        techniques=("T1078", "T1552", "T1552.004"),
        tactics=("TA0001", "TA0006"),
        default_params={
            "target_host": "LINUX-03",
            "target_user": "admin",
            "source_ip": "203.0.113.44",
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
        source_ip = self.param(params, "source_ip", env.adversary_ips[0])

        records: list[TelemetryRecord] = []
        moment = start
        port = rng.randint(40000, 60000)
        pid = rng.randint(9000, 9500)

        records.append(linux_auth(
            moment, host, "sshd",
            f"Accepted publickey for {user} from {source_ip} port {port} ssh2: "
            "RSA SHA256:8s1kQ0nJ2mXpL4vB7cD9eF0gH1iJ2kL3mN4oP5qR6sT",
            pid=pid, label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
        ))
        moment += dt.timedelta(seconds=jitter(rng, 2))

        records.append(linux_auth(
            moment, host, "sshd",
            f"pam_unix(sshd:session): session opened for user {user}(uid=1000) by (uid=0)",
            pid=pid, label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
        ))
        moment += dt.timedelta(seconds=jitter(rng, 9))

        # Credential harvesting: read the private key, then the shadow file.
        records.append(edr_process(
            moment, host, user, "/usr/bin/cat", f"cat /home/{user}/.ssh/id_rsa",
            pid=pid + 11, parent="bash", parent_pid=pid + 1,
            label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
        ))
        moment += dt.timedelta(seconds=jitter(rng, 6))

        records.append(edr_process(
            moment, host, user, "/usr/bin/cat", "cat /etc/shadow",
            pid=pid + 14, parent="bash", parent_pid=pid + 1,
            outcome="failure",
            label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
        ))
        moment += dt.timedelta(seconds=jitter(rng, 5))

        records.append(edr_process(
            moment, host, user, "/usr/bin/find", "find /home -name 'id_rsa' -o -name '*.pem'",
            pid=pid + 18, parent="bash", parent_pid=pid + 1,
            label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
        ))

        return records
