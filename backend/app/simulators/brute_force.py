"""Scenario: SSH brute force.

Generates the auth.log records a password-guessing run against one host leaves
behind.  Optionally ends in a success, which is what turns an attempt into a
compromise and triggers the sequence rule rather than only the threshold rule.

A spray variant is included because guessing and spraying look different in the
telemetry and need different detections — generating only the easy one would let
BRUTE_FORCE_002 pass unexercised.
"""

from __future__ import annotations

import datetime as dt
import random
from typing import Any

from app.models.enums import GroundTruthLabel
from app.simulators.base import ScenarioSpec, Simulator, TelemetryRecord, jitter, linux_auth
from app.simulators.environment import Environment

SCENARIO_KEY = "brute_force"


class BruteForceSimulator(Simulator):
    spec = ScenarioSpec(
        key=SCENARIO_KEY,
        name="SSH Brute Force",
        description=(
            "An external address attempts repeated SSH password authentication against an "
            "account on a production host. With 'succeed' enabled the final attempt is "
            "accepted, representing a successful credential compromise."
        ),
        expected_telemetry=(
            "Linux authentication records (sshd) showing repeated 'Failed password' entries",
            "An 'Accepted password' record when the run succeeds",
            "Session establishment records following a successful authentication",
        ),
        expected_detections=("BRUTE_FORCE_001", "BRUTE_FORCE_003"),
        techniques=("T1110", "T1110.001", "T1078"),
        tactics=("TA0006", "TA0001"),
        default_params={
            "target_host": "LINUX-03",
            "target_user": "admin",
            "source_ip": "203.0.113.44",
            "attempts": 11,
            "interval_seconds": 7,
            "succeed": True,
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
        attempts = int(self.param(params, "attempts", 11))
        interval = float(self.param(params, "interval_seconds", 7))
        succeed = bool(self.param(params, "succeed", True))

        records: list[TelemetryRecord] = []
        moment = start
        port = rng.randint(40000, 60000)

        for index in range(attempts):
            # Half the attempts target a username that does not exist, which is
            # what an attacker working from a wordlist actually produces.
            # A narrow invalid-name pool keeps this a *guessing* attack against
            # one account. Widening it would also satisfy the spraying rule, and
            # the two attacks deserve separate scenarios.
            invalid = index % 3 == 0
            attempted_user = rng.choice(["root", "ubuntu"]) if invalid else user
            prefix = "Failed password for invalid user" if invalid else "Failed password for"
            records.append(linux_auth(
                moment, host, "sshd",
                f"{prefix} {attempted_user} from {source_ip} port {port + index} ssh2",
                pid=4021 + index,
                label=GroundTruthLabel.MALICIOUS,
                scenario=SCENARIO_KEY,
            ))
            moment += dt.timedelta(seconds=jitter(rng, interval))

        if succeed:
            records.append(linux_auth(
                moment, host, "sshd",
                f"Accepted password for {user} from {source_ip} port {port + attempts} ssh2",
                pid=4021 + attempts,
                label=GroundTruthLabel.MALICIOUS,
                scenario=SCENARIO_KEY,
            ))
            moment += dt.timedelta(seconds=jitter(rng, 2))
            records.append(linux_auth(
                moment, host, "sshd",
                f"pam_unix(sshd:session): session opened for user {user}(uid=1000) by (uid=0)",
                pid=4021 + attempts,
                label=GroundTruthLabel.MALICIOUS,
                scenario=SCENARIO_KEY,
            ))

        return records


class PasswordSprayingSimulator(Simulator):
    spec = ScenarioSpec(
        key="password_spraying",
        name="Password Spraying",
        description=(
            "One external address attempts a small number of common passwords against many "
            "accounts, staying below per-account lockout thresholds. Invisible to any rule "
            "that counts failures per user."
        ),
        expected_telemetry=(
            "Linux authentication failures spread across several distinct accounts",
            "A low attempt count per account, from a single source address",
        ),
        expected_detections=("BRUTE_FORCE_002",),
        techniques=("T1110", "T1110.003"),
        tactics=("TA0006",),
        default_params={
            "target_host": "LINUX-03",
            "source_ip": "203.0.113.91",
            "accounts": 7,
            "attempts_per_account": 2,
            "interval_seconds": 26,
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
        source_ip = self.param(params, "source_ip", env.adversary_ips[1])
        account_count = int(self.param(params, "accounts", 7))
        per_account = int(self.param(params, "attempts_per_account", 2))
        interval = float(self.param(params, "interval_seconds", 26))

        candidates = [u.user_id for u in env.users if u.user_type == "human"]
        candidates += ["svc-deploy", "jenkins", "postgres", "gitlab"]
        targets = candidates[:account_count]

        records: list[TelemetryRecord] = []
        moment = start
        port = rng.randint(40000, 60000)

        for round_index in range(per_account):
            for offset, account in enumerate(targets):
                records.append(linux_auth(
                    moment, host, "sshd",
                    f"Failed password for {account} from {source_ip} "
                    f"port {port + offset + round_index * 100} ssh2",
                    pid=5100 + offset,
                    label=GroundTruthLabel.MALICIOUS,
                    scenario="password_spraying",
                ))
                moment += dt.timedelta(seconds=jitter(rng, interval))

        return records
