"""Scenario: the full intrusion chain.

Composes the individual scenarios into one coherent story, sharing the account,
the host and the source address so that the correlation engine has something real
to correlate — this is the scenario that demonstrates the whole platform end to
end, and it is what the one-click demo runs.

The narrative:

    external brute force -> credential compromise -> host discovery
      -> privilege escalation -> persistence -> lateral movement
      -> cloud identity abuse -> egress

Stage timings are compressed so the chain completes in a few minutes of event
time rather than the hours a real intrusion would take.  This is a deliberate
demonstration choice and is stated in the UI, not hidden.
"""

from __future__ import annotations

import datetime as dt
import random
from typing import Any

from app.models.enums import GroundTruthLabel
from app.simulators.base import ScenarioSpec, Simulator, TelemetryRecord, jitter, network_flow
from app.simulators.brute_force import BruteForceSimulator
from app.simulators.cloud_iam import CloudIAMSimulator
from app.simulators.credential_abuse import CredentialAbuseSimulator
from app.simulators.discovery import DiscoverySimulator
from app.simulators.environment import Environment
from app.simulators.lateral_movement import LateralMovementSimulator
from app.simulators.persistence import PersistenceSimulator
from app.simulators.privilege_escalation import PrivilegeEscalationSimulator

SCENARIO_KEY = "full_chain"


class FullChainSimulator(Simulator):
    spec = ScenarioSpec(
        key=SCENARIO_KEY,
        name="Full Attack Chain",
        description=(
            "A complete intrusion against one host and account: external brute force, "
            "credential compromise, host enumeration, privilege escalation, persistence, "
            "lateral movement to three further hosts, cloud identity abuse, and data egress. "
            "Every stage shares entities with the next, so the correlation engine assembles "
            "them into a single incident rather than eight unrelated alerts."
        ),
        expected_telemetry=(
            "Linux authentication records: repeated failures then a success",
            "Endpoint process telemetry for enumeration and escalation",
            "File integrity events for four persistence mechanisms",
            "Internal network flows to remote-administration ports",
            "Cloud audit records covering enumeration, privilege grant and log tampering",
            "An outbound transfer to external infrastructure",
        ),
        expected_detections=(
            "BRUTE_FORCE_001",
            "BRUTE_FORCE_003",
            "CREDENTIAL_FILE_ACCESS_001",
            "ACCOUNT_DISCOVERY_001",
            "PRIVESC_SUID_ENUM_001",
            "PRIVESC_SUDO_CHAIN_001",
            "PRIVESC_GROUP_CHANGE_001",
            "PERSISTENCE_SCHEDULED_TASK_001",
            "PERSISTENCE_BACKDOOR_ACCOUNT_001",
            "VALID_ACCOUNT_ABUSE_001",
            "LATERAL_MOVEMENT_001",
            "LATERAL_BREADTH_001",
            "LATERAL_TOOL_TRANSFER_001",
            "CLOUD_DISCOVERY_001",
            "CLOUD_IAM_PRIVESC_001",
            "CLOUD_IAM_KEY_CHAIN_001",
            "CLOUD_LOG_TAMPERING_001",
        ),
        techniques=(
            "T1110", "T1110.001", "T1078", "T1087", "T1087.001", "T1082", "T1033",
            "T1548", "T1548.001", "T1548.003", "T1098", "T1098.004", "T1136", "T1136.001",
            "T1053", "T1053.003", "T1543", "T1543.002", "T1021", "T1021.004",
            "T1105", "T1570", "T1552", "T1552.004", "T1078.004", "T1098.001",
            "T1098.003", "T1526", "T1087.004", "T1562", "T1562.008", "T1041",
        ),
        tactics=("TA0001", "TA0003", "TA0004", "TA0005", "TA0006", "TA0007", "TA0008", "TA0010", "TA0011"),
        default_params={
            "target_host": "LINUX-03",
            "target_user": "admin",
            "source_ip": "203.0.113.44",
            "cloud_identity": "dev-admin",
            "include_cloud": True,
            "stage_gap_seconds": 22,
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
        cloud_identity = self.param(params, "cloud_identity", "dev-admin")
        include_cloud = bool(self.param(params, "include_cloud", True))
        gap = float(self.param(params, "stage_gap_seconds", 22))

        shared = {"target_host": host, "target_user": user, "source_ip": source_ip}
        records: list[TelemetryRecord] = []
        moment = start

        def run(simulator: Simulator, extra: dict[str, Any] | None = None) -> None:
            nonlocal moment, records
            produced = simulator.generate(env, rng, moment, {**shared, **(extra or {})})
            records.extend(produced)
            moment = _latest(produced, moment) + dt.timedelta(seconds=jitter(rng, gap))

        # 1. Initial access -------------------------------------------------
        run(BruteForceSimulator(), {"attempts": 9, "interval_seconds": 6, "succeed": True})
        # 2. Credential abuse on the compromised session ---------------------
        run(CredentialAbuseSimulator())
        # 3. Discovery -------------------------------------------------------
        run(DiscoverySimulator(), {"command_count": 9, "interval_seconds": 7})
        # 4. Privilege escalation -------------------------------------------
        run(PrivilegeEscalationSimulator())
        # 5. Persistence -----------------------------------------------------
        run(PersistenceSimulator(), {"backdoor_account": "svc-telemetry"})
        # 6. Lateral movement ------------------------------------------------
        run(LateralMovementSimulator(), {
            "source_host": host,
            "target_hosts": ["LINUX-07", "LINUX-11", "LINUX-DB-02"],
            "interval_seconds": 30,
        })

        # 7. Cloud identity abuse -------------------------------------------
        if include_cloud:
            # The cloud stage runs from the same adversary address as the host
            # stages. That is both realistic (one operator, one egress point) and
            # load-bearing: the shared address is the only entity linking the
            # host chain to the cloud chain, and without it the correlation
            # engine would correctly refuse to merge them into one incident.
            run(CloudIAMSimulator(), {
                "identity": cloud_identity,
                "enumeration_calls": 6,
                "interval_seconds": 11,
            })

        # 8. Egress ----------------------------------------------------------
        records.append(network_flow(
            moment, "LINUX-DB-02", env.host_ip("LINUX-DB-02"), "198.51.100.200", 443,
            user_id=user, bytes_out=48_211_904, bytes_in=8_120, process="curl",
            label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
        ))

        records.sort(key=lambda r: _record_time(r))
        return records


def _record_time(record: TelemetryRecord) -> str:
    for key in ("timestamp", "@timestamp", "start_time", "time", "TimeCreated", "eventTime"):
        if key in record.record:
            return str(record.record[key])
    return ""


def _latest(records: list[TelemetryRecord], fallback: dt.datetime) -> dt.datetime:
    from app.core.timeutils import parse_timestamp

    latest = fallback
    for record in records:
        raw = _record_time(record)
        if not raw:
            continue
        try:
            moment = parse_timestamp(raw)
        except ValueError:
            continue
        latest = max(latest, moment)
    return latest
