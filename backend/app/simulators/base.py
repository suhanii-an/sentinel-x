"""Simulator contract and raw-record builders.

**Safety.** These simulators produce *telemetry*, and nothing else.  They do not
execute commands, write outside the database, touch the operating system, open
network connections, or reproduce exploit code.  A "privilege escalation
simulation" emits the log records a privilege escalation would have left behind;
no privilege is escalated anywhere.  This is the correct design for a detection
platform: the thing under test is the detection logic, and building real attack
tooling to test it would be both dangerous and unnecessary.

Simulators emit **source-native records**, not normalized events.  That matters:
it means every simulated attack exercises the normalizers, the validation layer
and the full pipeline, rather than injecting pre-digested data past the parts of
the system most likely to contain bugs.
"""

from __future__ import annotations

import datetime as dt
import random
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from app.models.enums import GroundTruthLabel, TelemetrySource
from app.simulators.environment import Environment


@dataclass(slots=True)
class TelemetryRecord:
    """One source-native record awaiting normalization."""

    source: str
    record: dict[str, Any]
    label: str | None = None
    label_scenario: str | None = None


@dataclass(frozen=True, slots=True)
class ScenarioSpec:
    """Everything the UI needs to describe a scenario *before* it is run."""

    key: str
    name: str
    description: str
    #: What telemetry the analyst should expect to appear.
    expected_telemetry: tuple[str, ...]
    #: Which detections should fire, by rule ID.  Compared against what actually
    #: fires, so a coverage regression is visible rather than assumed away.
    expected_detections: tuple[str, ...]
    techniques: tuple[str, ...]
    tactics: tuple[str, ...]
    default_params: dict[str, Any] = field(default_factory=dict)
    safety_notice: str = (
        "This scenario generates synthetic security telemetry only. No commands are "
        "executed, no system is modified, and no network connection is made."
    )


class Simulator(ABC):
    spec: ScenarioSpec

    @abstractmethod
    def generate(
        self,
        env: Environment,
        rng: random.Random,
        start: dt.datetime,
        params: dict[str, Any],
    ) -> list[TelemetryRecord]:
        """Produce the scenario's telemetry, ordered by time."""

    def param(self, params: dict[str, Any], key: str, default: Any) -> Any:
        value = params.get(key, self.spec.default_params.get(key, default))
        return default if value is None else value


# --------------------------------------------------------------------------
# Raw-record builders — one per telemetry source
# --------------------------------------------------------------------------
def iso(moment: dt.datetime) -> str:
    return moment.astimezone(dt.UTC).isoformat().replace("+00:00", "Z")


def linux_auth(
    moment: dt.datetime,
    host_id: str,
    program: str,
    message: str,
    *,
    pid: int | None = None,
    label: str = GroundTruthLabel.MALICIOUS,
    scenario: str | None = None,
) -> TelemetryRecord:
    return TelemetryRecord(
        source=TelemetrySource.LINUX_AUTH,
        record={
            "timestamp": iso(moment),
            "host": host_id,
            "program": program,
            "pid": pid,
            "message": message,
        },
        label=label,
        label_scenario=scenario,
    )


def edr_process(
    moment: dt.datetime,
    host_id: str,
    user_id: str,
    executable: str,
    command_line: str,
    *,
    pid: int,
    parent: str = "bash",
    parent_pid: int = 0,
    outcome: str = "success",
    label: str = GroundTruthLabel.MALICIOUS,
    scenario: str | None = None,
) -> TelemetryRecord:
    return TelemetryRecord(
        source=TelemetrySource.EDR_PROCESS,
        record={
            "@timestamp": iso(moment),
            "host": {"name": host_id},
            "user": {"name": user_id},
            "process": {
                "name": executable,
                "executable": executable,
                "pid": pid,
                "command_line": command_line,
                "working_directory": f"/home/{user_id}",
                "parent": {"name": parent, "pid": parent_pid or pid - 1},
            },
            "event": {"action": "exec", "outcome": outcome},
        },
        label=label,
        label_scenario=scenario,
    )


def network_flow(
    moment: dt.datetime,
    host_id: str,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    *,
    user_id: str | None = None,
    bytes_out: int = 0,
    bytes_in: int = 0,
    proto: str = "tcp",
    action: str = "allow",
    process: str | None = None,
    label: str = GroundTruthLabel.MALICIOUS,
    scenario: str | None = None,
) -> TelemetryRecord:
    return TelemetryRecord(
        source=TelemetrySource.NETWORK_FLOW,
        record={
            "start_time": iso(moment),
            "host": host_id,
            "user": user_id,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "proto": proto,
            "bytes_out": bytes_out,
            "bytes_in": bytes_in,
            "action": action,
            "process": process,
            "direction": "outbound",
        },
        label=label,
        label_scenario=scenario,
    )


def file_event(
    moment: dt.datetime,
    host_id: str,
    user_id: str,
    path: str,
    action: str,
    *,
    mode: str = "0644",
    sha256: str | None = None,
    process: str | None = None,
    label: str = GroundTruthLabel.MALICIOUS,
    scenario: str | None = None,
) -> TelemetryRecord:
    return TelemetryRecord(
        source=TelemetrySource.FILE_INTEGRITY,
        record={
            "time": iso(moment),
            "host": host_id,
            "user": user_id,
            "path": path,
            "action": action,
            "mode": mode,
            "hash_sha256": sha256,
            "process": process,
        },
        label=label,
        label_scenario=scenario,
    )


def windows_security(
    moment: dt.datetime,
    host_id: str,
    event_id: int,
    *,
    target_user: str | None = None,
    source_ip: str | None = None,
    logon_type: int | None = None,
    substatus: str | None = None,
    extra: dict[str, Any] | None = None,
    label: str = GroundTruthLabel.MALICIOUS,
    scenario: str | None = None,
) -> TelemetryRecord:
    record: dict[str, Any] = {
        "TimeCreated": iso(moment),
        "EventID": event_id,
        "Computer": host_id,
        "Channel": "Security",
    }
    if target_user:
        record["TargetUserName"] = target_user
    if source_ip:
        record["IpAddress"] = source_ip
    if logon_type is not None:
        record["LogonType"] = logon_type
    if substatus:
        record["SubStatus"] = substatus
    if extra:
        record.update(extra)
    return TelemetryRecord(
        source=TelemetrySource.WINDOWS_SECURITY,
        record=record,
        label=label,
        label_scenario=scenario,
    )


def cloud_audit(
    moment: dt.datetime,
    api: str,
    principal: str,
    *,
    account: str,
    source_ip: str,
    region: str = "us-east-1",
    service: str = "iam.amazonaws.com",
    request_parameters: dict[str, Any] | None = None,
    read_only: bool = False,
    mfa: bool | None = None,
    error_code: str | None = None,
    label: str = GroundTruthLabel.MALICIOUS,
    scenario: str | None = None,
) -> TelemetryRecord:
    identity: dict[str, Any] = {
        "type": "IAMUser",
        "userName": principal,
        "accountId": account,
        "arn": f"arn:aws:iam::{account}:user/{principal}",
    }
    if mfa is not None:
        identity["sessionContext"] = {"attributes": {"mfaAuthenticated": "true" if mfa else "false"}}

    record: dict[str, Any] = {
        "eventTime": iso(moment),
        "eventSource": service,
        "eventName": api,
        "userIdentity": identity,
        "sourceIPAddress": source_ip,
        "awsRegion": region,
        "recipientAccountId": account,
        "readOnly": read_only,
        "userAgent": "aws-cli/2.15.30 Python/3.11.8",
        "requestParameters": request_parameters or {},
    }
    if error_code:
        record["errorCode"] = error_code
        record["errorMessage"] = f"{api} was denied"
    return TelemetryRecord(
        source=TelemetrySource.CLOUD_AUDIT,
        record=record,
        label=label,
        label_scenario=scenario,
    )


def jitter(rng: random.Random, seconds: float, spread: float = 0.35) -> float:
    """Human-scale timing noise.

    Perfectly regular intervals would make every threshold rule trivially
    satisfiable and the demo data obviously synthetic.  Real attacks are ragged.
    """
    low = seconds * (1 - spread)
    high = seconds * (1 + spread)
    return max(0.2, rng.uniform(low, high))
