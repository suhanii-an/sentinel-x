"""Scenario: cloud IAM abuse.

**No cloud credentials are used and no cloud API is called.**  The scenario
produces CloudTrail-shaped audit records locally.  That is not a shortcut - it is
how a detection pipeline sees cloud activity in production too: as audit records
delivered after the fact.

The progression is the one that actually happens: enumerate the identity graph,
grant yourself administrative access, mint credentials that survive a password
reset, then turn off the logging that would show all of it.
"""

from __future__ import annotations

import datetime as dt
import random
from typing import Any

from app.models.enums import GroundTruthLabel
from app.simulators.base import ScenarioSpec, Simulator, TelemetryRecord, cloud_audit, jitter
from app.simulators.environment import Environment

SCENARIO_KEY = "cloud_iam"

ENUMERATION_CALLS: tuple[tuple[str, str], ...] = (
    ("GetCallerIdentity", "sts.amazonaws.com"),
    ("ListUsers", "iam.amazonaws.com"),
    ("ListRoles", "iam.amazonaws.com"),
    ("ListAttachedUserPolicies", "iam.amazonaws.com"),
    ("ListAccessKeys", "iam.amazonaws.com"),
    ("GetAccountAuthorizationDetails", "iam.amazonaws.com"),
    ("ListBuckets", "s3.amazonaws.com"),
)


class CloudIAMSimulator(Simulator):
    spec = ScenarioSpec(
        key=SCENARIO_KEY,
        name="Cloud IAM Abuse",
        description=(
            "A cloud identity is used from an unfamiliar address outside working hours. It "
            "enumerates the IAM graph, attaches AdministratorAccess to itself, creates a new "
            "long-lived access key, and finally stops CloudTrail logging."
        ),
        expected_telemetry=(
            "A burst of read-only IAM and inventory API calls",
            "An AttachUserPolicy call referencing AdministratorAccess",
            "A CreateAccessKey call on the same identity",
            "A StopLogging call against the audit trail",
        ),
        expected_detections=(
            "CLOUD_DISCOVERY_001",
            "CLOUD_IAM_PRIVESC_001",
            "CLOUD_IAM_KEY_CHAIN_001",
            "CLOUD_LOG_TAMPERING_001",
        ),
        techniques=(
            "T1087", "T1087.004", "T1526", "T1098", "T1098.001",
            "T1098.003", "T1078", "T1078.004", "T1562", "T1562.008",
        ),
        tactics=("TA0007", "TA0004", "TA0003", "TA0005"),
        default_params={
            "identity": "dev-admin",
            "source_ip": "198.51.100.77",
            "enumeration_calls": 6,
            "interval_seconds": 14,
            "disable_logging": True,
        },
    )

    def generate(
        self,
        env: Environment,
        rng: random.Random,
        start: dt.datetime,
        params: dict[str, Any],
    ) -> list[TelemetryRecord]:
        identity = self.param(params, "identity", "dev-admin")
        source_ip = self.param(params, "source_ip", env.adversary_ips[2])
        enumeration_count = int(self.param(params, "enumeration_calls", 6))
        interval = float(self.param(params, "interval_seconds", 14))
        disable_logging = bool(self.param(params, "disable_logging", True))

        account = env.cloud_account
        region = env.cloud_region
        records: list[TelemetryRecord] = []
        moment = start

        # An unauthenticated session is part of the story: the credential was
        # stolen, not issued through the normal MFA-backed flow.
        records.append(cloud_audit(
            moment, "ConsoleLogin", identity, account=account, source_ip=source_ip,
            region=region, service="signin.amazonaws.com", mfa=False,
            label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
        ))
        moment += dt.timedelta(seconds=jitter(rng, 20))

        for api, service in ENUMERATION_CALLS[:enumeration_count]:
            records.append(cloud_audit(
                moment, api, identity, account=account, source_ip=source_ip,
                region=region, service=service, read_only=True, mfa=False,
                label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
            ))
            moment += dt.timedelta(seconds=jitter(rng, interval))

        # A denied attempt first: actors probe what they are allowed to do.
        records.append(cloud_audit(
            moment, "AttachUserPolicy", identity, account=account, source_ip=source_ip,
            region=region,
            request_parameters={"userName": identity,
                                "policyArn": "arn:aws:iam::aws:policy/IAMFullAccess"},
            error_code="AccessDenied", mfa=False,
            label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
        ))
        moment += dt.timedelta(seconds=jitter(rng, 25))

        records.append(cloud_audit(
            moment, "AttachUserPolicy", identity, account=account, source_ip=source_ip,
            region=region,
            request_parameters={"userName": identity,
                                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
            mfa=False,
            label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
        ))
        moment += dt.timedelta(seconds=jitter(rng, 30))

        records.append(cloud_audit(
            moment, "CreateAccessKey", identity, account=account, source_ip=source_ip,
            region=region, request_parameters={"userName": identity}, mfa=False,
            label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
        ))
        moment += dt.timedelta(seconds=jitter(rng, 22))

        records.append(cloud_audit(
            moment, "AuthorizeSecurityGroupIngress", identity, account=account,
            source_ip=source_ip, region=region, service="ec2.amazonaws.com",
            request_parameters={"groupId": "sg-0a1b2c3d4e5f", "cidrIp": "0.0.0.0/0",
                                "fromPort": 22, "toPort": 22},
            mfa=False,
            label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
        ))

        if disable_logging:
            moment += dt.timedelta(seconds=jitter(rng, 35))
            records.append(cloud_audit(
                moment, "StopLogging", identity, account=account, source_ip=source_ip,
                region=region, service="cloudtrail.amazonaws.com",
                request_parameters={"name": "corp-org-trail"}, mfa=False,
                label=GroundTruthLabel.MALICIOUS, scenario=SCENARIO_KEY,
            ))

        return records
