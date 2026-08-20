"""Cloud control-plane audit telemetry.

Shaped after AWS CloudTrail because it is the most widely understood format, but
the normalizer accepts the generic keys other providers use so the module is not
AWS-only.  No cloud credentials are required or used anywhere in SENTINEL-X — the
cloud module consumes audit *records*, which is exactly how a real detection
pipeline sees them.

The risk classification of an API call lives here, as data.  Rules then reason
about ``metadata.iam_risk`` rather than maintaining their own list of dangerous
API names.
"""

from __future__ import annotations

from typing import Any

from app.models.enums import EventStatus, EventType, TelemetrySource
from app.telemetry.normalizers.base import NormalizationError, Normalizer
from app.telemetry.schema import NormalizedEvent

#: API call -> (category, risk).  Risk is about blast radius if abused.
IAM_SENSITIVE_ACTIONS: dict[str, tuple[str, str]] = {
    "AttachUserPolicy": ("privilege_grant", "critical"),
    "AttachRolePolicy": ("privilege_grant", "critical"),
    "AttachGroupPolicy": ("privilege_grant", "critical"),
    "PutUserPolicy": ("privilege_grant", "critical"),
    "PutRolePolicy": ("privilege_grant", "critical"),
    "CreateAccessKey": ("credential_creation", "high"),
    "UpdateAccessKey": ("credential_modification", "high"),
    "CreateLoginProfile": ("credential_creation", "high"),
    "UpdateLoginProfile": ("credential_modification", "high"),
    "CreateUser": ("identity_creation", "high"),
    "CreateRole": ("identity_creation", "medium"),
    "UpdateAssumeRolePolicy": ("trust_policy_change", "critical"),
    "AddUserToGroup": ("privilege_grant", "high"),
    "DeleteUserPolicy": ("privilege_change", "medium"),
    "PutBucketPolicy": ("resource_exposure", "high"),
    "PutBucketAcl": ("resource_exposure", "high"),
    "DeleteBucketPolicy": ("resource_exposure", "high"),
    "ModifyDBInstance": ("resource_exposure", "medium"),
    "AuthorizeSecurityGroupIngress": ("network_exposure", "high"),
    "StopLogging": ("defense_evasion", "critical"),
    "DeleteTrail": ("defense_evasion", "critical"),
    "UpdateTrail": ("defense_evasion", "high"),
    "DeleteFlowLogs": ("defense_evasion", "high"),
    "PutEventSelectors": ("defense_evasion", "high"),
    "DisableKey": ("defense_evasion", "high"),
    "ConsoleLogin": ("authentication", "low"),
    "AssumeRole": ("authentication", "low"),
    "GetSessionToken": ("authentication", "low"),
}

#: Read-only calls that, in volume, mean the identity is mapping the account.
CLOUD_DISCOVERY_ACTIONS = {
    "ListUsers", "ListRoles", "ListPolicies", "ListGroups", "ListAccessKeys",
    "GetAccountAuthorizationDetails", "ListAttachedUserPolicies",
    "ListAttachedRolePolicies", "ListBuckets", "DescribeInstances",
    "ListSecrets", "GetCallerIdentity", "DescribeSecurityGroups",
    "ListGroupsForUser", "GetAccountSummary",
}

#: Managed policies that grant effectively unlimited access.
HIGH_RISK_POLICIES = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
    "AdministratorAccess",
    "PowerUserAccess",
    "IAMFullAccess",
}


class CloudAuditNormalizer(Normalizer):
    source = TelemetrySource.CLOUD_AUDIT

    def normalize(self, record: dict[str, Any]) -> NormalizedEvent | None:
        api = self.first(record, "eventName", "event_name", "operation", "methodName")
        if not api:
            raise NormalizationError("cloud_audit record has no eventName")
        api = str(api)

        ts = self.timestamp(record, "eventTime", "event_time", "@timestamp", "timestamp")
        identity = record.get("userIdentity") or {}
        if not isinstance(identity, dict):
            identity = {}

        principal = (
            identity.get("userName")
            or identity.get("principalId")
            or identity.get("arn")
            or self.first(record, "user", "user_id", "principal")
        )
        if principal and ":" in str(principal) and str(principal).startswith("arn:"):
            principal = str(principal).rsplit("/", 1)[-1]

        account = identity.get("accountId") or self.first(record, "recipientAccountId", "account_id", "cloud_account")
        service = self.first(record, "eventSource", "service", default="")
        service_short = str(service).split(".")[0] if service else None
        error_code = self.first(record, "errorCode", "error_code")

        params = record.get("requestParameters") or {}
        if not isinstance(params, dict):
            params = {}

        category, risk = IAM_SENSITIVE_ACTIONS.get(api, (None, None))
        meta: dict[str, Any] = {
            "api_call": api,
            "identity_type": identity.get("type"),
            "mfa_authenticated": self._mfa(identity),
            "user_agent": self.truncate(record.get("userAgent"), 255),
            "read_only": bool(record.get("readOnly")) or api in CLOUD_DISCOVERY_ACTIONS,
        }
        if category:
            meta["iam_category"] = category
            meta["iam_risk"] = risk
        if api in CLOUD_DISCOVERY_ACTIONS:
            meta["cloud_discovery"] = True

        policy = params.get("policyArn") or params.get("policyName")
        if policy:
            meta["policy"] = policy
            meta["high_risk_policy"] = str(policy) in HIGH_RISK_POLICIES or "Administrator" in str(policy)
        if target_user := (params.get("userName") or params.get("roleName")):
            meta["target_principal"] = target_user
        if params.get("groupName"):
            meta["target_group"] = params["groupName"]

        resource = (
            params.get("policyArn")
            or params.get("bucketName")
            or params.get("roleName")
            or params.get("userName")
            or record.get("resource")
        )

        # Cloud IAM changes are privilege events; discovery calls are discovery;
        # everything else stays a generic cloud audit record.
        if category in {"privilege_grant", "credential_creation", "credential_modification", "trust_policy_change"}:
            event_type = EventType.PRIVILEGE
        elif meta.get("cloud_discovery"):
            event_type = EventType.DISCOVERY
        elif category == "authentication":
            event_type = EventType.AUTHENTICATION
        else:
            event_type = EventType.CLOUD_AUDIT

        return NormalizedEvent(
            timestamp=ts,
            event_type=event_type,
            source=self.source,
            user_id=self.truncate(principal, 128),
            source_ip=self._ip(record),
            cloud_provider=self.truncate(record.get("cloudProvider") or "aws", 32),
            cloud_account=self.truncate(account, 128),
            cloud_service=self.truncate(service_short, 64),
            cloud_resource=self.truncate(resource, 2048),
            cloud_region=self.truncate(self.first(record, "awsRegion", "region"), 48),
            action=self.truncate(api, 128),
            status=EventStatus.FAILURE if error_code else EventStatus.SUCCESS,
            message=self.truncate(record.get("errorMessage"), 2048),
            metadata={**{k: v for k, v in meta.items() if v not in (None, "")},
                      **({"error_code": error_code} if error_code else {})},
            raw_event=record,
        )

    @staticmethod
    def _mfa(identity: dict[str, Any]) -> bool | None:
        ctx = identity.get("sessionContext") or {}
        attrs = ctx.get("attributes") if isinstance(ctx, dict) else None
        if isinstance(attrs, dict) and "mfaAuthenticated" in attrs:
            return str(attrs["mfaAuthenticated"]).lower() == "true"
        return None

    @staticmethod
    def _ip(record: dict[str, Any]) -> str | None:
        value = record.get("sourceIPAddress") or record.get("source_ip")
        if not value:
            return None
        text = str(value)
        # CloudTrail writes a service principal here for AWS-internal calls.
        if text.endswith(".amazonaws.com") or text == "AWS Internal":
            return None
        return text
