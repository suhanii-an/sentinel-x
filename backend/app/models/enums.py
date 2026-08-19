"""Shared vocabularies.

These are stored as plain strings rather than native database enums: adding a new
event type or detection status is then a code change, not a migration that locks
a large table.  Validation happens in the Pydantic layer at the API boundary.
"""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def from_score(cls, score: float) -> Severity:
        """Map a 0-100 risk score onto the severity bands documented in
        ``docs/detection-engine.md``."""
        if score >= 76:
            return cls.CRITICAL
        if score >= 51:
            return cls.HIGH
        if score >= 26:
            return cls.MEDIUM
        return cls.LOW

    @classmethod
    def max_of(cls, values) -> Severity:
        best = cls.INFO
        for v in values:
            sev = cls(v)
            if sev.rank > best.rank:
                best = sev
        return best


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# Normalised weight used by the risk model (see app/correlation/risk.py).
SEVERITY_WEIGHT: dict[str, float] = {
    Severity.INFO: 0.10,
    Severity.LOW: 0.30,
    Severity.MEDIUM: 0.55,
    Severity.HIGH: 0.80,
    Severity.CRITICAL: 1.00,
}


class EventType(StrEnum):
    AUTHENTICATION = "authentication"
    PROCESS = "process"
    NETWORK = "network"
    FILE = "file"
    CLOUD_AUDIT = "cloud_audit"
    ACCOUNT = "account"
    PRIVILEGE = "privilege"
    SCHEDULED_TASK = "scheduled_task"
    SERVICE = "service"
    DISCOVERY = "discovery"


class EventStatus(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    ATTEMPT = "attempt"
    UNKNOWN = "unknown"


class TelemetrySource(StrEnum):
    LINUX_AUTH = "linux_auth"
    WINDOWS_SECURITY = "windows_security"
    LINUX_AUDITD = "linux_auditd"
    EDR_PROCESS = "edr_process"
    NETWORK_FLOW = "network_flow"
    FILE_INTEGRITY = "file_integrity"
    CLOUD_AUDIT = "cloud_audit"
    NORMALIZED = "normalized"


class AlertStatus(StrEnum):
    NEW = "new"
    INVESTIGATING = "investigating"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class IncidentStatus(StrEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class RuleType(StrEnum):
    MATCH = "match"
    THRESHOLD = "threshold"
    SEQUENCE = "sequence"
    IOC = "ioc"
    ANOMALY = "anomaly"


class IOCType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    USERNAME = "username"
    HOSTNAME = "hostname"


class Role(StrEnum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"

    @property
    def level(self) -> int:
        return {"viewer": 1, "analyst": 2, "admin": 3}[self.value]


class ResponseActionType(StrEnum):
    ISOLATE_HOST = "isolate_host"
    RELEASE_HOST = "release_host"
    DISABLE_ACCOUNT = "disable_account"
    ENABLE_ACCOUNT = "enable_account"
    BLOCK_IOC = "block_ioc"
    COLLECT_EVIDENCE = "collect_evidence"
    ESCALATE_INCIDENT = "escalate_incident"
    RESET_CREDENTIALS = "reset_credentials"
    REVOKE_CLOUD_SESSION = "revoke_cloud_session"


class GroundTruthLabel(StrEnum):
    """Evaluation-only label attached to synthetic telemetry."""

    BENIGN = "benign"
    MALICIOUS = "malicious"
    AMBIGUOUS = "ambiguous"


class SimulationStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
