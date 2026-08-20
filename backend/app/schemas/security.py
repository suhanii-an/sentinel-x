"""API schemas for the core security objects."""

from __future__ import annotations

import datetime as dt
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.common import ORMModel


# --------------------------------------------------------------------- events
class EventSummary(ORMModel):
    event_id: str
    timestamp: dt.datetime
    event_type: str
    source: str
    host_ref: str | None = None
    user_ref: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    action: str | None = None
    status: str
    process_name: str | None = None
    is_demo: bool = False


class EventDetail(EventSummary):
    ingested_at: dt.datetime
    destination_port: int | None = None
    protocol: str | None = None
    bytes_out: int | None = None
    process_id: int | None = None
    parent_process: str | None = None
    command_line: str | None = None
    file_path: str | None = None
    file_hash: str | None = None
    cloud_provider: str | None = None
    cloud_account: str | None = None
    cloud_service: str | None = None
    cloud_resource: str | None = None
    cloud_region: str | None = None
    message: str | None = None
    #: Serialization alias only, deliberately. A validation alias of "metadata"
    #: would make Pydantic read the attribute ``metadata`` from the ORM object,
    #: which on any SQLAlchemy model is the declarative MetaData registry rather
    #: than the event's enrichment dictionary.
    meta: dict[str, Any] = Field(default_factory=dict, serialization_alias="metadata")
    raw_event: dict[str, Any] = Field(default_factory=dict)
    label: str | None = None
    label_scenario: str | None = None

    model_config = ConfigDict(from_attributes=True)


# --------------------------------------------------------------------- alerts
class AlertSummary(ORMModel):
    alert_id: str
    detected_at: dt.datetime
    created_at: dt.datetime
    rule_id: str
    rule_name: str
    rule_type: str
    title: str
    severity: str
    confidence: float
    risk_score: float
    status: str
    host_ref: str | None = None
    user_ref: str | None = None
    source_ip: str | None = None
    technique_ids: list[str] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)
    detection_latency_ms: int = 0
    is_demo: bool = False
    incident_id: str | None = None


class AlertDetail(AlertSummary):
    description: str = ""
    explanation: list[str] = Field(default_factory=list)
    risk_breakdown: list[dict[str, Any]] = Field(default_factory=list)
    entity_keys: list[str] = Field(default_factory=list)
    first_event_at: dt.datetime
    last_event_at: dt.datetime
    processing_latency_ms: int = 0
    triaged_by: str | None = None
    triaged_at: dt.datetime | None = None
    false_positive_reason: str | None = None
    evidence: list[EventSummary] = Field(default_factory=list)


class AlertStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str
    #: Required when moving to false_positive: an unexplained dismissal is not a
    #: triage decision, it is a lost finding.
    reason: str | None = Field(default=None, max_length=2000)


# ------------------------------------------------------------------ incidents
class IncidentSummary(ORMModel):
    incident_id: str
    title: str
    severity: str
    status: str
    confidence: float
    risk_score: float
    first_seen: dt.datetime
    last_seen: dt.datetime
    alert_count: int
    event_count: int
    affected_hosts: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    technique_ids: list[str] = Field(default_factory=list)
    assigned_to: str | None = None
    is_demo: bool = False


class TechniqueMapping(BaseModel):
    technique_id: str
    name: str
    tactic_id: str | None = None
    tactic_name: str | None = None
    confidence: float
    first_observed: dt.datetime
    last_observed: dt.datetime
    detected_at: dt.datetime
    evidence_event_ids: list[str] = Field(default_factory=list)
    source_rule_ids: list[str] = Field(default_factory=list)
    url: str | None = None


class AnalystNoteOut(ORMModel):
    author: str
    body: str
    created_at: dt.datetime


class IncidentDetail(IncidentSummary):
    summary: str = ""
    created_at: dt.datetime
    updated_at: dt.datetime
    duration_seconds: int = 0
    targeted_users: list[str] = Field(default_factory=list)
    source_ips: list[str] = Field(default_factory=list)
    destination_ips: list[str] = Field(default_factory=list)
    risk_breakdown: list[dict[str, Any]] = Field(default_factory=list)
    confidence_breakdown: list[dict[str, Any]] = Field(default_factory=list)
    correlation_reason: dict[str, Any] = Field(default_factory=dict)
    attack_chain: list[dict[str, Any]] = Field(default_factory=list)
    ioc_matches: list[dict[str, Any]] = Field(default_factory=list)
    mttr_seconds: int | None = None
    closed_at: dt.datetime | None = None
    false_positive_reason: str | None = None
    alerts: list[AlertSummary] = Field(default_factory=list)
    techniques: list[TechniqueMapping] = Field(default_factory=list)
    notes: list[AnalystNoteOut] = Field(default_factory=list)


class IncidentStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str
    reason: str | None = Field(default=None, max_length=2000)
    assigned_to: str | None = Field(default=None, max_length=128)


class NoteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    body: str = Field(min_length=1, max_length=5000)


# ------------------------------------------------------------------- entities
class HostSummary(ORMModel):
    host_id: str
    hostname: str
    os_family: str
    os_version: str | None = None
    ip_address: str | None = None
    environment: str
    criticality: int
    risk_score: float
    is_isolated: bool
    tags: list[str] = Field(default_factory=list)
    first_seen: dt.datetime
    last_seen: dt.datetime


class HostDetail(HostSummary):
    notes: str | None = None
    isolated_at: dt.datetime | None = None
    event_count: int = 0
    alert_counts: dict[str, int] = Field(default_factory=dict)
    open_incidents: list[IncidentSummary] = Field(default_factory=list)
    recent_alerts: list[AlertSummary] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    top_processes: list[dict[str, Any]] = Field(default_factory=list)
    network_peers: list[dict[str, Any]] = Field(default_factory=list)


class UserSummary(ORMModel):
    user_id: str
    display_name: str | None = None
    user_type: str
    department: str | None = None
    is_privileged: bool
    is_disabled: bool
    risk_score: float
    tags: list[str] = Field(default_factory=list)
    first_seen: dt.datetime
    last_seen: dt.datetime


class UserDetail(UserSummary):
    domain: str | None = None
    disabled_at: dt.datetime | None = None
    event_count: int = 0
    alert_counts: dict[str, int] = Field(default_factory=dict)
    source_ips: list[dict[str, Any]] = Field(default_factory=list)
    hosts: list[dict[str, Any]] = Field(default_factory=list)
    authentication_summary: dict[str, Any] = Field(default_factory=dict)
    baseline: dict[str, Any] = Field(default_factory=dict)
    open_incidents: list[IncidentSummary] = Field(default_factory=list)
    recent_alerts: list[AlertSummary] = Field(default_factory=list)


# ----------------------------------------------------------------------- iocs
class IOCSummary(ORMModel):
    ioc_id: str
    indicator: str
    ioc_type: str
    source: str
    confidence: float
    severity: str
    is_active: bool
    is_blocked: bool
    match_count: int
    tags: list[str] = Field(default_factory=list)
    first_seen: dt.datetime
    last_seen: dt.datetime | None = None


class IOCDetail(IOCSummary):
    description: str | None = None
    matched_events: list[EventSummary] = Field(default_factory=list)
    related_incidents: list[IncidentSummary] = Field(default_factory=list)
    affected_hosts: list[str] = Field(default_factory=list)


class IOCCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    indicator: str = Field(min_length=1, max_length=512)
    ioc_type: str
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    severity: str = "medium"
    source: str = Field(default="manual", max_length=128)
    description: str | None = Field(default=None, max_length=2000)
    tags: list[str] = Field(default_factory=list, max_length=20)


# ----------------------------------------------------------------- detections
class DetectionRuleSummary(ORMModel):
    rule_id: str
    name: str
    description: str
    rule_type: str
    severity: str
    confidence: float
    enabled: bool
    category: str
    mitre_techniques: list[str] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)
    trigger_count: int
    last_triggered_at: dt.datetime | None = None
    created_at: dt.datetime
    updated_at: dt.datetime
    version: str
    author: str


class DetectionRuleDetail(DetectionRuleSummary):
    definition: dict[str, Any] = Field(default_factory=dict)
    source_path: str | None = None
    references: list[str] = Field(default_factory=list)
    false_positives: list[str] = Field(default_factory=list)
    tests: list[dict[str, Any]] = Field(default_factory=list)


class RuleToggle(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool
    reason: str | None = Field(default=None, max_length=1000)
