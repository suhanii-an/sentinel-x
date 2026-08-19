"""Platform-side records: logins, simulations, evaluations, hunts, baselines."""

from __future__ import annotations

import datetime as dt

from sqlalchemy import Boolean, Float, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, JSONVariant
from app.core.timeutils import UTCDateTime, utcnow
from app.models.enums import Role, SimulationStatus


class AppUser(Base):
    """An account that signs in to SENTINEL-X."""

    __tablename__ = "app_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    full_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    #: bcrypt hash.  Plaintext passwords never touch this model.
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default=Role.ANALYST)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_login_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<AppUser {self.username} ({self.role})>"


class SimulationRun(Base):
    """One execution of an attack simulation.

    Every synthetic event is tagged with its run, which is what makes it possible
    to say honestly "these 47 events are simulated, and here is the run that
    produced them".
    """

    __tablename__ = "simulation_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    scenario: Mapped[str] = mapped_column(String(64), index=True)
    scenario_name: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(24), default=SimulationStatus.PENDING, index=True)

    started_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    finished_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)

    parameters: Mapped[dict] = mapped_column(JSONVariant, default=dict)
    #: Explicit RNG seed so a run is reproducible and can be cited in a report.
    seed: Mapped[int] = mapped_column(Integer, default=0)

    event_count: Mapped[int] = mapped_column(Integer, default=0)
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    incident_ids: Mapped[list] = mapped_column(JSONVariant, default=list)
    alert_ids: Mapped[list] = mapped_column(JSONVariant, default=list)
    #: Techniques the scenario *intended* to exercise; compared against what was
    #: actually detected, which is how coverage gaps become visible.
    expected_techniques: Mapped[list] = mapped_column(JSONVariant, default=list)
    detected_techniques: Mapped[list] = mapped_column(JSONVariant, default=list)
    stage_log: Mapped[list] = mapped_column(JSONVariant, default=list)

    requested_by: Mapped[str] = mapped_column(String(128), default="system")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class EvaluationRun(Base):
    """A measured detection-performance run.

    Metrics are computed from a labelled dataset at run time.  Nothing in this
    table is ever written by hand.
    """

    __tablename__ = "evaluation_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    eval_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    started_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    finished_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="running", index=True)

    dataset_name: Mapped[str] = mapped_column(String(128))
    dataset_seed: Mapped[int] = mapped_column(Integer, default=0)
    dataset_size: Mapped[int] = mapped_column(Integer, default=0)
    benign_count: Mapped[int] = mapped_column(Integer, default=0)
    malicious_count: Mapped[int] = mapped_column(Integer, default=0)
    ambiguous_count: Mapped[int] = mapped_column(Integer, default=0)

    true_positives: Mapped[int] = mapped_column(Integer, default=0)
    false_positives: Mapped[int] = mapped_column(Integer, default=0)
    true_negatives: Mapped[int] = mapped_column(Integer, default=0)
    false_negatives: Mapped[int] = mapped_column(Integer, default=0)
    precision: Mapped[float] = mapped_column(Float, default=0.0)
    recall: Mapped[float] = mapped_column(Float, default=0.0)
    f1: Mapped[float] = mapped_column(Float, default=0.0)
    median_latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    p95_latency_ms: Mapped[float] = mapped_column(Float, default=0.0)

    per_scenario: Mapped[list] = mapped_column(JSONVariant, default=list)
    per_rule: Mapped[list] = mapped_column(JSONVariant, default=list)
    config: Mapped[dict] = mapped_column(JSONVariant, default=dict)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_by: Mapped[str] = mapped_column(String(128), default="system")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class SavedHunt(Base):
    __tablename__ = "saved_hunts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    #: A validated HuntQuery document — never a SQL string.
    query: Mapped[dict] = mapped_column(JSONVariant, default=dict)
    created_by: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_run_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    run_count: Mapped[int] = mapped_column(Integer, default=0)
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False)


class BehaviorBaseline(Base):
    """Per-entity behavioural profile backing the anomaly detectors.

    Kept deliberately simple and interpretable: observed login hours, known
    source IPs, known hosts.  The platform makes no claim to machine learning,
    and the UI explains every anomaly in plain language ("login at 02:13 is
    outside this account's observed 09:00-18:00 window, 34 prior observations").
    """

    __tablename__ = "behavior_baselines"
    __table_args__ = (
        UniqueConstraint("entity_type", "entity_ref", "feature", name="uq_baseline_entity_feature"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    entity_type: Mapped[str] = mapped_column(String(24), index=True)  # user | host | ip
    entity_ref: Mapped[str] = mapped_column(String(128), index=True)
    feature: Mapped[str] = mapped_column(String(64), index=True)
    value: Mapped[dict] = mapped_column(JSONVariant, default=dict)
    observation_count: Mapped[int] = mapped_column(Integer, default=0)
    first_observed: Mapped[dt.datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)


Index("ix_sim_scenario_started", SimulationRun.scenario, SimulationRun.started_at.desc())
Index("ix_eval_started", EvaluationRun.started_at.desc())
