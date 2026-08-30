"""Attack simulation."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from app.api.deps import DbSession, RequireAnalyst, RequireViewer
from app.core.errors import NotFoundError, ValidationFailed
from app.models.platform import SimulationRun
from app.services import audit
from app.services.simulation_runner import ScenarioNotFound, coverage_report, run_scenario
from app.simulators.registry import get_simulator, list_specs, scenario_keys

router = APIRouter(prefix="/simulations", tags=["simulations"])

GLOBAL_SAFETY_NOTICE = (
    "SENTINEL-X attack simulations generate synthetic security telemetry only. They do "
    "not execute commands, exploit vulnerabilities, modify any operating system, create "
    "accounts, install persistence, open network connections or contact any external "
    "system. A 'privilege escalation simulation' emits the log records an escalation "
    "would leave behind; no privilege is escalated anywhere."
)


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenario: str
    #: Reproducibility: the same seed regenerates identical telemetry.
    seed: int | None = Field(default=None, ge=0, le=2**31 - 1)
    parameters: dict[str, Any] = Field(default_factory=dict)
    mark_as_demo: bool = True


@router.get("/scenarios", summary="Available scenarios")
def scenarios(_: RequireViewer) -> dict[str, Any]:
    """Full scenario descriptions, shown before a run so the analyst knows what
    to expect and what the safety boundary is."""
    return {
        "safety_notice": GLOBAL_SAFETY_NOTICE,
        "scenarios": [
            {
                "key": spec.key,
                "name": spec.name,
                "description": spec.description,
                "expected_telemetry": list(spec.expected_telemetry),
                "expected_detections": list(spec.expected_detections),
                "techniques": list(spec.techniques),
                "tactics": list(spec.tactics),
                "default_parameters": spec.default_params,
                "safety_notice": spec.safety_notice,
            }
            for spec in list_specs()
        ],
    }


@router.get("/runs", summary="Simulation history")
def list_runs(
    db: DbSession,
    _: RequireViewer,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    scenario: str | None = None,
) -> dict[str, Any]:
    stmt = select(SimulationRun)
    count_stmt = select(func.count()).select_from(SimulationRun)
    if scenario:
        stmt = stmt.where(SimulationRun.scenario == scenario)
        count_stmt = count_stmt.where(SimulationRun.scenario == scenario)

    total = db.execute(count_stmt).scalar_one()
    rows = db.execute(
        stmt.order_by(SimulationRun.started_at.desc()).limit(limit).offset(offset)
    ).scalars().all()
    return {
        "total": total,
        "items": [_run_payload(r) for r in rows],
    }


def _run_payload(run: SimulationRun) -> dict[str, Any]:
    return {
        "run_id": run.run_id,
        "scenario": run.scenario,
        "scenario_name": run.scenario_name,
        "status": run.status,
        "started_at": run.started_at.isoformat(),
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "duration_ms": run.duration_ms,
        "seed": run.seed,
        "parameters": run.parameters,
        "event_count": run.event_count,
        "alert_count": run.alert_count,
        "alert_ids": run.alert_ids,
        "incident_ids": run.incident_ids,
        "stage_log": run.stage_log,
        "coverage": coverage_report(run),
        "error": run.error,
        "requested_by": run.requested_by,
    }


@router.get("/runs/{run_id}", summary="One simulation run")
def get_run(run_id: str, db: DbSession, _: RequireViewer) -> dict[str, Any]:
    run = db.execute(
        select(SimulationRun).where(SimulationRun.run_id == run_id)
    ).scalar_one_or_none()
    if run is None:
        raise NotFoundError(f"Simulation run '{run_id}' does not exist.")
    return _run_payload(run)


@router.post("/run", status_code=status.HTTP_201_CREATED, summary="Run a scenario")
def run(payload: RunRequest, db: DbSession, principal: RequireAnalyst) -> dict[str, Any]:
    """Generate a scenario's telemetry and drive it through the full pipeline.

    Synchronous on purpose. The whole chain completes in well under a second, and
    a background job would add moving parts for no benefit while making the demo
    harder to follow.
    """
    if payload.scenario not in scenario_keys():
        raise ValidationFailed(
            f"Unknown scenario '{payload.scenario}'. "
            f"Available: {', '.join(scenario_keys())}"
        )

    try:
        run_row, result = run_scenario(
            db,
            payload.scenario,
            params=payload.parameters,
            seed=payload.seed,
            requested_by=principal.username,
            is_demo=payload.mark_as_demo,
        )
    except ScenarioNotFound as exc:
        raise NotFoundError(f"Scenario '{payload.scenario}' does not exist.") from exc

    audit.record(
        db, actor=principal.username, actor_role=principal.role.value,
        action="simulation_started", target_type="simulation", target_id=run_row.run_id,
        details={"scenario": payload.scenario, "seed": run_row.seed,
                 "events": run_row.event_count, "alerts": run_row.alert_count},
        ip_address=principal.ip_address,
    )
    db.commit()
    db.refresh(run_row)

    spec = get_simulator(payload.scenario).spec
    return {
        "run": _run_payload(run_row),
        "pipeline": result.summary(),
        "incidents": sorted({i.incident_id for i in result.incidents}),
        "expected_detections": list(spec.expected_detections),
        "actual_detections": sorted({a.rule_id for a in result.alerts}),
        "detections_missing": sorted(
            set(spec.expected_detections) - {a.rule_id for a in result.alerts}
        ),
        "safety_notice": GLOBAL_SAFETY_NOTICE,
    }
