"""Detection evaluation."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from app.api.deps import DbSession, RequireAdmin, RequireViewer
from app.core.errors import NotFoundError
from app.evaluation.dataset import DEFAULT_SCENARIOS, build_dataset
from app.evaluation.runner import run_and_store
from app.models.platform import EvaluationRun
from app.services import audit

router = APIRouter(prefix="/evaluation", tags=["evaluation"])

METHODOLOGY = {
    "unit_of_analysis": "one security event",
    "positive": "the event is trigger evidence for at least one alert",
    "true_positive": "malicious-labelled event that triggered an alert",
    "false_positive": "benign-labelled event that triggered an alert",
    "false_negative": "malicious-labelled event that no alert triggered on",
    "true_negative": "benign-labelled event that no alert triggered on",
    "ambiguous_handling": (
        "Benign activity that legitimately resembles an attack — an administrator "
        "enumerating a host, a backup account sweeping the estate at 02:00, "
        "configuration management writing a cron entry, a user mistyping a password "
        "four times. Excluded from precision and recall (scoring them either way would "
        "be a claim about ground truth nobody can justify) and reported separately as "
        "false-positive pressure."
    ),
    "trigger_evidence_only": (
        "Alerts also carry context events. Counting those as detections would credit a "
        "rule for every benign event that happened to sit in the same window, inflating "
        "recall and hollowing out precision."
    ),
    "detection_latency": (
        "Event time from a scenario's first malicious event to the first alert detecting "
        "it. Measured in event time so it is stable under dataset replay, and reported "
        "separately from the platform's wall-clock processing time."
    ),
    "causality": (
        "The dataset is replayed in hourly batches rather than as one batch, so stateful "
        "rules cannot see events that had not yet occurred. Processing it all at once "
        "would produce optimistic recall."
    ),
    "isolation": (
        "Each run executes in a temporary database of its own, so evaluation never "
        "pollutes operational data and results are never influenced by what was already "
        "in the platform."
    ),
    "honesty": (
        "Every figure is computed at run time from the labelled dataset. There is no "
        "configuration, default or seed value for any metric anywhere in the codebase."
    ),
}


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    seed: int = Field(default=1337, ge=0, le=2**31 - 1)
    benign_days: int = Field(default=14, ge=1, le=60)
    include_ambiguous: bool = True
    scenarios: list[str] | None = None


def _payload(run: EvaluationRun) -> dict[str, Any]:
    config = run.config or {}
    return {
        "eval_id": run.eval_id,
        "status": run.status,
        "started_at": run.started_at.isoformat(),
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "requested_by": run.requested_by,
        "dataset": {
            "name": run.dataset_name,
            "seed": run.dataset_seed,
            "size": run.dataset_size,
            "benign": run.benign_count,
            "malicious": run.malicious_count,
            "ambiguous": run.ambiguous_count,
            "composition": config.get("dataset"),
        },
        "metrics": {
            "true_positives": run.true_positives,
            "false_positives": run.false_positives,
            "true_negatives": run.true_negatives,
            "false_negatives": run.false_negatives,
            "precision": run.precision,
            "recall": run.recall,
            "f1": run.f1,
            "median_detection_latency_ms": run.median_latency_ms,
            "p95_detection_latency_ms": run.p95_latency_ms,
            **{k: v for k, v in (config.get("metrics") or {}).items()
               if k not in {"precision", "recall", "f1"}},
        },
        "per_scenario": run.per_scenario,
        "per_rule": run.per_rule,
        "silent_rules": config.get("silent_rules", []),
        "totals": config.get("totals", {}),
        "run_info": config.get("run", {}),
        "error": run.error,
    }


@router.get("/methodology", summary="How detection performance is measured")
def methodology(_: RequireViewer) -> dict[str, Any]:
    return METHODOLOGY


@router.get("/dataset/preview", summary="Dataset composition without running an evaluation")
def dataset_preview(
    _: RequireViewer,
    seed: Annotated[int, Query(ge=0)] = 1337,
    benign_days: Annotated[int, Query(ge=1, le=60)] = 14,
) -> dict[str, Any]:
    dataset = build_dataset(seed=seed, benign_days=benign_days)
    return {
        **dataset.composition(),
        "scenario_windows": dataset.scenario_windows,
        "note": (
            "Deterministic given the seed: the same seed yields byte-identical telemetry, "
            "so any reported metric can be reproduced from this repository."
        ),
    }


@router.get("/runs", summary="Evaluation history")
def list_runs(
    db: DbSession,
    _: RequireViewer,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    total = db.execute(select(func.count()).select_from(EvaluationRun)).scalar_one()
    rows = db.execute(
        select(EvaluationRun).order_by(EvaluationRun.started_at.desc())
        .limit(limit).offset(offset)
    ).scalars().all()
    return {"total": total, "items": [_payload(r) for r in rows]}


@router.get("/latest", summary="Most recent completed evaluation")
def latest(db: DbSession, _: RequireViewer) -> dict[str, Any]:
    run = db.execute(
        select(EvaluationRun).where(EvaluationRun.status == "completed")
        .order_by(EvaluationRun.started_at.desc()).limit(1)
    ).scalars().first()
    if run is None:
        return {
            "available": False,
            "message": (
                "No evaluation has been run yet. Detection performance requires labelled "
                "ground truth and cannot be derived from live telemetry, so this platform "
                "reports nothing until an evaluation is executed."
            ),
            "methodology": METHODOLOGY,
        }
    return {"available": True, "methodology": METHODOLOGY, **_payload(run)}


@router.get("/runs/{eval_id}", summary="One evaluation run")
def get_run(eval_id: str, db: DbSession, _: RequireViewer) -> dict[str, Any]:
    run = db.execute(
        select(EvaluationRun).where(EvaluationRun.eval_id == eval_id)
    ).scalar_one_or_none()
    if run is None:
        raise NotFoundError(f"Evaluation run '{eval_id}' does not exist.")
    return {"methodology": METHODOLOGY, **_payload(run)}


@router.post("/run", status_code=status.HTTP_201_CREATED, summary="Run an evaluation")
def run_evaluation(payload: RunRequest, db: DbSession, principal: RequireAdmin) -> dict[str, Any]:
    """Measure detection performance against the labelled dataset.

    Synchronous: a full run takes a few seconds, and a background job would make
    the result harder to trust by separating the request from its measurement.
    """
    scenarios = tuple(payload.scenarios) if payload.scenarios else DEFAULT_SCENARIOS
    run = run_and_store(
        db,
        seed=payload.seed,
        benign_days=payload.benign_days,
        scenarios=scenarios,
        include_ambiguous=payload.include_ambiguous,
        requested_by=principal.username,
    )
    audit.record(
        db, actor=principal.username, actor_role=principal.role.value,
        action="evaluation_started", target_type="evaluation", target_id=run.eval_id,
        details={"seed": payload.seed, "benign_days": payload.benign_days,
                 "precision": run.precision, "recall": run.recall, "f1": run.f1},
        ip_address=principal.ip_address,
    )
    db.commit()
    db.refresh(run)
    return {"methodology": METHODOLOGY, **_payload(run)}
