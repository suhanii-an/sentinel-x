"""Response actions and playbooks."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from app.api.deps import DbSession, RequireAnalyst, RequireViewer
from app.core.errors import NotFoundError
from app.models.incidents import Incident
from app.models.operations import ResponseAction
from app.response.playbooks import PLAYBOOKS
from app.response.service import (
    available_actions,
    execute_action,
    get_playbook,
    incident_playbooks,
    recommended_actions,
)
from app.services import audit

router = APIRouter(prefix="/response", tags=["response"])

SIMULATION_NOTICE = (
    "All containment actions in this deployment are SIMULATED. SENTINEL-X records that "
    "an action was rehearsed and updates its own state; it does not contact any EDR "
    "platform, directory service, firewall or cloud provider, and no real host, account "
    "or network control is affected. Evidence collection is the one action that is "
    "genuinely performed, because assembling a package from stored records is something "
    "the platform can do completely and correctly."
)


class ExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action_type: str
    target: str = Field(min_length=1, max_length=255)
    incident_id: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    justification: str | None = Field(default=None, max_length=2000)
    playbook_id: str | None = None
    playbook_step: int | None = Field(default=None, ge=1, le=100)


@router.get("/actions", summary="Available response actions")
def actions(_: RequireViewer) -> dict[str, Any]:
    return {"simulation_notice": SIMULATION_NOTICE, "actions": available_actions()}


@router.get("/playbooks", summary="All playbooks")
def playbooks(_: RequireViewer) -> list[dict[str, Any]]:
    return [p.to_dict() for p in PLAYBOOKS.values()]


@router.get("/playbooks/{playbook_id}", summary="One playbook")
def playbook(playbook_id: str, _: RequireViewer) -> dict[str, Any]:
    return get_playbook(playbook_id).to_dict()


@router.get("/incidents/{incident_id}", summary="Response state for an incident")
def incident_response(incident_id: str, db: DbSession, _: RequireViewer) -> dict[str, Any]:
    incident = db.execute(
        select(Incident).where(Incident.incident_id == incident_id)
    ).scalar_one_or_none()
    if incident is None:
        raise NotFoundError(f"Incident '{incident_id}' does not exist.")

    taken = db.execute(
        select(ResponseAction).where(ResponseAction.incident_pk == incident.id)
        .order_by(ResponseAction.created_at.desc())
    ).scalars().all()

    return {
        "incident_id": incident.incident_id,
        "simulation_notice": SIMULATION_NOTICE,
        "recommended_actions": recommended_actions(db, incident),
        "playbooks": incident_playbooks(incident),
        "actions_taken": [_action_payload(a) for a in taken],
        "mttr_seconds": incident.mttr_seconds,
        "containment_state": {
            "isolated_hosts": [
                h for h in incident.affected_hosts
                if any(a.action_type == "isolate_host" and a.target == h and a.status == "simulated"
                       for a in taken)
            ],
            "disabled_accounts": [
                u for u in incident.affected_users
                if any(a.action_type == "disable_account" and a.target == u
                       and a.status == "simulated" for a in taken)
            ],
        },
    }


def _action_payload(action: ResponseAction) -> dict[str, Any]:
    return {
        "action_id": action.action_id,
        "action_type": action.action_type,
        "target_type": action.target_type,
        "target": action.target,
        "status": action.status,
        "is_simulated": action.is_simulated,
        "parameters": action.parameters,
        "result": action.result,
        "justification": action.justification,
        "playbook_id": action.playbook_id,
        "playbook_step": action.playbook_step,
        "requested_by": action.requested_by,
        "created_at": action.created_at.isoformat(),
    }


@router.get("/actions/history", summary="Response action history")
def history(
    db: DbSession,
    _: RequireViewer,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    action_type: str | None = None,
) -> dict[str, Any]:
    stmt = select(ResponseAction)
    count_stmt = select(func.count()).select_from(ResponseAction)
    if action_type:
        stmt = stmt.where(ResponseAction.action_type == action_type)
        count_stmt = count_stmt.where(ResponseAction.action_type == action_type)

    total = db.execute(count_stmt).scalar_one()
    rows = db.execute(
        stmt.order_by(ResponseAction.created_at.desc()).limit(limit).offset(offset)
    ).scalars().all()
    return {"total": total, "items": [_action_payload(a) for a in rows]}


@router.post("/execute", status_code=status.HTTP_201_CREATED, summary="Execute a simulated action")
def execute(payload: ExecuteRequest, db: DbSession, principal: RequireAnalyst) -> dict[str, Any]:
    incident = None
    if payload.incident_id:
        incident = db.execute(
            select(Incident).where(Incident.incident_id == payload.incident_id)
        ).scalar_one_or_none()
        if incident is None:
            raise NotFoundError(f"Incident '{payload.incident_id}' does not exist.")

    action = execute_action(
        db,
        action_type=payload.action_type,
        target=payload.target,
        incident=incident,
        parameters=payload.parameters,
        requested_by=principal.username,
        requested_by_role=principal.role,
        justification=payload.justification,
        playbook_id=payload.playbook_id,
        playbook_step=payload.playbook_step,
    )

    audit.record(
        db, actor=principal.username, actor_role=principal.role.value,
        action="response_action", target_type=action.target_type, target_id=action.target,
        result="success" if action.status != "failed" else "failure",
        details={"action_id": action.action_id, "action_type": action.action_type,
                 "simulated": action.is_simulated, "incident": payload.incident_id,
                 "justification": payload.justification},
        ip_address=principal.ip_address,
    )
    db.commit()
    db.refresh(action)
    return {"action": _action_payload(action), "simulation_notice": SIMULATION_NOTICE}
