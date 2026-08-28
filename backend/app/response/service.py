"""Response execution and MTTR measurement."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import AuthorizationError, NotFoundError, ValidationFailed
from app.core.ids import action_id as new_action_id
from app.core.logging import get_logger
from app.core.netutils import is_external
from app.core.timeutils import utcnow
from app.models.enums import ResponseActionType, Role
from app.models.incidents import Incident
from app.models.operations import ResponseAction
from app.response.actions import ACTION_SPECS, HANDLERS
from app.response.playbooks import PLAYBOOKS, Playbook, match_playbooks

logger = get_logger("sentinelx.response")

#: Action types that count as containment for MTTR purposes.  Escalation and
#: evidence collection are important but they do not reduce exposure, so counting
#: them would flatter the metric.
CONTAINMENT_ACTIONS = {
    ResponseActionType.ISOLATE_HOST,
    ResponseActionType.DISABLE_ACCOUNT,
    ResponseActionType.BLOCK_IOC,
    ResponseActionType.RESET_CREDENTIALS,
    ResponseActionType.REVOKE_CLOUD_SESSION,
}


def available_actions() -> list[dict[str, Any]]:
    return [
        {
            "action_type": spec.action_type,
            "name": spec.name,
            "description": spec.description,
            "target_type": spec.target_type,
            "destructive": spec.destructive,
            "reverses": spec.reverses,
            "production_behaviour": spec.production_behaviour,
            "requires_role": spec.requires_role,
            "simulated": spec.action_type != ResponseActionType.COLLECT_EVIDENCE,
        }
        for spec in ACTION_SPECS.values()
    ]


def execute_action(
    db: Session,
    *,
    action_type: str,
    target: str,
    incident: Incident | None = None,
    parameters: dict[str, Any] | None = None,
    requested_by: str = "analyst",
    requested_by_role: Role | None = None,
    justification: str | None = None,
    playbook_id: str | None = None,
    playbook_step: int | None = None,
) -> ResponseAction:
    """Run a response action and record it.

    Every action is recorded whether or not it succeeded.  A failed containment
    attempt is operationally significant — it usually means the target is not
    what the analyst thought it was — and discarding the record would hide that.
    """
    spec = ACTION_SPECS.get(action_type)
    if spec is None:
        raise ValidationFailed(f"Unknown response action '{action_type}'.")

    # Enforce the per-action minimum role.
    #
    # ``ActionSpec.requires_role`` is published by /response/actions and
    # rendered as a badge in the console, so it is a claim the interface makes
    # about authorization. Checking it only at the endpoint's blanket
    # ``RequireAnalyst`` meant that claim was decorative: every spec happens to
    # say "analyst" today, so nothing was exploitable, but the first spec that
    # said "admin" would have been enforced nowhere. A published authorization
    # control that is not enforced is exactly the kind of thing this project
    # says it does not ship.
    if requested_by_role is not None:
        required = Role(spec.requires_role)
        if requested_by_role.level < required.level:
            raise AuthorizationError(
                f"Action '{action_type}' requires the {required.value} role or higher; "
                f"your account has {requested_by_role.value}."
            )

    handler = HANDLERS[action_type]

    target = str(target).strip()
    if not target:
        raise ValidationFailed(f"Action '{action_type}' requires a target {spec.target_type}.")

    params = parameters or {}
    outcome = handler(db, target, incident, params)

    # Evidence collection is genuinely performed; everything else is simulated.
    simulated = action_type != ResponseActionType.COLLECT_EVIDENCE
    result = dict(outcome.result)
    evidence_bundle = result.pop("evidence", None)  # too large for the action record

    record = ResponseAction(
        action_id=new_action_id(),
        incident_pk=incident.id if incident is not None else None,
        action_type=action_type,
        target_type=spec.target_type,
        target=target[:255],
        status="simulated" if (outcome.ok and simulated) else ("completed" if outcome.ok else "failed"),
        is_simulated=simulated,
        parameters=params,
        result=result if outcome.ok else {"error": outcome.error},
        playbook_id=playbook_id,
        playbook_step=playbook_step,
        justification=justification,
        requested_by=requested_by,
        created_at=utcnow(),
    )
    db.add(record)
    db.flush()

    if outcome.ok and incident is not None and action_type in CONTAINMENT_ACTIONS:
        _record_mttr(db, incident, record)

    logger.info(
        "response_action",
        extra={
            "action_id": record.action_id,
            "action_type": action_type,
            "target": target,
            "status": record.status,
            "simulated": simulated,
            "incident": incident.incident_id if incident else None,
            "actor": requested_by,
        },
    )

    if evidence_bundle is not None:
        record.result = {**record.result, "package_available": True}
        db.flush()

    return record


def _record_mttr(db: Session, incident: Incident, action: ResponseAction) -> None:
    """Measure detection-to-containment for this incident.

    Measured from the first alert's creation (when SENTINEL-X knew) to the first
    containment action (when exposure was reduced).  Set once: subsequent
    containment actions do not overwrite the first response time.
    """
    if incident.mttr_seconds is not None:
        return
    alerts = sorted(incident.alerts, key=lambda a: a.created_at)
    if not alerts:
        return
    incident.mttr_seconds = max(0, int((action.created_at - alerts[0].created_at).total_seconds()))
    db.flush()


def incident_playbooks(incident: Incident) -> list[dict[str, Any]]:
    """Playbooks relevant to an incident, most relevant first."""
    rule_ids = sorted({a.rule_id for a in incident.alerts})
    matched = match_playbooks(rule_ids, list(incident.technique_ids or []))
    return [p.to_dict() for p in matched]


def get_playbook(playbook_id: str) -> Playbook:
    playbook = PLAYBOOKS.get(playbook_id)
    if playbook is None:
        raise NotFoundError(f"Playbook '{playbook_id}' does not exist.")
    return playbook


def recommended_actions(db: Session, incident: Incident) -> list[dict[str, Any]]:
    """Concrete, targeted action proposals derived from the incident's own entities.

    Deterministic — no AI involved.  Each proposal names a real target from the
    evidence, so the Response tab is never a generic list of buttons.
    """
    proposals: list[dict[str, Any]] = []
    taken = {
        (a.action_type, a.target)
        for a in db.execute(
            select(ResponseAction).where(ResponseAction.incident_pk == incident.id)
        ).scalars().all()
    }

    playbooks = match_playbooks(
        sorted({a.rule_id for a in incident.alerts}), list(incident.technique_ids or [])
    )
    primary = playbooks[0] if playbooks else None

    from app.models.entities import Host, User

    hosts = (
        db.execute(select(Host).where(Host.host_id.in_(incident.affected_hosts))).scalars().all()
        if incident.affected_hosts else []
    )
    for host in sorted(hosts, key=lambda h: h.criticality, reverse=True):
        if host.is_isolated or (ResponseActionType.ISOLATE_HOST, host.host_id) in taken:
            continue
        proposals.append({
            "action_type": ResponseActionType.ISOLATE_HOST,
            "target": host.host_id,
            "target_type": "host",
            "priority": "high" if host.criticality >= 4 else "medium",
            "rationale": (
                f"{host.host_id} is a criticality-{host.criticality}/5 asset with confirmed "
                f"attacker activity in this incident."
            ),
            "playbook_id": primary.playbook_id if primary else None,
        })

    users = (
        db.execute(select(User).where(User.user_id.in_(incident.affected_users))).scalars().all()
        if incident.affected_users else []
    )
    for user in users:
        if user.is_disabled or (ResponseActionType.DISABLE_ACCOUNT, user.user_id) in taken:
            continue
        proposals.append({
            "action_type": ResponseActionType.DISABLE_ACCOUNT,
            "target": user.user_id,
            "target_type": "user",
            "priority": "high" if user.is_privileged else "medium",
            "rationale": (
                f"'{user.user_id}' performed successful actions in this incident"
                + (" and holds privileged access." if user.is_privileged else ".")
            ),
            "playbook_id": primary.playbook_id if primary else None,
        })

    for ip in incident.source_ips:
        if not is_external(ip):
            continue  # blocking an internal address is a different decision entirely
        if (ResponseActionType.BLOCK_IOC, ip) in taken:
            continue
        proposals.append({
            "action_type": ResponseActionType.BLOCK_IOC,
            "target": ip,
            "target_type": "ioc",
            "priority": "medium",
            "rationale": f"{ip} is an external source address observed in this incident.",
            "playbook_id": primary.playbook_id if primary else None,
        })

    if (ResponseActionType.COLLECT_EVIDENCE, incident.incident_id) not in taken:
        proposals.append({
            "action_type": ResponseActionType.COLLECT_EVIDENCE,
            "target": incident.incident_id,
            "target_type": "incident",
            "priority": "high",
            "rationale": "Preserve the evidence package before further state changes.",
            "playbook_id": primary.playbook_id if primary else None,
        })

    order = {"high": 0, "medium": 1, "low": 2}
    proposals.sort(key=lambda p: order.get(p["priority"], 3))
    return proposals
