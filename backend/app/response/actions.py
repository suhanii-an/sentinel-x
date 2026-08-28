"""Response actions — simulated, by construction.

**SENTINEL-X never performs a real containment action.**  There is no code path
here that reaches a firewall, a directory service, an EDR agent, a cloud API or
the host operating system.  Every handler updates SENTINEL-X's own database to
record that an action was *rehearsed*, and every record carries
``is_simulated=True``.

This is not a limitation to apologise for, it is the correct design for an
educational platform: the interesting engineering in a response layer is the
decision model, the audit trail and the state machine, none of which require the
ability to actually disable someone's account.

What a production deployment would add is documented in
``docs/incident-response.md``: an executor interface behind this registry, an
approval workflow for destructive actions, and per-action rollback.  The registry
below is already shaped for it — each action declares whether it is destructive
and what it would reverse.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.timeutils import iso, utcnow
from app.models.entities import Host, User
from app.models.enums import IncidentStatus, ResponseActionType
from app.models.incidents import Incident
from app.models.iocs import IOC


@dataclass(frozen=True, slots=True)
class ActionSpec:
    action_type: str
    name: str
    description: str
    target_type: str          # host | user | ioc | incident | cloud_identity
    destructive: bool
    reverses: str | None
    #: What this would do against real infrastructure, shown in the UI so the
    #: gap between simulation and production is explicit rather than implied.
    production_behaviour: str
    requires_role: str = "analyst"


@dataclass(slots=True)
class ActionOutcome:
    ok: bool
    result: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


ACTION_SPECS: dict[str, ActionSpec] = {
    ResponseActionType.ISOLATE_HOST: ActionSpec(
        action_type=ResponseActionType.ISOLATE_HOST,
        name="Isolate host",
        description="Cut a host off from the network while preserving analyst access.",
        target_type="host",
        destructive=True,
        reverses=ResponseActionType.RELEASE_HOST,
        production_behaviour=(
            "Would call the EDR platform's network-containment API for this host, "
            "leaving only the management channel reachable."
        ),
    ),
    ResponseActionType.RELEASE_HOST: ActionSpec(
        action_type=ResponseActionType.RELEASE_HOST,
        name="Release host from isolation",
        description="Restore normal network access to a previously isolated host.",
        target_type="host",
        destructive=False,
        reverses=ResponseActionType.ISOLATE_HOST,
        production_behaviour="Would lift EDR network containment for this host.",
    ),
    ResponseActionType.DISABLE_ACCOUNT: ActionSpec(
        action_type=ResponseActionType.DISABLE_ACCOUNT,
        name="Disable account",
        description="Prevent an account from authenticating anywhere.",
        target_type="user",
        destructive=True,
        reverses=ResponseActionType.ENABLE_ACCOUNT,
        production_behaviour=(
            "Would disable the account in the directory service and revoke its "
            "active sessions and refresh tokens."
        ),
    ),
    ResponseActionType.ENABLE_ACCOUNT: ActionSpec(
        action_type=ResponseActionType.ENABLE_ACCOUNT,
        name="Re-enable account",
        description="Restore an account disabled during response.",
        target_type="user",
        destructive=False,
        reverses=ResponseActionType.DISABLE_ACCOUNT,
        production_behaviour="Would re-enable the account in the directory service.",
    ),
    ResponseActionType.RESET_CREDENTIALS: ActionSpec(
        action_type=ResponseActionType.RESET_CREDENTIALS,
        name="Force credential reset",
        description="Invalidate an account's credentials and require a reset at next logon.",
        target_type="user",
        destructive=True,
        reverses=None,
        production_behaviour=(
            "Would expire the password, revoke API keys and SSH keys, and "
            "force re-enrolment of second factors."
        ),
    ),
    ResponseActionType.BLOCK_IOC: ActionSpec(
        action_type=ResponseActionType.BLOCK_IOC,
        name="Block indicator",
        description="Add an indicator to the perimeter blocklist.",
        target_type="ioc",
        destructive=False,
        reverses=None,
        production_behaviour=(
            "Would push the indicator to the firewall, proxy and DNS sinkhole."
        ),
    ),
    ResponseActionType.REVOKE_CLOUD_SESSION: ActionSpec(
        action_type=ResponseActionType.REVOKE_CLOUD_SESSION,
        name="Revoke cloud sessions",
        description="Invalidate an identity's active cloud sessions and access keys.",
        target_type="user",
        destructive=True,
        reverses=None,
        production_behaviour=(
            "Would attach a deny-all policy scoped by token issue date, deactivate "
            "the identity's access keys, and revoke active federated sessions."
        ),
    ),
    ResponseActionType.COLLECT_EVIDENCE: ActionSpec(
        action_type=ResponseActionType.COLLECT_EVIDENCE,
        name="Collect evidence package",
        description="Snapshot the incident's evidence for preservation and handover.",
        target_type="incident",
        destructive=False,
        reverses=None,
        production_behaviour=(
            "Would additionally trigger host memory and disk acquisition through "
            "the forensics platform."
        ),
    ),
    ResponseActionType.ESCALATE_INCIDENT: ActionSpec(
        action_type=ResponseActionType.ESCALATE_INCIDENT,
        name="Escalate incident",
        description="Raise the incident to the next response tier.",
        target_type="incident",
        destructive=False,
        reverses=None,
        production_behaviour=(
            "Would page the on-call responder and open a ticket in the incident "
            "management system."
        ),
    ),
}


# --------------------------------------------------------------------------
# Handlers. Each mutates only SENTINEL-X's own records.
# --------------------------------------------------------------------------
def _isolate_host(db: Session, target: str, incident: Incident | None, params: dict) -> ActionOutcome:
    host = db.execute(select(Host).where(Host.host_id == target)).scalar_one_or_none()
    if host is None:
        return ActionOutcome(ok=False, error=f"Host '{target}' is not in the asset inventory.")
    if host.is_isolated:
        return ActionOutcome(ok=True, result={
            "state": "already_isolated",
            "host": host.host_id,
            "isolated_at": iso(host.isolated_at),
            "note": "No change made; the host was already marked isolated.",
        })
    host.is_isolated = True
    host.isolated_at = utcnow()
    db.flush()
    return ActionOutcome(ok=True, result={
        "state": "isolated",
        "host": host.host_id,
        "hostname": host.hostname,
        "criticality": host.criticality,
        "isolated_at": iso(host.isolated_at),
        "simulated": True,
        "note": "SIMULATED. No network control was contacted; only SENTINEL-X state changed.",
    })


def _release_host(db: Session, target: str, incident: Incident | None, params: dict) -> ActionOutcome:
    host = db.execute(select(Host).where(Host.host_id == target)).scalar_one_or_none()
    if host is None:
        return ActionOutcome(ok=False, error=f"Host '{target}' is not in the asset inventory.")
    host.is_isolated = False
    host.isolated_at = None
    db.flush()
    return ActionOutcome(ok=True, result={"state": "released", "host": host.host_id, "simulated": True})


def _disable_account(db: Session, target: str, incident: Incident | None, params: dict) -> ActionOutcome:
    user = db.execute(select(User).where(User.user_id == target)).scalar_one_or_none()
    if user is None:
        return ActionOutcome(ok=False, error=f"Account '{target}' is not in the identity inventory.")
    if user.is_disabled:
        return ActionOutcome(ok=True, result={"state": "already_disabled", "user": user.user_id})
    user.is_disabled = True
    user.disabled_at = utcnow()
    db.flush()
    return ActionOutcome(ok=True, result={
        "state": "disabled",
        "user": user.user_id,
        "privileged": user.is_privileged,
        "disabled_at": iso(user.disabled_at),
        "simulated": True,
        "note": "SIMULATED. No directory service was contacted.",
    })


def _enable_account(db: Session, target: str, incident: Incident | None, params: dict) -> ActionOutcome:
    user = db.execute(select(User).where(User.user_id == target)).scalar_one_or_none()
    if user is None:
        return ActionOutcome(ok=False, error=f"Account '{target}' is not in the identity inventory.")
    user.is_disabled = False
    user.disabled_at = None
    db.flush()
    return ActionOutcome(ok=True, result={"state": "enabled", "user": user.user_id, "simulated": True})


def _reset_credentials(db: Session, target: str, incident: Incident | None, params: dict) -> ActionOutcome:
    user = db.execute(select(User).where(User.user_id == target)).scalar_one_or_none()
    if user is None:
        return ActionOutcome(ok=False, error=f"Account '{target}' is not in the identity inventory.")
    return ActionOutcome(ok=True, result={
        "state": "reset_requested",
        "user": user.user_id,
        "simulated": True,
        "note": "SIMULATED. No credential was changed anywhere.",
        "would_invalidate": ["password", "ssh_keys", "api_keys", "active_sessions"],
    })


def _revoke_cloud_session(db: Session, target: str, incident: Incident | None, params: dict) -> ActionOutcome:
    return ActionOutcome(ok=True, result={
        "state": "sessions_revoked",
        "identity": target,
        "simulated": True,
        "note": "SIMULATED. No cloud API was called and no credentials exist in this deployment.",
    })


def _block_ioc(db: Session, target: str, incident: Incident | None, params: dict) -> ActionOutcome:
    ioc = db.execute(
        select(IOC).where((IOC.indicator == target) | (IOC.ioc_id == target))
    ).scalars().first()
    if ioc is None:
        return ActionOutcome(ok=False, error=f"Indicator '{target}' is not in the indicator store.")
    ioc.is_blocked = True
    db.flush()
    return ActionOutcome(ok=True, result={
        "state": "blocked",
        "ioc_id": ioc.ioc_id,
        "indicator": ioc.indicator,
        "ioc_type": ioc.ioc_type,
        "simulated": True,
        "note": "SIMULATED. No perimeter device was configured.",
    })


def _collect_evidence(db: Session, target: str, incident: Incident | None, params: dict) -> ActionOutcome:
    """Produce a real evidence package.

    This action is genuinely performed rather than simulated: preserving a
    snapshot of the evidence is something SENTINEL-X can do correctly and
    completely, so pretending it is simulated would be the dishonest choice.
    """
    if incident is None:
        return ActionOutcome(ok=False, error="Evidence collection requires an incident.")

    from app.ai.context import build_incident_bundle

    bundle = build_incident_bundle(db, incident, max_events=10_000)
    return ActionOutcome(ok=True, result={
        "state": "collected",
        "incident_id": incident.incident_id,
        "simulated": False,
        "note": "Evidence package assembled from stored records. This action is performed, not simulated.",
        "package": {
            "alert_count": len(bundle.get("alerts", [])),
            "event_count": len(bundle.get("events", [])),
            "technique_count": len(bundle.get("mitre_techniques", [])),
            "indicator_matches": len(bundle.get("indicator_matches", [])),
            "collected_at": iso(utcnow()),
        },
        "evidence": bundle,
    })


def _escalate_incident(db: Session, target: str, incident: Incident | None, params: dict) -> ActionOutcome:
    if incident is None:
        return ActionOutcome(ok=False, error="Escalation requires an incident.")
    previous = incident.status
    incident.status = IncidentStatus.INVESTIGATING
    incident.assigned_to = params.get("assign_to") or incident.assigned_to
    db.flush()
    return ActionOutcome(ok=True, result={
        "state": "escalated",
        "incident_id": incident.incident_id,
        "previous_status": previous,
        "new_status": incident.status,
        "assigned_to": incident.assigned_to,
        "simulated": True,
        "note": "SIMULATED. No pager or ticketing system was contacted.",
    })


HANDLERS: dict[str, Callable[[Session, str, Incident | None, dict], ActionOutcome]] = {
    ResponseActionType.ISOLATE_HOST: _isolate_host,
    ResponseActionType.RELEASE_HOST: _release_host,
    ResponseActionType.DISABLE_ACCOUNT: _disable_account,
    ResponseActionType.ENABLE_ACCOUNT: _enable_account,
    ResponseActionType.RESET_CREDENTIALS: _reset_credentials,
    ResponseActionType.REVOKE_CLOUD_SESSION: _revoke_cloud_session,
    ResponseActionType.BLOCK_IOC: _block_ioc,
    ResponseActionType.COLLECT_EVIDENCE: _collect_evidence,
    ResponseActionType.ESCALATE_INCIDENT: _escalate_incident,
}
