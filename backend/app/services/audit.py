"""Audit logging.

Records who did what, to what, and whether it worked.  Deliberately append-only:
there is no update or delete path in this module, and no API endpoint that
exposes one.  An audit trail an operator can edit is not an audit trail.

Failures are recorded as well as successes. A rejected authorization attempt is
more interesting than an accepted one, and a trail containing only successes
cannot show an attack that did not work.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.core.timeutils import utcnow
from app.models.operations import AuditLog

logger = get_logger("sentinelx.audit")

#: Actions worth an audit record. Read operations are excluded: auditing every
#: list request would bury the entries that matter under millions of reads.
AUDITED_ACTIONS = {
    "login", "login_failed", "logout", "password_changed", "user_created",
    "alert_status_changed", "alert_false_positive",
    "incident_status_changed", "incident_assigned", "incident_note_added",
    "incident_false_positive",
    "detection_rule_toggled", "detection_rules_synced", "detection_rule_tested",
    "response_action", "report_generated", "report_exported",
    "simulation_started", "evaluation_started",
    "ai_investigation", "ai_response_rejected",
    "ioc_created", "ioc_blocked", "hunt_executed", "hunt_saved",
    "authorization_denied", "rate_limited",
}


def record(
    db: Session,
    *,
    actor: str,
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
    result: str = "success",
    actor_role: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    entry = AuditLog(
        created_at=utcnow(),
        actor=actor[:128],
        actor_role=actor_role,
        action=action[:64],
        target_type=target_type,
        target_id=str(target_id)[:128] if target_id else None,
        result=result,
        ip_address=ip_address,
        user_agent=(user_agent or "")[:255] or None,
        details=details or {},
    )
    db.add(entry)
    db.flush()
    logger.info(
        "audit",
        extra={"actor": actor, "action": action, "target": target_id, "result": result},
    )
    return entry
