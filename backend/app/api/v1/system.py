"""Dashboard, search, audit log and system information."""

from __future__ import annotations

import datetime as dt
from typing import Annotated, Any

from fastapi import APIRouter, Query
from sqlalchemy import func, select, text

from app.api.deps import DbSession, RequireAdmin, RequireViewer
from app.core.config import settings
from app.core.database import engine
from app.core.timeutils import iso, utcnow
from app.models.alerts import Alert
from app.models.events import Event
from app.models.incidents import Incident
from app.models.operations import AuditLog
from app.services import search as search_service
from app.services import stats as stats_service

router = APIRouter(tags=["system"])


@router.get("/stats/dashboard", summary="Everything the SOC overview needs")
def dashboard(
    db: DbSession,
    _: RequireViewer,
    window_hours: Annotated[int, Query(ge=1, le=24 * 30)] = 24,
) -> dict[str, Any]:
    return stats_service.dashboard(db, window_hours=window_hours)


@router.get("/stats/kpis", summary="Headline metrics only")
def kpis(
    db: DbSession,
    _: RequireViewer,
    window_hours: Annotated[int, Query(ge=1, le=24 * 30)] = 24,
) -> dict[str, Any]:
    return stats_service.kpis(db, window_hours=window_hours)


@router.get("/search", summary="Global search")
def search(
    db: DbSession,
    _: RequireViewer,
    q: Annotated[str, Query(min_length=1, max_length=256)],
    limit: Annotated[int, Query(ge=1, le=50)] = 10,
) -> dict[str, Any]:
    """Search incidents, alerts, events, hosts, accounts, indicators and techniques.

    The term's type is inferred from its shape first, so ``SX-2026-0042``,
    ``10.20.4.31`` and ``T1110`` each go straight to an indexed lookup instead of
    scanning every table.
    """
    return search_service.search(db, q, limit=limit)


@router.get("/audit", summary="Audit log (admin only)")
def audit_log(
    db: DbSession,
    _: RequireAdmin,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    actor: str | None = None,
    action: str | None = None,
    target_id: str | None = None,
    result: str | None = None,
    since: dt.datetime | None = None,
) -> dict[str, Any]:
    """Read the audit trail.

    Read-only by construction: there is no endpoint that modifies or deletes an
    audit record anywhere in this API.
    """
    conditions = []
    if actor:
        conditions.append(AuditLog.actor == actor)
    if action:
        conditions.append(AuditLog.action == action)
    if target_id:
        conditions.append(AuditLog.target_id == target_id)
    if result:
        conditions.append(AuditLog.result == result)
    if since:
        conditions.append(AuditLog.created_at >= since)

    stmt = select(AuditLog)
    count_stmt = select(func.count()).select_from(AuditLog)
    for condition in conditions:
        stmt = stmt.where(condition)
        count_stmt = count_stmt.where(condition)

    total = db.execute(count_stmt).scalar_one()
    rows = db.execute(
        stmt.order_by(AuditLog.created_at.desc()).limit(limit).offset(offset)
    ).scalars().all()
    return {
        "total": total,
        "items": [
            {
                "id": r.id,
                "created_at": iso(r.created_at),
                "actor": r.actor,
                "actor_role": r.actor_role,
                "action": r.action,
                "target_type": r.target_type,
                "target_id": r.target_id,
                "result": r.result,
                "ip_address": r.ip_address,
                "details": r.details,
            }
            for r in rows
        ],
    }


@router.get("/system/health", summary="Liveness and dependency health")
def health(db: DbSession) -> dict[str, Any]:
    """Unauthenticated: container orchestrators need it before a token exists.

    Returns only whether dependencies respond — no version numbers, no
    configuration, nothing that helps someone profile the deployment.
    """
    database_ok = True
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        database_ok = False
    return {
        "status": "ok" if database_ok else "degraded",
        "database": "ok" if database_ok else "unavailable",
        "time": iso(utcnow()),
    }


@router.get("/system/info", summary="Platform configuration and posture")
def info(db: DbSession, _: RequireViewer) -> dict[str, Any]:
    """What this deployment is and is not.

    Deliberately explicit about the simulation boundary, because a reader
    should not have to infer it from the absence of a disclaimer.
    """
    from app.services.rule_registry import load_rule_definitions

    definitions, errors = load_rule_definitions()
    counts = {
        "events": db.execute(select(func.count()).select_from(Event)).scalar_one(),
        "alerts": db.execute(select(func.count()).select_from(Alert)).scalar_one(),
        "incidents": db.execute(select(func.count()).select_from(Incident)).scalar_one(),
    }
    demo_events = db.execute(
        select(func.count()).select_from(Event).where(Event.is_demo.is_(True))
    ).scalar_one()

    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "database_backend": engine.dialect.name,
        "demo_mode": settings.DEMO_MODE,
        "ai": {
            "configured": settings.ai_enabled,
            "provider": settings.AI_PROVIDER if settings.ai_enabled else None,
            "note": (
                "Detection, correlation, incident creation, ATT&CK mapping, threat "
                "hunting, response simulation, reporting and evaluation operate "
                "independently of AI availability."
            ),
        },
        "detection": {
            "rules_loaded": len(definitions),
            "load_errors": errors,
        },
        "data": {
            **counts,
            "simulated_events": demo_events,
            "simulated_share": round(demo_events / counts["events"], 3) if counts["events"] else 0.0,
        },
        "boundaries": {
            "telemetry": (
                "All telemetry in this deployment is synthetic, generated by the attack "
                "simulator and the evaluation dataset against a fictional estate. No real "
                "systems are monitored."
            ),
            "response": (
                "Every containment action is simulated. No EDR, directory service, "
                "firewall or cloud provider is contacted. Evidence collection is the "
                "single action that is genuinely performed."
            ),
            "threat_intelligence": (
                "The indicator store contains local demo data only. No external feed "
                "integration ships with this project."
            ),
            "addresses": (
                "All addresses come from RFC 1918 private space or the RFC 5737 "
                "documentation ranges. Nothing here is routable to real infrastructure."
            ),
        },
    }
