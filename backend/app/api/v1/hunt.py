"""Threat hunting."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from app.api.deps import AIRateLimited, DbSession, RequireAnalyst, RequireViewer
from app.core.errors import NotFoundError
from app.core.timeutils import utcnow
from app.models.platform import SavedHunt
from app.services import audit
from app.threat_hunting.dsl import ALLOWED_FIELDS, OPERATORS, HuntQuery
from app.threat_hunting.library import install_builtin_hunts
from app.threat_hunting.service import run_hunt

router = APIRouter(prefix="/hunt", tags=["hunting"])


class TranslateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=3, max_length=1000)
    execute: bool = True


class SaveHuntRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=2000)
    query: HuntQuery


@router.get("/schema", summary="Queryable fields and operators")
def hunt_schema(_: RequireViewer) -> dict[str, Any]:
    """The hunt DSL surface.

    Published so the UI's query builder, the natural-language translator and any
    API client all work from the same definition rather than three drifting copies.
    """
    return {
        "datasets": {name: sorted(fields) for name, fields in ALLOWED_FIELDS.items()},
        "operators": sorted(OPERATORS),
        "metadata_fields": {
            "note": "Available on the events dataset as metadata.<key>.",
            "common_keys": [
                "discovery_category", "persistence_mechanism", "persistence_path",
                "iam_category", "iam_risk", "high_risk_policy", "policy",
                "elevated", "target_user", "privileged_group", "group", "uid_zero",
                "internal_lateral_candidate", "remote_admin_protocol", "outbound_external",
                "failure_reason", "logon_type_name", "auth_method", "invalid_user",
                "argument_indicators", "setuid", "sensitive_file", "mfa_authenticated",
                "windows_event_id", "cloud_discovery", "read_only",
            ],
        },
        "sequence": {
            "note": (
                "For ordered questions ('X then Y'). Steps are matched in order within "
                "within_seconds and must agree on the correlate_on entity fields."
            ),
            "correlatable_fields": ["host", "user", "source_ip", "destination_ip",
                                    "cloud_account", "process"],
            "max_steps": 5,
        },
        "safety": (
            "A hunt is a validated document, never a SQL string. Field names are checked "
            "against this allow-list and compiled into a parameterised query. No caller — "
            "including the natural-language translator — can express a query this schema "
            "does not describe."
        ),
    }


@router.post("/run", summary="Execute a structured hunt")
def execute_hunt(
    query: HuntQuery,
    db: DbSession,
    principal: RequireViewer,
    include_sql: bool = True,
) -> dict[str, Any]:
    result = run_hunt(db, query, include_sql=include_sql)
    audit.record(
        db, actor=principal.username, actor_role=principal.role.value,
        action="hunt_executed", target_type="hunt",
        details={"dataset": query.dataset, "filters": len(query.filters),
                 "sequence": query.sequence is not None, "returned": result.returned},
        ip_address=principal.ip_address,
    )
    db.commit()
    return result.to_dict()


@router.post("/translate", summary="Translate a question into a hunt query")
def translate(
    payload: TranslateRequest,
    db: DbSession,
    principal: RequireAnalyst,
    _rate: AIRateLimited,
) -> dict[str, Any]:
    """Natural language to a validated query document.

    The model never produces SQL and its output is never executed directly. It
    emits a query document, that document is validated by the same schema a
    hand-written hunt goes through, and only then is it compiled. If the model
    emits something the schema rejects, nothing runs.
    """
    from app.ai.service import translate_hunt

    result, hunt_query, _row = translate_hunt(
        db, payload.question, created_by=principal.username
    )

    response: dict[str, Any] = {
        "question": payload.question,
        "ai": result.to_dict(),
        "query": hunt_query.model_dump(mode="json", exclude_none=True) if hunt_query else None,
        "interpretation": hunt_query.describe() if hunt_query else None,
        "executed": False,
        "results": None,
    }

    if hunt_query is not None and payload.execute:
        run = run_hunt(db, hunt_query)
        response["executed"] = True
        response["results"] = run.to_dict()

    audit.record(
        db, actor=principal.username, actor_role=principal.role.value,
        action="hunt_executed", target_type="hunt_nl",
        result="success" if hunt_query else "rejected",
        details={"question": payload.question[:200],
                 "validation_status": result.validation_status},
        ip_address=principal.ip_address,
    )
    db.commit()
    return response


@router.get("/saved", summary="Saved and built-in hunts")
def list_saved(
    db: DbSession,
    _: RequireViewer,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> list[dict[str, Any]]:
    # Built-ins are installed lazily so the page is useful on a fresh database.
    if db.execute(select(SavedHunt).limit(1)).scalars().first() is None:
        install_builtin_hunts(db)
        db.commit()

    rows = db.execute(
        select(SavedHunt).order_by(SavedHunt.is_builtin.desc(), SavedHunt.name.asc()).limit(limit)
    ).scalars().all()
    return [
        {
            "id": r.id, "name": r.name, "description": r.description, "query": r.query,
            "created_by": r.created_by, "created_at": r.created_at.isoformat(),
            "last_run_at": r.last_run_at.isoformat() if r.last_run_at else None,
            "run_count": r.run_count, "is_builtin": r.is_builtin,
        }
        for r in rows
    ]


@router.post("/saved", status_code=status.HTTP_201_CREATED, summary="Save a hunt")
def save_hunt(payload: SaveHuntRequest, db: DbSession, principal: RequireAnalyst) -> dict[str, Any]:
    hunt = SavedHunt(
        name=payload.name,
        description=payload.description,
        query=payload.query.model_dump(mode="json", exclude_none=True),
        created_by=principal.username,
        created_at=utcnow(),
        is_builtin=False,
    )
    db.add(hunt)
    audit.record(
        db, actor=principal.username, actor_role=principal.role.value,
        action="hunt_saved", target_type="saved_hunt", target_id=payload.name,
        ip_address=principal.ip_address,
    )
    db.commit()
    db.refresh(hunt)
    return {"id": hunt.id, "name": hunt.name, "query": hunt.query}


@router.post("/saved/{hunt_id}/run", summary="Run a saved hunt")
def run_saved(hunt_id: int, db: DbSession, principal: RequireViewer) -> dict[str, Any]:
    hunt = db.get(SavedHunt, hunt_id)
    if hunt is None:
        raise NotFoundError(f"Saved hunt {hunt_id} does not exist.")

    query = HuntQuery(**hunt.query)
    result = run_hunt(db, query)
    hunt.last_run_at = utcnow()
    hunt.run_count += 1
    db.commit()
    return {"hunt": {"id": hunt.id, "name": hunt.name}, **result.to_dict()}


@router.post("/saved/install-builtins", summary="Install the built-in hunt library")
def install_builtins(db: DbSession, principal: RequireAnalyst) -> dict[str, Any]:
    created = install_builtin_hunts(db, author=principal.username)
    db.commit()
    return {"created": created}
