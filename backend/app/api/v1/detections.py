"""Detection rule management and testing."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query
from sqlalchemy import func, select

from app.api.deps import DbSession, RequireAdmin, RequireAnalyst, RequireViewer
from app.core.errors import NotFoundError
from app.core.sqlutils import LIKE_ESCAPE, json_member
from app.detection.testing import run_all_rule_tests, run_rule_tests
from app.models.detections import DetectionRule
from app.schemas.common import Page
from app.schemas.security import DetectionRuleDetail, DetectionRuleSummary, RuleToggle
from app.services import audit
from app.services.rule_registry import load_rule_definitions, sync_rules

router = APIRouter(prefix="/detections", tags=["detections"])


@router.get("", response_model=Page[DetectionRuleSummary], summary="Detection rule registry")
def list_rules(
    db: DbSession,
    _: RequireViewer,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
    enabled: bool | None = None,
    rule_type: str | None = None,
    category: str | None = None,
    technique: str | None = None,
) -> Page[DetectionRuleSummary]:
    from sqlalchemy import Text, cast

    conditions = []
    if enabled is not None:
        conditions.append(DetectionRule.enabled.is_(enabled))
    if rule_type:
        conditions.append(DetectionRule.rule_type == rule_type)
    if category:
        conditions.append(DetectionRule.category == category)
    if technique:
        conditions.append(
            cast(DetectionRule.mitre_techniques, Text).ilike(
                json_member(technique), escape=LIKE_ESCAPE
            )
        )

    stmt = select(DetectionRule)
    count_stmt = select(func.count()).select_from(DetectionRule)
    for condition in conditions:
        stmt = stmt.where(condition)
        count_stmt = count_stmt.where(condition)

    total = db.execute(count_stmt).scalar_one()
    rows = db.execute(
        stmt.order_by(DetectionRule.rule_id.asc()).limit(limit).offset(offset)
    ).scalars().all()
    return Page[DetectionRuleSummary](
        items=[DetectionRuleSummary.model_validate(r) for r in rows],
        total=total, limit=limit, offset=offset,
    )


@router.get("/status", summary="Rule loading state and any errors")
def rule_status(db: DbSession, _: RequireViewer) -> dict[str, Any]:
    """Rule health, including load errors.

    Load errors are surfaced rather than logged and forgotten: a rule that fails
    to parse looks exactly like coverage and provides none.
    """
    definitions, errors = load_rule_definitions()
    registered = db.execute(select(func.count()).select_from(DetectionRule)).scalar_one()
    enabled = db.execute(
        select(func.count()).select_from(DetectionRule).where(DetectionRule.enabled.is_(True))
    ).scalar_one()
    by_type: dict[str, int] = {}
    for definition in definitions:
        by_type[str(definition.type)] = by_type.get(str(definition.type), 0) + 1

    return {
        "rules_on_disk": len(definitions),
        "rules_registered": registered,
        "rules_enabled": enabled,
        "by_type": by_type,
        "load_errors": errors,
        "healthy": not errors,
    }


@router.get("/tests", summary="Run every rule's self-tests")
def run_tests(_: RequireViewer) -> dict[str, Any]:
    """Execute the declarative tests shipped with each rule.

    The same function backs the pytest suite and CI, so this page cannot show a
    result that CI did not enforce.
    """
    definitions, _errors = load_rule_definitions()
    summary = run_all_rule_tests(definitions)
    return {
        "total": summary.total,
        "passed": summary.passed,
        "failed": summary.failed,
        "ok": summary.ok,
        "rules_without_tests": summary.rules_without_tests,
        "rules_without_negative_tests": summary.rules_without_negative_tests,
        "results": [
            {
                "rule_id": r.rule_id,
                "test_name": r.test_name,
                "expected": r.expected,
                "actual": r.actual,
                "passed": r.passed,
                "matched_count": r.matched_count,
                "detail": r.detail,
            }
            for r in summary.results
        ],
    }


@router.post("/sync", summary="Reload rules from disk")
def sync(db: DbSession, principal: RequireAdmin) -> dict[str, Any]:
    created, updated, errors = sync_rules(db)
    audit.record(
        db, actor=principal.username, actor_role=principal.role.value,
        action="detection_rules_synced", target_type="detection_rules",
        details={"created": created, "updated": updated, "errors": len(errors)},
        ip_address=principal.ip_address,
    )
    db.commit()
    return {"created": created, "updated": updated, "errors": errors}


@router.get("/{rule_id}", response_model=DetectionRuleDetail, summary="Rule detail")
def get_rule(rule_id: str, db: DbSession, _: RequireViewer) -> DetectionRuleDetail:
    rule = db.execute(
        select(DetectionRule).where(DetectionRule.rule_id == rule_id)
    ).scalar_one_or_none()
    if rule is None:
        raise NotFoundError(f"Detection rule '{rule_id}' does not exist.")
    return DetectionRuleDetail.model_validate(rule)


@router.post("/{rule_id}/test", summary="Run one rule's self-tests")
def test_rule(rule_id: str, db: DbSession, principal: RequireAnalyst) -> dict[str, Any]:
    definitions, _ = load_rule_definitions()
    definition = next((d for d in definitions if d.id == rule_id), None)
    if definition is None:
        raise NotFoundError(f"Detection rule '{rule_id}' does not exist on disk.")

    results = run_rule_tests(definition)
    audit.record(
        db, actor=principal.username, actor_role=principal.role.value,
        action="detection_rule_tested", target_type="detection_rule", target_id=rule_id,
        details={"tests": len(results), "passed": sum(1 for r in results if r.passed)},
        ip_address=principal.ip_address,
    )
    db.commit()
    return {
        "rule_id": rule_id,
        "total": len(results),
        "passed": sum(1 for r in results if r.passed),
        "failed": sum(1 for r in results if not r.passed),
        "results": [
            {
                "test_name": r.test_name, "expected": r.expected, "actual": r.actual,
                "passed": r.passed, "matched_count": r.matched_count, "detail": r.detail,
            }
            for r in results
        ],
    }


@router.patch("/{rule_id}", response_model=DetectionRuleDetail, summary="Enable or disable a rule")
def toggle_rule(
    rule_id: str,
    payload: RuleToggle,
    db: DbSession,
    principal: RequireAdmin,
) -> DetectionRuleDetail:
    """Change a rule's operational state.

    Only the enabled flag is mutable through the API. Rule *logic* lives in
    version-controlled files and cannot be edited here — there is deliberately no
    endpoint that accepts rule content, because that would be a path to
    introducing new executable detection logic through a web request.
    """
    rule = db.execute(
        select(DetectionRule).where(DetectionRule.rule_id == rule_id)
    ).scalar_one_or_none()
    if rule is None:
        raise NotFoundError(f"Detection rule '{rule_id}' does not exist.")

    previous = rule.enabled
    rule.enabled = payload.enabled
    audit.record(
        db, actor=principal.username, actor_role=principal.role.value,
        action="detection_rule_toggled", target_type="detection_rule", target_id=rule_id,
        details={"from": previous, "to": payload.enabled, "reason": payload.reason},
        ip_address=principal.ip_address,
    )
    db.commit()
    db.refresh(rule)
    return DetectionRuleDetail.model_validate(rule)
