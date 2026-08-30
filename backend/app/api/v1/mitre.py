"""MITRE ATT&CK navigation and coverage."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query
from sqlalchemy import Text, cast, func, select

from app.api.deps import DbSession, RequireViewer
from app.core.errors import NotFoundError
from app.core.sqlutils import LIKE_ESCAPE, json_member
from app.mitre import catalog
from app.models.alerts import Alert
from app.models.detections import DetectionRule
from app.models.incidents import Incident, IncidentTechnique

router = APIRouter(prefix="/mitre", tags=["mitre"])


@router.get("/tactics", summary="ATT&CK tactics in kill-chain order")
def tactics(_: RequireViewer) -> list[dict[str, Any]]:
    entries, _techniques = catalog.load_catalog()
    return sorted(entries, key=lambda t: t.get("order", 0))


@router.get("/techniques", summary="Technique catalogue")
def techniques(
    _: RequireViewer,
    tactic: str | None = None,
    q: Annotated[str | None, Query(max_length=128)] = None,
    include_subtechniques: bool = True,
) -> list[dict[str, Any]]:
    _tactics, entries = catalog.load_catalog()
    results = entries
    if tactic:
        results = [t for t in results if tactic in t.get("tactic_ids", [])]
    if not include_subtechniques:
        results = [t for t in results if not t.get("is_subtechnique")]
    if q:
        needle = q.lower()
        results = [
            t for t in results
            if needle in t["name"].lower() or needle in t["technique_id"].lower()
        ]
    return sorted(results, key=lambda t: t["technique_id"])


@router.get("/coverage", summary="Detection coverage across the matrix")
def coverage(db: DbSession, _: RequireViewer) -> dict[str, Any]:
    """Which techniques the rule set covers, and which it does not.

    The uncovered list is the point. A coverage view that only shows what is
    detected tells an analyst nothing about where they are blind.
    """
    _tactics, entries = catalog.load_catalog()
    order = catalog.tactic_order()
    names = catalog.tactic_names()

    rules = db.execute(select(DetectionRule)).scalars().all()
    covered: dict[str, list[str]] = {}
    for rule in rules:
        if not rule.enabled:
            continue
        for technique_id in rule.mitre_techniques or []:
            covered.setdefault(technique_id, []).append(rule.rule_id)

    observed: dict[str, int] = {}
    for row in db.execute(select(IncidentTechnique.technique_id, func.count())
                          .group_by(IncidentTechnique.technique_id)).all():
        observed[row[0]] = row[1]

    by_tactic: dict[str, dict[str, Any]] = {}
    for entry in entries:
        for tactic_id in entry.get("tactic_ids", []):
            bucket = by_tactic.setdefault(tactic_id, {
                "tactic_id": tactic_id,
                "tactic": names.get(tactic_id, tactic_id),
                "order": order.get(tactic_id, 99),
                "techniques": [],
            })
            bucket["techniques"].append({
                "technique_id": entry["technique_id"],
                "name": entry["name"],
                "is_subtechnique": entry.get("is_subtechnique", False),
                "covered": entry["technique_id"] in covered,
                "detection_rules": covered.get(entry["technique_id"], []),
                "observed_in_incidents": observed.get(entry["technique_id"], 0),
                "url": entry.get("url"),
            })

    tactic_list = sorted(by_tactic.values(), key=lambda t: t["order"])
    for bucket in tactic_list:
        bucket["techniques"].sort(key=lambda t: t["technique_id"])
        bucket["covered_count"] = sum(1 for t in bucket["techniques"] if t["covered"])
        bucket["total_count"] = len(bucket["techniques"])

    total_techniques = len(entries)
    return {
        "catalogue": {
            "technique_count": total_techniques,
            "tactic_count": len(_tactics),
            "note": (
                "The bundled catalogue is a curated subset of ATT&CK Enterprise covering the "
                "techniques this platform detects plus neighbouring techniques, so coverage "
                "percentages are relative to that subset and not to the full matrix. "
                "scripts/build_mitre_catalog.py documents the selection."
            ),
        },
        "covered_techniques": len(covered),
        "coverage_ratio": round(len(covered) / total_techniques, 3) if total_techniques else 0.0,
        "uncovered_techniques": sorted(
            {e["technique_id"] for e in entries} - set(covered.keys())
        ),
        "by_tactic": tactic_list,
    }


@router.get("/techniques/{technique_id}", summary="Technique detail with local activity")
def technique_detail(technique_id: str, db: DbSession, _: RequireViewer) -> dict[str, Any]:
    info = catalog.technique(technique_id)
    if info is None:
        raise NotFoundError(
            f"'{technique_id}' is not in the bundled ATT&CK catalogue. "
            "SENTINEL-X never invents technique identifiers; if this is a real technique, "
            "regenerate the catalogue with scripts/build_mitre_catalog.py."
        )

    _tactics, entries = catalog.load_catalog()
    entry = next(e for e in entries if e["technique_id"] == technique_id)

    rules = db.execute(
        select(DetectionRule)
        .where(
            cast(DetectionRule.mitre_techniques, Text).ilike(
                json_member(technique_id), escape=LIKE_ESCAPE
            )
        )
    ).scalars().all()

    alerts = db.execute(
        select(Alert).where(
            cast(Alert.technique_ids, Text).ilike(json_member(technique_id), escape=LIKE_ESCAPE)
        )
        .order_by(Alert.detected_at.desc()).limit(25)
    ).scalars().all()

    incident_pks = [
        row[0] for row in db.execute(
            select(IncidentTechnique.incident_pk)
            .where(IncidentTechnique.technique_id == technique_id).distinct()
        ).all()
    ]
    incidents = (
        db.execute(
            select(Incident).where(Incident.id.in_(incident_pks))
            .order_by(Incident.last_seen.desc()).limit(25)
        ).scalars().all()
        if incident_pks else []
    )

    names = catalog.tactic_names()
    return {
        **entry,
        "tactics": [{"tactic_id": t, "name": names.get(t, t)} for t in entry.get("tactic_ids", [])],
        "detection_rules": [
            {"rule_id": r.rule_id, "name": r.name, "enabled": r.enabled,
             "severity": r.severity, "rule_type": r.rule_type}
            for r in rules
        ],
        "recent_alerts": [
            {"alert_id": a.alert_id, "title": a.title, "severity": a.severity,
             "detected_at": a.detected_at.isoformat(), "rule_id": a.rule_id}
            for a in alerts
        ],
        "incidents": [
            {"incident_id": i.incident_id, "title": i.title, "severity": i.severity,
             "status": i.status, "last_seen": i.last_seen.isoformat()}
            for i in incidents
        ],
        "alert_count": len(alerts),
        "incident_count": len(incidents),
    }
