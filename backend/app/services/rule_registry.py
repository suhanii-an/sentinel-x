"""Bridge between rule files on disk and the runtime rule registry.

Files are the source of truth for rule *logic*; the database is the source of
truth for rule *state* (enabled/disabled, trigger statistics).  Syncing preserves
state across restarts, so an analyst disabling a noisy rule in the UI does not
have that decision silently reverted by the next deploy.
"""

from __future__ import annotations

import threading
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.core.timeutils import utcnow
from app.detection.engine import DetectionEngine
from app.detection.rules import RuleDefinition, load_rules
from app.models.detections import DetectionRule

logger = get_logger("sentinelx.rules")

_lock = threading.Lock()
_cache: dict[str, object] = {"rules": None, "errors": [], "signature": None}


def _directory_signature(rules_dir: Path) -> tuple:
    """Cheap change token: (path, mtime, size) for every rule file."""
    entries = []
    for path in sorted(rules_dir.rglob("*")):
        if path.suffix.lower() in {".yml", ".yaml"} and path.is_file():
            stat = path.stat()
            entries.append((str(path), stat.st_mtime_ns, stat.st_size))
    return tuple(entries)


def load_rule_definitions(*, force: bool = False) -> tuple[list[RuleDefinition], list[str]]:
    """Load rules from disk, reloading only when the files have changed."""
    rules_dir = settings.rules_path
    signature = _directory_signature(rules_dir)
    with _lock:
        if not force and _cache["rules"] is not None and _cache["signature"] == signature:
            return list(_cache["rules"]), list(_cache["errors"])  # type: ignore[arg-type]
        rules, errors = load_rules(rules_dir)
        _cache["rules"] = rules
        _cache["errors"] = errors
        _cache["signature"] = signature
        if errors:
            logger.warning("rule_load_errors", extra={"count": len(errors), "errors": errors[:10]})
        return list(rules), list(errors)


def sync_rules(db: Session) -> tuple[int, int, list[str]]:
    """Upsert file-defined rules into the registry.

    Returns ``(created, updated, errors)``.
    """
    definitions, errors = load_rule_definitions(force=True)
    existing = {row.rule_id: row for row in db.execute(select(DetectionRule)).scalars().all()}
    created = updated = 0

    for definition in definitions:
        payload = definition.model_dump(mode="json")
        row = existing.get(definition.id)
        if row is None:
            row = DetectionRule(
                rule_id=definition.id,
                enabled=definition.enabled,  # file default applies only on first import
            )
            db.add(row)
            created += 1
        else:
            updated += 1

        row.name = definition.name
        row.description = definition.description
        row.rule_type = str(definition.type)
        row.severity = str(definition.severity)
        row.confidence = definition.confidence
        row.category = definition.category
        row.mitre_techniques = list(definition.mitre.techniques)
        row.tactics = list(definition.mitre.tactics)
        row.definition = payload
        row.source_path = definition.source_path
        row.author = definition.author
        row.version = definition.version
        row.references = list(definition.references)
        row.false_positives = list(definition.false_positives)
        row.tests = [t.model_dump(mode="json") for t in definition.tests]
        row.updated_at = utcnow()

    db.flush()
    return created, updated, errors


def active_engine(db: Session) -> tuple[DetectionEngine, list[str]]:
    """Build an engine containing only the rules currently enabled in the registry."""
    definitions, errors = load_rule_definitions()
    states = {
        row.rule_id: row.enabled
        for row in db.execute(select(DetectionRule.rule_id, DetectionRule.enabled)).all()
    }
    active: list[RuleDefinition] = []
    for definition in definitions:
        enabled = states.get(definition.id, definition.enabled)
        if enabled:
            copy = definition.model_copy(deep=True)
            copy.enabled = True
            active.append(copy)
    return DetectionEngine(active), errors


def record_rule_firings(db: Session, rule_ids: list[str]) -> None:
    if not rule_ids:
        return
    now = utcnow()
    rows = db.execute(
        select(DetectionRule).where(DetectionRule.rule_id.in_(sorted(set(rule_ids))))
    ).scalars().all()
    counts: dict[str, int] = {}
    for rule_id in rule_ids:
        counts[rule_id] = counts.get(rule_id, 0) + 1
    for row in rows:
        row.trigger_count += counts.get(row.rule_id, 0)
        row.last_triggered_at = now
    db.flush()
