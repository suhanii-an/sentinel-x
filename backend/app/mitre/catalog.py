"""MITRE ATT&CK catalogue access.

One mapping layer, referenced everywhere by ID.  No component outside this module
knows a technique's name, and no technique name is ever hard-coded in the UI or
in a detection rule — names change between ATT&CK releases, IDs do not.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.models.mitre import MitreTactic, MitreTechnique

logger = get_logger("sentinelx.mitre")


@dataclass(slots=True)
class TechniqueInfo:
    technique_id: str
    name: str
    tactic_ids: list[str]
    is_subtechnique: bool
    parent_technique_id: str | None
    url: str | None
    description: str = ""


def _data_dir() -> Path:
    return settings.data_path / "mitre"


@lru_cache(maxsize=1)
def load_catalog() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Read the bundled catalogue files.  Cached: they never change at runtime."""
    directory = _data_dir()
    tactics_path = directory / "tactics.json"
    techniques_path = directory / "techniques.json"
    if not tactics_path.exists() or not techniques_path.exists():
        logger.warning("mitre_catalog_missing", extra={"directory": str(directory)})
        return [], []
    tactics = json.loads(tactics_path.read_text(encoding="utf-8"))
    techniques = json.loads(techniques_path.read_text(encoding="utf-8"))
    return tactics, techniques


def sync_mitre(db: Session) -> tuple[int, int]:
    """Load the catalogue into the database.  Idempotent."""
    tactics, techniques = load_catalog()

    existing_tactics = {row.tactic_id: row for row in db.execute(select(MitreTactic)).scalars().all()}
    for entry in tactics:
        row = existing_tactics.get(entry["tactic_id"]) or MitreTactic(tactic_id=entry["tactic_id"])
        row.name = entry["name"]
        row.shortname = entry["shortname"]
        row.description = entry.get("description", "")
        row.order = entry.get("order", 0)
        row.url = entry.get("url")
        db.add(row)

    existing_techniques = {
        row.technique_id: row for row in db.execute(select(MitreTechnique)).scalars().all()
    }
    for entry in techniques:
        row = existing_techniques.get(entry["technique_id"]) or MitreTechnique(
            technique_id=entry["technique_id"]
        )
        row.name = entry["name"]
        row.description = entry.get("description", "")
        row.tactic_ids = entry.get("tactic_ids", [])
        row.is_subtechnique = entry.get("is_subtechnique", False)
        row.parent_technique_id = entry.get("parent_technique_id")
        row.platforms = entry.get("platforms", [])
        row.data_sources = entry.get("data_sources", [])
        row.detection_guidance = entry.get("detection_guidance", "")
        row.url = entry.get("url")
        db.add(row)

    db.flush()
    return len(tactics), len(techniques)


@lru_cache(maxsize=1)
def technique_index() -> dict[str, TechniqueInfo]:
    _, techniques = load_catalog()
    return {
        entry["technique_id"]: TechniqueInfo(
            technique_id=entry["technique_id"],
            name=entry["name"],
            tactic_ids=list(entry.get("tactic_ids", [])),
            is_subtechnique=entry.get("is_subtechnique", False),
            parent_technique_id=entry.get("parent_technique_id"),
            url=entry.get("url"),
            description=entry.get("description", ""),
        )
        for entry in techniques
    }


@lru_cache(maxsize=1)
def tactic_order() -> dict[str, int]:
    """Kill-chain position per tactic, used to order the attack chain."""
    tactics, _ = load_catalog()
    return {entry["tactic_id"]: entry.get("order", 0) for entry in tactics}


@lru_cache(maxsize=1)
def tactic_names() -> dict[str, str]:
    tactics, _ = load_catalog()
    return {entry["tactic_id"]: entry["name"] for entry in tactics}


def technique(technique_id: str) -> TechniqueInfo | None:
    return technique_index().get(technique_id)


def technique_name(technique_id: str) -> str:
    info = technique_index().get(technique_id)
    return info.name if info else technique_id


def tactics_for(technique_ids: list[str]) -> list[str]:
    """Resolve the tactics covered by a set of techniques, in kill-chain order."""
    index = technique_index()
    order = tactic_order()
    found: set[str] = set()
    for technique_id in technique_ids:
        info = index.get(technique_id)
        if info:
            found.update(info.tactic_ids)
    return sorted(found, key=lambda t: order.get(t, 99))


def unknown_techniques(technique_ids: list[str]) -> list[str]:
    """Technique IDs that are not in the catalogue.

    Used by the validation endpoint and the test suite: a rule or an AI response
    referencing an ID that does not exist is a defect, and it must be visible.
    """
    index = technique_index()
    return sorted({t for t in technique_ids if t not in index})
