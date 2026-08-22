"""Indicator store loading.

The bundled dataset is explicitly local demo data — synthetic values in reserved
ranges, described as such in ``data/sample_iocs/indicators.json`` and surfaced as
such in the UI.  Nothing in SENTINEL-X contacts an external threat-intelligence
provider, and the README separates the two clearly.

The schema is provider-neutral, so attaching a real feed later is a loader change
rather than a data-model change.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.ids import ioc_id as new_ioc_id
from app.core.logging import get_logger
from app.core.timeutils import utcnow
from app.models.enums import IOCType
from app.models.iocs import IOC

logger = get_logger("sentinelx.iocs")


def default_path() -> Path:
    return settings.data_path / "sample_iocs" / "indicators.json"


def load_indicator_file(path: Path | None = None) -> dict[str, Any]:
    path = path or default_path()
    if not path.exists():
        logger.warning("ioc_dataset_missing", extra={"path": str(path)})
        return {"indicators": [], "provenance": "unavailable"}
    return json.loads(path.read_text(encoding="utf-8"))


def install_indicators(
    db: Session,
    *,
    path: Path | None = None,
    is_demo: bool = True,
) -> tuple[int, int]:
    """Upsert indicators from the dataset file.  Returns ``(created, updated)``."""
    document = load_indicator_file(path)
    entries = document.get("indicators", [])
    source_label = document.get("provenance", "LOCAL DEMO DATA")

    existing = {
        (row.indicator.lower(), row.ioc_type): row
        for row in db.execute(select(IOC)).scalars().all()
    }
    created = updated = 0
    valid_types = {t.value for t in IOCType}

    for entry in entries:
        indicator = str(entry.get("indicator", "")).strip()
        ioc_type = str(entry.get("ioc_type", "")).strip().lower()
        if not indicator or ioc_type not in valid_types:
            logger.warning("ioc_entry_skipped", extra={"indicator": indicator[:60], "type": ioc_type})
            continue

        key = (indicator.lower(), ioc_type)
        row = existing.get(key)
        if row is None:
            row = IOC(ioc_id=new_ioc_id(), indicator=indicator, ioc_type=ioc_type,
                      first_seen=utcnow(), is_demo=is_demo)
            db.add(row)
            created += 1
        else:
            updated += 1

        row.source = entry.get("source", "local-demo")
        row.confidence = float(entry.get("confidence", 0.5))
        row.severity = entry.get("severity", "medium")
        row.description = entry.get("description")
        row.tags = list(entry.get("tags", [])) + ([source_label] if source_label else [])
        row.is_active = bool(entry.get("is_active", True))

    db.flush()
    logger.info(
        "indicators_installed", extra={"created_count": created, "updated_count": updated}
    )
    return created, updated
