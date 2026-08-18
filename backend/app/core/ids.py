"""Human-readable, analyst-friendly identifiers.

SOC analysts talk to each other in identifiers ("pull up SX-2026-0042").  Opaque
UUIDs are correct for machines and hostile to humans, so every analyst-facing
object gets a short prefixed ID alongside its surrogate primary key.

Format
------
EVT-<12 hex>     security event
ALT-<10 hex>     alert
SX-<year>-<nnnn> incident (sequential within the year)
IOC-<10 hex>     indicator record
ACT-<10 hex>     response action
SIM-<10 hex>     simulation run
EVAL-<10 hex>    evaluation run
RPT-<10 hex>     generated report
"""

from __future__ import annotations

import datetime as dt
import secrets

from sqlalchemy import func, select
from sqlalchemy.orm import Session


def _token(n: int) -> str:
    return secrets.token_hex(n)[:n].upper()


def event_id() -> str:
    return f"EVT-{_token(12)}"


def alert_id() -> str:
    return f"ALT-{_token(10)}"


def ioc_id() -> str:
    return f"IOC-{_token(10)}"


def action_id() -> str:
    return f"ACT-{_token(10)}"


def simulation_id() -> str:
    return f"SIM-{_token(10)}"


def evaluation_id() -> str:
    return f"EVAL-{_token(10)}"


def report_id() -> str:
    return f"RPT-{_token(10)}"


def next_incident_id(db: Session, *, now: dt.datetime | None = None) -> str:
    """Allocate the next sequential incident identifier for the current year.

    Sequential (rather than random) because incident numbering is an operational
    convention analysts rely on for ordering and for referencing in tickets.
    """
    from app.models.incidents import Incident

    now = now or dt.datetime.now(dt.UTC)
    year = now.year
    prefix = f"SX-{year}-"
    count = db.execute(
        select(func.count()).select_from(Incident).where(Incident.incident_id.like(f"{prefix}%"))
    ).scalar_one()
    return f"{prefix}{count + 1:04d}"
