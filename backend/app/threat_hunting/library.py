"""Built-in hunts.

The hunting interface has to be useful with no LLM configured, so the questions
an analyst most often asks ship as ready-made structured queries.  They also
serve as worked examples of the DSL: an analyst who wants something slightly
different starts from the closest one and edits it.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.timeutils import utcnow
from app.models.platform import SavedHunt

BUILTIN_HUNTS: list[dict[str, Any]] = [
    {
        "name": "Failed logins followed by a success",
        "description": (
            "The classic credential-compromise shape. Correlated on source address, so a "
            "user mistyping their own password on their own machine does not match."
        ),
        "query": {
            "dataset": "events",
            "time_range": {"last_minutes": 1440},
            "sequence": {
                "steps": [
                    {
                        "name": "failures",
                        "min_count": 3,
                        "filters": [
                            {"field": "event_type", "operator": "eq", "value": "authentication"},
                            {"field": "status", "operator": "eq", "value": "failure"},
                        ],
                    },
                    {
                        "name": "success",
                        "min_count": 1,
                        "filters": [
                            {"field": "event_type", "operator": "eq", "value": "authentication"},
                            {"field": "status", "operator": "eq", "value": "success"},
                        ],
                    },
                ],
                "within_seconds": 900,
                "correlate_on": ["source_ip"],
            },
            "limit": 100,
        },
    },
    {
        "name": "Privilege escalation in the last hour",
        "description": "Every successful elevation across the estate in the last 60 minutes.",
        "query": {
            "dataset": "events",
            "time_range": {"last_minutes": 60},
            "filters": [
                {"field": "event_type", "operator": "eq", "value": "privilege"},
                {"field": "status", "operator": "eq", "value": "success"},
            ],
            "order_by": "timestamp",
            "order": "desc",
            "limit": 200,
        },
    },
    {
        "name": "Persistence mechanisms created",
        "description": "Writes to cron, systemd, init, shell profile and authorized_keys paths.",
        "query": {
            "dataset": "events",
            "time_range": {"last_minutes": 10080},
            "filters": [
                {"field": "event_type", "operator": "eq", "value": "file"},
                {"field": "metadata.persistence_path", "operator": "eq", "value": True},
            ],
            "limit": 200,
        },
    },
    {
        "name": "Authentication from external addresses",
        "description": (
            "Successful authentications whose source is outside RFC 1918 space. Noisy by "
            "itself - useful when narrowed to one account or host."
        ),
        "query": {
            "dataset": "events",
            "time_range": {"last_minutes": 1440},
            "filters": [
                {"field": "event_type", "operator": "eq", "value": "authentication"},
                {"field": "status", "operator": "eq", "value": "success"},
                {"field": "source_ip", "operator": "not_contains", "value": "10."},
            ],
            "limit": 200,
        },
    },
    {
        "name": "Cloud privilege grants",
        "description": "IAM operations that widen an identity's permissions.",
        "query": {
            "dataset": "events",
            "time_range": {"last_minutes": 10080},
            "filters": [
                {"field": "metadata.iam_category", "operator": "in",
                 "value": ["privilege_grant", "credential_creation", "trust_policy_change"]},
            ],
            "limit": 200,
        },
    },
    {
        "name": "Large outbound transfers",
        "description": "Network flows moving more than 10 MB to external address space.",
        "query": {
            "dataset": "events",
            "time_range": {"last_minutes": 10080},
            "filters": [
                {"field": "event_type", "operator": "eq", "value": "network"},
                {"field": "bytes_out", "operator": "gt", "value": 10_000_000},
            ],
            "order_by": "bytes_out",
            "order": "desc",
            "limit": 100,
        },
    },
    {
        "name": "Enumeration activity by host",
        "description": "Discovery commands, newest first - review for bursts from one account.",
        "query": {
            "dataset": "events",
            "time_range": {"last_minutes": 1440},
            "filters": [
                {"field": "event_type", "operator": "eq", "value": "discovery"},
            ],
            "limit": 300,
        },
    },
    {
        "name": "Critical and high alerts awaiting triage",
        "description": "Everything still in the 'new' state at high severity or above.",
        "query": {
            "dataset": "alerts",
            "filters": [
                {"field": "severity", "operator": "in", "value": ["critical", "high"]},
                {"field": "status", "operator": "eq", "value": "new"},
            ],
            "order_by": "risk_score",
            "order": "desc",
            "limit": 100,
        },
    },
]


def install_builtin_hunts(db: Session, *, author: str = "sentinel-x") -> int:
    """Insert the built-in hunts, skipping any already present."""
    existing = {
        row.name for row in db.execute(select(SavedHunt).where(SavedHunt.is_builtin.is_(True))).scalars().all()
    }
    created = 0
    for entry in BUILTIN_HUNTS:
        if entry["name"] in existing:
            continue
        db.add(SavedHunt(
            name=entry["name"],
            description=entry["description"],
            query=entry["query"],
            created_by=author,
            created_at=utcnow(),
            is_builtin=True,
        ))
        created += 1
    db.flush()
    return created
