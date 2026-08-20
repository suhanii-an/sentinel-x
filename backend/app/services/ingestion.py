"""Event ingestion: validated telemetry in, persisted evidence out.

Responsibilities, in order:

1. Assign public event identifiers.
2. Resolve (or create) the host and user inventory records the event references,
   so entity pages are populated by ingestion rather than by a background job.
3. Persist the event with both its normalized form and its raw original.

Detection deliberately does *not* happen here.  Ingestion is a write path that
must stay fast and predictable; the pipeline (``app/services/pipeline.py``)
composes ingestion with detection and correlation.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.ids import event_id as new_event_id
from app.core.timeutils import utcnow
from app.models.entities import Host, User
from app.models.events import Event
from app.telemetry.schema import NormalizedEvent

#: Default criticality for a host we learn about from telemetry alone.  Real
#: deployments import this from a CMDB; the seed script sets it explicitly for
#: the demo estate.
DEFAULT_CRITICALITY = 3


class EntityResolver:
    """Batch-scoped cache of host/user records.

    Without this, a 200-event batch issues 400 redundant SELECTs.  Scoped to the
    batch rather than global so it can never serve stale inventory.
    """

    def __init__(self, db: Session):
        self.db = db
        self._hosts: dict[str, Host] = {}
        self._users: dict[str, User] = {}

    def host(self, host_ref: str | None, *, is_demo: bool = False) -> Host | None:
        if not host_ref:
            return None
        if host_ref in self._hosts:
            return self._hosts[host_ref]
        host = self.db.execute(select(Host).where(Host.host_id == host_ref)).scalar_one_or_none()
        if host is None:
            host = Host(
                host_id=host_ref,
                hostname=host_ref,
                os_family=_guess_os(host_ref),
                criticality=DEFAULT_CRITICALITY,
                first_seen=utcnow(),
                last_seen=utcnow(),
                tags=["auto-discovered"],
                is_demo=is_demo,
            )
            self.db.add(host)
            self.db.flush()
        self._hosts[host_ref] = host
        return host

    def user(self, user_ref: str | None, *, is_demo: bool = False) -> User | None:
        if not user_ref:
            return None
        if user_ref in self._users:
            return self._users[user_ref]
        user = self.db.execute(select(User).where(User.user_id == user_ref)).scalar_one_or_none()
        if user is None:
            user = User(
                user_id=user_ref,
                display_name=user_ref,
                user_type=_guess_user_type(user_ref),
                is_privileged=user_ref.lower() in {"root", "administrator", "admin"},
                first_seen=utcnow(),
                last_seen=utcnow(),
                tags=["auto-discovered"],
                is_demo=is_demo,
            )
            self.db.add(user)
            self.db.flush()
        self._users[user_ref] = user
        return user


def _guess_os(host_ref: str) -> str:
    upper = host_ref.upper()
    if upper.startswith("WIN") or "WINDOWS" in upper:
        return "windows"
    if upper.startswith("MAC") or "DARWIN" in upper:
        return "macos"
    return "linux"


def _guess_user_type(user_ref: str) -> str:
    lowered = user_ref.lower()
    if lowered.startswith(("svc", "service", "sa-")) or lowered.endswith(("-svc", "$")):
        return "service"
    if lowered.startswith(("arn:", "aws-", "role/")) or "-admin" in lowered:
        return "cloud"
    return "human"


def ingest_events(
    db: Session,
    events: Iterable[NormalizedEvent],
    *,
    simulation_run_pk: int | None = None,
    is_demo: bool = False,
) -> list[Event]:
    """Persist a batch of normalized events and return the ORM rows."""
    resolver = EntityResolver(db)
    now = utcnow()
    rows: list[Event] = []

    for normalized in events:
        host = resolver.host(normalized.host_id, is_demo=is_demo)
        user = resolver.user(normalized.user_id, is_demo=is_demo)

        if host is not None:
            host.last_seen = max(host.last_seen, normalized.timestamp)
            host.first_seen = min(host.first_seen, normalized.timestamp)
        if user is not None:
            user.last_seen = max(user.last_seen, normalized.timestamp)
            user.first_seen = min(user.first_seen, normalized.timestamp)

        row = Event(
            event_id=normalized.event_id or new_event_id(),
            timestamp=normalized.timestamp,
            ingested_at=now,
            event_type=str(normalized.event_type),
            source=str(normalized.source),
            host_ref=normalized.host_id,
            host_pk=host.id if host else None,
            user_ref=normalized.user_id,
            user_pk=user.id if user else None,
            source_ip=normalized.source_ip,
            destination_ip=normalized.destination_ip,
            destination_port=normalized.destination_port,
            protocol=normalized.protocol,
            bytes_out=normalized.bytes_out,
            process_name=normalized.process,
            process_id=normalized.process_id,
            parent_process=normalized.parent_process,
            command_line=normalized.command_line,
            file_path=normalized.file_path,
            file_hash=normalized.file_hash,
            cloud_provider=normalized.cloud_provider,
            cloud_account=normalized.cloud_account,
            cloud_service=normalized.cloud_service,
            cloud_resource=normalized.cloud_resource,
            cloud_region=normalized.cloud_region,
            action=normalized.action,
            status=str(normalized.status),
            message=normalized.message,
            meta=normalized.metadata,
            raw_event=normalized.raw_event,
            simulation_run_pk=simulation_run_pk,
            label=normalized.label,
            label_scenario=normalized.label_scenario,
            is_demo=is_demo,
        )
        db.add(row)
        rows.append(row)

    db.flush()
    return rows


def event_public_ids(events: Sequence[Event]) -> list[str]:
    return [e.event_id for e in events]
