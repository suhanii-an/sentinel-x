"""Behavioural baselines: what "normal" means for an entity.

Baselines are frequency tables, deliberately.  They are inspectable (an analyst
can see the exact hours and addresses an account has used), cheap to update
incrementally, and they degrade honestly — with little history they simply
refuse to make a judgement rather than inventing one.

Ordering matters and is enforced by the pipeline: detection runs *before* the
baseline is updated with the current batch.  Otherwise an anomalous login would
teach the baseline that it is normal, in the same transaction in which it is
being evaluated, and the detector would never fire.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.timeutils import utcnow
from app.detection.results import BaselineSnapshot
from app.models.enums import EventStatus, EventType
from app.models.events import Event
from app.models.platform import BehaviorBaseline

#: Bound on distinct values retained per feature.  A compromised account talking
#: to 50k addresses must not produce a 50k-entry JSON document.
MAX_VALUES_PER_FEATURE = 250

AUTH_FEATURES = ("login_hours", "source_ips", "hosts")
CLOUD_FEATURES = ("cloud_apis", "cloud_hours", "source_ips")


def build_snapshot(db: Session, user_refs: Iterable[str]) -> BaselineSnapshot:
    """Load the baselines relevant to a batch, in one query."""
    refs = sorted({u.lower() for u in user_refs if u})
    snapshot = BaselineSnapshot()
    if not refs:
        return snapshot

    rows = db.execute(
        select(BehaviorBaseline).where(
            BehaviorBaseline.entity_type == "user",
            BehaviorBaseline.entity_ref.in_(refs),
        )
    ).scalars().all()

    for row in rows:
        key = (row.entity_type, row.entity_ref.lower(), row.feature)
        snapshot.entries[key] = row.value or {}
        snapshot.counts[key] = row.observation_count
    return snapshot


def _bump(container: dict[str, int], value: str | None) -> None:
    if value is None:
        return
    key = str(value).lower()
    container[key] = container.get(key, 0) + 1
    if len(container) > MAX_VALUES_PER_FEATURE:
        # Evict the least-observed value: a baseline should remember habits, not
        # one-off noise.
        least = min(container, key=lambda k: container[k])
        if least != key:
            container.pop(least, None)


def update_baselines(db: Session, events: Sequence[Event]) -> int:
    """Fold a batch of events into the stored baselines.  Returns rows touched."""
    if not events:
        return 0

    refs = {e.user_ref.lower() for e in events if e.user_ref}
    if not refs:
        return 0

    existing = {
        (row.entity_ref.lower(), row.feature): row
        for row in db.execute(
            select(BehaviorBaseline).where(
                BehaviorBaseline.entity_type == "user",
                BehaviorBaseline.entity_ref.in_(sorted(refs)),
            )
        ).scalars().all()
    }

    def row_for(user_ref: str, feature: str) -> BehaviorBaseline:
        key = (user_ref.lower(), feature)
        if key not in existing:
            row = BehaviorBaseline(
                entity_type="user",
                entity_ref=user_ref.lower(),
                feature=feature,
                value={},
                observation_count=0,
                first_observed=utcnow(),
            )
            db.add(row)
            existing[key] = row
        return existing[key]

    touched: set[int] = set()
    for event in events:
        if not event.user_ref:
            continue

        if event.event_type == EventType.AUTHENTICATION and event.status == EventStatus.SUCCESS:
            hours_row = row_for(event.user_ref, "login_hours")
            hours = dict(hours_row.value.get("hours", {}))
            _bump(hours, str(event.timestamp.hour))
            hours_row.value = {"hours": hours}
            hours_row.observation_count += 1

            if event.source_ip:
                ip_row = row_for(event.user_ref, "source_ips")
                ips = dict(ip_row.value.get("ips", {}))
                _bump(ips, event.source_ip)
                ip_row.value = {"ips": ips}
                ip_row.observation_count += 1

            if event.host_ref:
                host_row = row_for(event.user_ref, "hosts")
                hosts = dict(host_row.value.get("hosts", {}))
                _bump(hosts, event.host_ref)
                host_row.value = {"hosts": hosts}
                host_row.observation_count += 1

        if event.cloud_account and event.action:
            api_row = row_for(event.user_ref, "cloud_apis")
            apis = dict(api_row.value.get("apis", {}))
            _bump(apis, event.action)
            api_row.value = {"apis": apis}
            api_row.observation_count += 1

            hour_row = row_for(event.user_ref, "cloud_hours")
            hours = dict(hour_row.value.get("hours", {}))
            _bump(hours, str(event.timestamp.hour))
            hour_row.value = {"hours": hours}
            hour_row.observation_count += 1

            if event.source_ip:
                ip_row = row_for(event.user_ref, "source_ips")
                ips = dict(ip_row.value.get("ips", {}))
                _bump(ips, event.source_ip)
                ip_row.value = {"ips": ips}
                ip_row.observation_count += 1

    db.flush()
    for row in existing.values():
        if row.id:
            touched.add(row.id)
    return len(touched)


def reset_baselines(db: Session) -> int:
    count = db.query(BehaviorBaseline).delete()
    db.flush()
    return count
