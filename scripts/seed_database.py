#!/usr/bin/env python3
"""Seed SENTINEL-X with a realistic, fully-labelled demo estate.

What this produces and why each part is needed:

1. **Asset and identity inventory** with explicit criticality. Risk scoring is
   only as good as the inventory behind it; without this, every host defaults to
   criticality 3 and the asset term of the risk model says nothing.
2. **Benign history**, replayed through the real pipeline. This is what builds
   the behavioural baselines — the anomaly rules are silent for accounts with
   too little history, by design, so a demo without history cannot demonstrate
   them.
3. **Historical incidents** at staggered past timestamps, so the dashboard is not
   empty and trend charts have something to show.
4. **A recent full attack chain**, ending moments ago, for the live demo.
5. **A measured evaluation run**, so the Evaluation page shows real numbers
   rather than an empty state.

Everything created here is tagged as demo data and labelled as such in the UI.

Usage:
    python scripts/seed_database.py                 # full seed
    python scripts/seed_database.py --reset         # drop and recreate first
    python scripts/seed_database.py --quick         # less history, no evaluation
"""

from __future__ import annotations

import argparse
import datetime as dt
import random
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.core.config import settings  # noqa: E402
from app.core.database import Base, SessionLocal, create_all, engine  # noqa: E402
from app.core.timeutils import utcnow  # noqa: E402
from app.evaluation.dataset import _benign_day  # noqa: E402
from app.evaluation.runner import run_and_store  # noqa: E402
from app.mitre.catalog import sync_mitre  # noqa: E402
from app.models.entities import Host, User  # noqa: E402
from app.models.enums import Role  # noqa: E402
from app.services.auth import create_user, get_user  # noqa: E402
from app.services.ioc_store import install_indicators  # noqa: E402
from app.services.pipeline import process_events  # noqa: E402
from app.services.rule_registry import sync_rules  # noqa: E402
from app.services.simulation_runner import normalize_records, run_scenario  # noqa: E402
from app.simulators.environment import DEFAULT_ENVIRONMENT  # noqa: E402
from app.threat_hunting.library import install_builtin_hunts  # noqa: E402

#: Historical scenarios, as (scenario key, hours before now).  Spread out so
#: they correlate into separate incidents rather than one long one.
HISTORICAL_SCENARIOS = [
    ("password_spraying", 76),
    ("cloud_iam", 52),
    ("persistence", 31),
    ("account_discovery", 19),
    ("lateral_movement", 8),
]


def log(message: str) -> None:
    print(f"  {message}", flush=True)


def seed_inventory(db) -> tuple[int, int]:
    """Create hosts and identities with their real attributes."""
    env = DEFAULT_ENVIRONMENT
    hosts = users = 0

    for spec in env.hosts:
        existing = db.query(Host).filter(Host.host_id == spec.host_id).one_or_none()
        host = existing or Host(host_id=spec.host_id, first_seen=utcnow())
        host.hostname = spec.hostname
        host.os_family = spec.os_family
        host.os_version = spec.os_version
        host.ip_address = spec.ip
        host.environment = spec.environment
        host.criticality = spec.criticality
        host.tags = list(spec.tags)
        host.last_seen = utcnow()
        host.is_demo = True
        if existing is None:
            db.add(host)
            hosts += 1

    for spec in env.users:
        existing = db.query(User).filter(User.user_id == spec.user_id).one_or_none()
        user = existing or User(user_id=spec.user_id, first_seen=utcnow())
        user.display_name = spec.display_name
        user.user_type = spec.user_type
        user.department = spec.department
        user.is_privileged = spec.is_privileged
        user.tags = [f"active-hours:{spec.active_hours[0]:02d}-{spec.active_hours[1]:02d}"]
        user.last_seen = utcnow()
        user.is_demo = True
        if existing is None:
            db.add(user)
            users += 1

    db.flush()
    return hosts, users


def seed_benign_history(db, *, days: int, seed: int = 4242) -> int:
    """Replay ordinary activity so behavioural baselines have something to learn.

    Runs through the real pipeline, not a shortcut: baselines must be built the
    same way live ingestion builds them, or the demo is measuring something other
    than the product.
    """
    rng = random.Random(seed)
    env = DEFAULT_ENVIRONMENT
    now = utcnow()
    total = 0

    for day_offset in range(days, 0, -1):
        day_start = (now - dt.timedelta(days=day_offset)).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        records = _benign_day(env, rng, day_start)
        normalized, rejected = normalize_records(records)
        if rejected:
            log(f"warning: {len(rejected)} benign record(s) failed normalization")

        # Hourly batches so stateful rules see events in causal order.
        batch: list = []
        bucket = None
        for event in normalized:
            hour = event.timestamp.replace(minute=0, second=0, microsecond=0)
            if bucket is None or hour == bucket:
                bucket = hour
                batch.append(event)
            else:
                process_events(db, batch, is_demo=True)
                total += len(batch)
                batch, bucket = [event], hour
        if batch:
            process_events(db, batch, is_demo=True)
            total += len(batch)
        db.commit()

    return total


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed the SENTINEL-X demo estate.")
    parser.add_argument("--reset", action="store_true",
                        help="Drop and recreate all tables first.")
    parser.add_argument("--quick", action="store_true",
                        help="Less history and no evaluation run. Faster.")
    parser.add_argument("--benign-days", type=int, default=None,
                        help="Days of benign history to generate.")
    parser.add_argument("--no-evaluation", action="store_true",
                        help="Skip the evaluation run.")
    parser.add_argument("--seed", type=int, default=20260914,
                        help="RNG seed, for reproducibility.")
    parser.add_argument("--if-empty", action="store_true",
                        help="Do nothing if the database already holds events. "
                             "Used by the container entrypoint so a restart "
                             "does not re-seed over an operator's data.")
    args = parser.parse_args()

    benign_days = args.benign_days if args.benign_days is not None else (4 if args.quick else 21)

    print("\nSENTINEL-X database seed")
    print(f"  database : {engine.url.render_as_string(hide_password=True)}")
    print(f"  history  : {benign_days} days of benign activity")
    print()

    if args.reset:
        log("dropping existing schema")
        Base.metadata.drop_all(bind=engine)

    log("creating schema")
    create_all()

    if args.if_empty:
        # The container runs this on every start. Re-seeding a database that
        # already holds telemetry would overwrite an operator's incidents with
        # demo data, so the check is on real content rather than on a marker
        # file that a volume reset would lose.
        from sqlalchemy import func, select

        from app.models.events import Event

        probe = SessionLocal()
        try:
            existing = probe.execute(select(func.count()).select_from(Event)).scalar_one()
        finally:
            probe.close()
        if existing:
            log(f"database already holds {existing} events — leaving it alone")
            return 0

    db = SessionLocal()
    try:
        tactics, techniques = sync_mitre(db)
        log(f"MITRE ATT&CK catalogue: {tactics} tactics, {techniques} techniques")

        created, updated, errors = sync_rules(db)
        log(f"detection rules: {created} created, {updated} updated")
        if errors:
            log(f"  !! {len(errors)} rule load error(s):")
            for error in errors[:10]:
                log(f"     {error}")

        ioc_created, ioc_updated = install_indicators(db)
        log(f"indicators (local demo data): {ioc_created} created, {ioc_updated} updated")

        hunts = install_builtin_hunts(db)
        log(f"built-in hunts: {hunts} installed")

        hosts, users = seed_inventory(db)
        log(f"inventory: {hosts} hosts, {users} identities")
        db.commit()

        # ---------------------------------------------------------- account
        username = settings.BOOTSTRAP_ADMIN_USERNAME
        if get_user(db, username) is None:
            password = settings.BOOTSTRAP_ADMIN_PASSWORD
            if not password:
                raise RuntimeError(
                    "BOOTSTRAP_ADMIN_PASSWORD must be set before "
                    "creating the bootstrap admin account."
                )
            create_user(db, username=username, password=password, role=Role.ADMIN,
                        full_name="SENTINEL-X Administrator")
            db.commit()
            log(f"admin account created: {username}")
        else:
            log(f"admin account already exists: {username}")

        # ------------------------------------------------- benign baseline
        log(f"generating {benign_days} days of benign history (builds baselines)...")
        benign_events = seed_benign_history(db, days=benign_days, seed=args.seed)
        log(f"  {benign_events} benign events ingested")

        # --------------------------------------------- historical incidents
        log("running historical attack scenarios...")
        scenarios = HISTORICAL_SCENARIOS[:2] if args.quick else HISTORICAL_SCENARIOS
        for scenario, hours_ago in scenarios:
            anchor = utcnow() - dt.timedelta(hours=hours_ago)
            run, result = run_scenario(
                db, scenario, seed=args.seed + hours_ago,
                requested_by="seed", is_demo=True, anchor_end_at=anchor,
            )
            db.commit()
            log(f"  {scenario:22s} {hours_ago:3d}h ago  "
                f"{run.event_count:3d} events -> {run.alert_count:2d} alerts -> "
                f"{len(run.incident_ids)} incident(s)")

        # ------------------------------------------------- the live incident
        log("running the full attack chain (ends now)...")
        run, result = run_scenario(
            db, "full_chain", seed=args.seed, requested_by="seed", is_demo=True
        )
        db.commit()
        log(f"  {run.event_count} events -> {run.alert_count} alerts -> "
            f"incident(s) {', '.join(run.incident_ids)}")

        # ----------------------------------------------------- evaluation
        if not (args.quick or args.no_evaluation):
            log("running detection evaluation (measured, not asserted)...")
            evaluation = run_and_store(
                db, seed=1337, benign_days=14, requested_by="seed"
            )
            db.commit()
            log(f"  precision {evaluation.precision:.1%}  recall {evaluation.recall:.1%}  "
                f"F1 {evaluation.f1:.1%}  median latency "
                f"{evaluation.median_latency_ms / 1000:.1f}s")
        else:
            log("evaluation skipped (run it from the Evaluation page)")

        # --------------------------------------------------------- summary
        from sqlalchemy import func, select

        from app.models.alerts import Alert
        from app.models.events import Event
        from app.models.incidents import Incident

        print("\nSeed complete.")
        print(f"  events    : {db.execute(select(func.count()).select_from(Event)).scalar_one()}")
        print(f"  alerts    : {db.execute(select(func.count()).select_from(Alert)).scalar_one()}")
        print(f"  incidents : {db.execute(select(func.count()).select_from(Incident)).scalar_one()}")

        print()
        return 0

    except Exception as exc:
        db.rollback()
        print(f"\nSeed failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
