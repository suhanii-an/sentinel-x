"""Shared test fixtures.

Two things happen here before anything from ``app`` is imported, and the order
matters:

1. The environment is pinned to a throwaway SQLite database. ``app.core.database``
   builds its engine at import time from ``settings``, so setting
   ``DATABASE_URL`` afterwards would silently have no effect and the suite would
   run against whatever the developer's ``.env`` points at — which for a
   security tool could mean running destructive tests against seeded evidence.
2. ``SECRET_KEY`` is pinned to a fixed test value. Left unset, ``Settings``
   generates a fresh random key per process, which is correct behaviour for the
   application and useless for a test that wants to assert something about a
   token it minted a moment ago.

The suite is deliberately runnable with no services: no Postgres, no Redis, no
AI provider, no network. Anything that cannot be tested that way is tested
against an explicit fake rather than skipped.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

_TMP_DIR = Path(tempfile.mkdtemp(prefix="sentinelx-tests-"))

os.environ.setdefault("ENVIRONMENT", "test")

# A throwaway SQLite database unless the caller named one. CI runs the whole
# suite a second time against Postgres, because the ORM layer is dialect-neutral
# by design and a dialect bug — a JSON predicate that silently matches nothing
# on one engine — is exactly the kind that ships quietly. Overwriting the
# variable unconditionally would make that second CI leg a very slow way of
# testing SQLite twice.
#
# The guard below keeps the original safety property: a URL that is neither
# SQLite nor an obvious test database is refused, so `pytest` can never point
# at a developer's real deployment and start truncating tables between tests.
_EXTERNAL_URL = os.environ.get("DATABASE_URL", "").strip()
if _EXTERNAL_URL:
    _looks_disposable = _EXTERNAL_URL.startswith("sqlite") or any(
        marker in _EXTERNAL_URL for marker in ("test", "_ci", "ci_")
    )
    if not _looks_disposable:
        raise RuntimeError(
            "Refusing to run the test suite against "
            f"{_EXTERNAL_URL.split('@')[-1]!r}: the suite deletes every row "
            "between tests. Point DATABASE_URL at a database whose name "
            "contains 'test', or unset it to use a temporary SQLite file."
        )
else:
    os.environ["DATABASE_URL"] = f"sqlite+pysqlite:///{_TMP_DIR / 'test.db'}"

os.environ["SECRET_KEY"] = "test-only-secret-key-not-used-anywhere-real-0123456789"
os.environ["AI_PROVIDER"] = "none"
os.environ["AI_API_KEY"] = ""
os.environ["DEMO_MODE"] = "false"
# The rate limiters are process-global. Left at production values a long test
# session eventually trips them and produces confusing 429s in unrelated tests;
# the limiter itself is tested directly, with its own limits.
os.environ["RATE_LIMIT_REQUESTS"] = "100000"
os.environ["AI_RATE_LIMIT_REQUESTS"] = "100000"

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.api import deps as api_deps  # noqa: E402
from app.core import security as security_module  # noqa: E402

# bcrypt at 12 rounds costs roughly a quarter of a second per hash, and the
# suite creates three accounts and signs in several times per test. The cost
# factor is a deployment property, not a behavioural one — the code path is
# byte-for-byte the same — so the suite turns it down and pays milliseconds
# instead of minutes. `test_security.py` asserts that the shipped default is
# still strong, so this cannot mask a weakened production setting.
#
# Patched on the function object rather than on the module constant, because
# `rounds` is bound as a keyword default at definition time and other modules
# hold direct references to the function.
security_module.hash_password.__kwdefaults__["rounds"] = 4

from app.core.database import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models.enums import Role  # noqa: E402
from app.services import auth as auth_service  # noqa: E402
from app.services.ioc_store import install_indicators  # noqa: E402
from app.services.rule_registry import sync_rules  # noqa: E402

# Passwords used only by the suite. They satisfy the 12-character minimum and
# appear nowhere outside these tests.
VIEWER_PASSWORD = "test-viewer-password"
ANALYST_PASSWORD = "test-analyst-password"
ADMIN_PASSWORD = "test-admin-password"


@pytest.fixture(autouse=True)
def _reset_rate_limiters() -> None:
    """Clear the process-global rate limiters between tests.

    The login limiter is deliberately tight (10 attempts per minute) and is not
    configurable — throttling credential guessing is not something a deployment
    should be able to turn off. The suite signs in many times a minute, so it
    resets the counters rather than weakening the control. `test_security.py`
    exercises the limiter directly, with its real limits.
    """
    api_deps.general_limiter.reset()
    api_deps.ai_limiter.reset()
    api_deps.login_limiter.reset()


@pytest.fixture(scope="session", autouse=True)
def _schema() -> Iterator[None]:
    """Create the schema once for the session."""
    import app.models  # noqa: F401  (registers every mapper)

    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db() -> Iterator[Session]:
    """A session whose writes are rolled back at the end of the test.

    Every test therefore starts from an empty database. That is slower than
    sharing state, and it is the only way an assertion like "correlation
    produced exactly one incident" means anything.
    """
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()
        _truncate()


def _truncate() -> None:
    """Delete every row, children first, between tests."""
    with engine.begin() as connection:
        for table in reversed(Base.metadata.sorted_tables):
            # Table names come from SQLAlchemy's own metadata, never from
            # user input, so there is nothing here to inject.
            connection.exec_driver_sql(f"DELETE FROM {table.name}")  # noqa: S608


@pytest.fixture
def rules(db: Session) -> int:
    """Load the on-disk rule pack into the database; returns how many rules."""
    created, updated, errors = sync_rules(db)
    assert not errors, f"rule pack failed to load: {errors}"
    assert created + updated > 0, "the rule pack is empty"
    db.commit()
    return created + updated


@pytest.fixture
def indicators(db: Session) -> None:
    install_indicators(db, is_demo=False)
    db.commit()


@pytest.fixture
def users(db: Session) -> dict[str, str]:
    """One account per role."""
    auth_service.create_user(
        db, username="test-viewer", password=VIEWER_PASSWORD, role=Role.VIEWER
    )
    auth_service.create_user(
        db, username="test-analyst", password=ANALYST_PASSWORD, role=Role.ANALYST
    )
    auth_service.create_user(
        db, username="test-admin", password=ADMIN_PASSWORD, role=Role.ADMIN
    )
    db.commit()
    return {
        "viewer": VIEWER_PASSWORD,
        "analyst": ANALYST_PASSWORD,
        "admin": ADMIN_PASSWORD,
    }


@pytest.fixture
def client() -> Iterator[TestClient]:
    """An unauthenticated API client.

    ``raise_server_exceptions=False`` so a handler that raises reaches the test
    as the 500 an operator would see, letting us assert that the error envelope
    never leaks internals — with the default, the exception would propagate and
    the middleware under test would never run.
    """
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    _truncate()


def token_for(client: TestClient, username: str, password: str) -> str:
    response = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _signed_in(users: dict[str, str], role: str) -> Iterator[TestClient]:
    """A client of its own, carrying one role's token.

    Each role gets a separate client rather than re-heading a shared one: a
    test that wants to compare what an analyst and an admin may do would
    otherwise have the second fixture silently overwrite the first's
    credentials, and the comparison would assert nothing.
    """
    with TestClient(app, raise_server_exceptions=False) as test_client:
        token = token_for(test_client, f"test-{role}", users[role])
        test_client.headers.update(auth_header(token))
        yield test_client


@pytest.fixture
def analyst_client(users: dict[str, str]) -> Iterator[TestClient]:
    yield from _signed_in(users, "analyst")


@pytest.fixture
def admin_client(users: dict[str, str]) -> Iterator[TestClient]:
    yield from _signed_in(users, "admin")


@pytest.fixture
def viewer_client(users: dict[str, str]) -> Iterator[TestClient]:
    yield from _signed_in(users, "viewer")
