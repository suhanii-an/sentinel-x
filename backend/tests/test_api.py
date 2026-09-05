"""API surface, authentication and authorization tests.

Three things are checked here that a per-endpoint test would miss:

* **Nothing is reachable without a token.** The test walks the OpenAPI schema
  and asserts that every operation except the deliberately public ones refuses
  an anonymous caller. A new endpoint that forgets its dependency fails this
  test the day it is added, rather than the day it is exploited.
* **Role requirements are enforced by the server**, not only hidden in the
  interface. A viewer holding a valid token still cannot change anything.
* **Errors are structured and say nothing useful to an attacker** — no SQL,
  no stack traces, no distinction between "no such account" and "wrong
  password".
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from tests.conftest import auth_header, token_for

#: Endpoints that must work without a token, and why.
PUBLIC_OPERATIONS = {
    ("post", "/api/v1/auth/login"),      # you cannot authenticate with a token you do not have
    ("get", "/api/v1/system/health"),    # orchestrators probe this before any token exists
}

#: Minimum role for each mutating operation, asserted against the live server.
ROLE_REQUIREMENTS: list[tuple[str, str, dict, str]] = [
    ("patch", "/api/v1/alerts/ALT-DOESNOTEXIST/status", {"status": "investigating"}, "analyst"),
    ("patch", "/api/v1/incidents/SX-2026-9999/status", {"status": "investigating"}, "analyst"),
    ("post", "/api/v1/incidents/SX-2026-9999/notes", {"body": "note"}, "analyst"),
    ("post", "/api/v1/simulations/run", {"scenario": "brute_force"}, "analyst"),
    ("post", "/api/v1/reports", {"incident_id": "SX-2026-9999", "use_ai_summary": False}, "analyst"),
    ("post", "/api/v1/response/execute",
     {"action_type": "isolate_host", "target": "web-01"}, "analyst"),
    # Admin, not analyst: an evaluation run is expensive and its result is the
    # number this project is judged on. Mislabelling it here silently excluded
    # it from the analyst-cannot-do-admin-things test, so a downgrade to
    # RequireAnalyst would have passed CI.
    ("post", "/api/v1/evaluation/run",
     {"seed": 1, "benign_days": 1, "include_ambiguous": True}, "admin"),
    ("patch", "/api/v1/detections/BRUTE_FORCE_001", {"enabled": False}, "admin"),
    ("post", "/api/v1/detections/sync", {}, "admin"),
    ("post", "/api/v1/auth/users",
     {"username": "someone-new", "password": "a-long-enough-password", "role": "viewer"}, "admin"),
    ("get", "/api/v1/audit", None, "admin"),
    ("post", "/api/v1/iocs",
     {"indicator": "203.0.113.200", "ioc_type": "ip", "severity": "high",
      "confidence": 0.8, "source": "test"}, "analyst"),
]


def operations(client: TestClient) -> list[tuple[str, str]]:
    spec = client.get("/openapi.json").json()
    return [
        (verb, path)
        for path, verbs in spec["paths"].items()
        for verb in verbs
        if verb in {"get", "post", "patch", "put", "delete"}
    ]


def concrete(path: str) -> str:
    """Substitute a plausible identifier for each path parameter.

    The identifier does not have to exist: an anonymous caller must be refused
    before the handler ever looks anything up, so a 404 here would itself be a
    finding.
    """
    samples = {
        "incident_id": "SX-2026-9999",
        "alert_id": "ALT-0000000000",
        "event_id": "EVT-0000000000",
        "report_id": "RPT-0000000000",
        "rule_id": "BRUTE_FORCE_001",
        "technique_id": "T1110",
        "host_id": "web-01",
        "user_id": "alice",
        "ioc_id": "IOC-0000000000",
        "run_id": "SIM-0000000000",
        "eval_id": "EVAL-0000000000",
        "identity": "svc-deploy",
        "playbook_id": "PB-BRUTE-FORCE",
        "hunt_id": "1",
    }
    return re.sub(r"\{(\w+)\}", lambda m: samples.get(m.group(1), "x"), path)


# ------------------------------------------------------------ authentication


class TestAuthentication:
    def test_login_returns_a_token_and_the_user(self, client: TestClient, users) -> None:
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "test-analyst", "password": users["analyst"]},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["access_token"]
        assert body["user"]["role"] == "analyst"

    def test_a_wrong_password_is_refused(self, client: TestClient, users) -> None:
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "test-analyst", "password": "not-the-password"},
        )
        assert response.status_code == 401

    def test_an_unknown_account_is_indistinguishable_from_a_wrong_password(
        self, client: TestClient, users
    ) -> None:
        """Different messages here turn the login endpoint into an account
        enumeration oracle."""
        wrong_password = client.post(
            "/api/v1/auth/login",
            json={"username": "test-analyst", "password": "not-the-password"},
        )
        no_such_user = client.post(
            "/api/v1/auth/login",
            json={"username": "nobody-at-all", "password": "not-the-password"},
        )
        assert wrong_password.status_code == no_such_user.status_code == 401
        assert wrong_password.json()["error"] == no_such_user.json()["error"]

    def test_no_response_ever_contains_a_password_hash(
        self, client: TestClient, users
    ) -> None:
        login = client.post(
            "/api/v1/auth/login",
            json={"username": "test-analyst", "password": users["analyst"]},
        )
        token = login.json()["access_token"]
        me = client.get("/api/v1/auth/me", headers=auth_header(token))
        for body in (login.text, me.text):
            assert "password_hash" not in body
            assert "$2b$" not in body

    def test_a_forged_token_is_refused(self, client: TestClient, users) -> None:
        forged = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiJ0ZXN0LWFkbWluIiwicm9sZSI6ImFkbWluIn0."
            "not-a-valid-signature"
        )
        assert client.get("/api/v1/auth/me", headers=auth_header(forged)).status_code == 401

    def test_a_token_with_no_signature_is_refused(self, client: TestClient, users) -> None:
        """The `alg: none` family of JWT attacks."""
        import base64
        import json

        def segment(payload: dict) -> str:
            raw = json.dumps(payload).encode()
            return base64.urlsafe_b64encode(raw).decode().rstrip("=")

        unsigned = f"{segment({'alg': 'none', 'typ': 'JWT'})}.{segment({'sub': 'test-admin'})}."
        assert client.get("/api/v1/auth/me", headers=auth_header(unsigned)).status_code == 401

    def test_a_malformed_authorization_header_is_refused(self, client: TestClient) -> None:
        for header in ({"Authorization": "Bearer"}, {"Authorization": "Basic abc"},
                       {"Authorization": "Bearer "}):
            assert client.get("/api/v1/auth/me", headers=header).status_code == 401

    def test_a_deactivated_account_cannot_use_an_issued_token(
        self, client: TestClient, users, db
    ) -> None:
        """The token is still cryptographically valid; the account is not."""
        from app.services import auth as auth_service

        token = token_for(client, "test-viewer", users["viewer"])
        assert client.get("/api/v1/auth/me", headers=auth_header(token)).status_code == 200

        user = auth_service.get_user(db, "test-viewer")
        user.is_active = False
        db.commit()

        assert client.get("/api/v1/auth/me", headers=auth_header(token)).status_code == 401

    def test_a_short_password_is_refused_when_creating_an_account(
        self, admin_client: TestClient
    ) -> None:
        response = admin_client.post(
            "/api/v1/auth/users",
            json={"username": "shorty", "password": "short", "role": "viewer"},
        )
        assert response.status_code in (400, 422)


# -------------------------------------------------------------- authorization


class TestAuthorization:
    def test_every_operation_requires_a_token(self, client: TestClient) -> None:
        """Walks the whole API rather than trusting a hand-maintained list."""
        unprotected: list[tuple[str, str, int]] = []
        for verb, path in operations(client):
            if (verb, path) in PUBLIC_OPERATIONS:
                continue
            response = client.request(verb, concrete(path), json={} if verb != "get" else None)
            if response.status_code != 401:
                unprotected.append((verb, path, response.status_code))
        assert not unprotected, f"reachable without a token: {unprotected}"

    @pytest.mark.parametrize("verb,path,payload,required", ROLE_REQUIREMENTS)
    def test_a_viewer_cannot_perform_privileged_actions(
        self, viewer_client: TestClient, verb: str, path: str, payload: dict, required: str
    ) -> None:
        response = viewer_client.request(verb, path, json=payload)
        assert response.status_code == 403, (
            f"{verb.upper()} {path} requires {required} but a viewer got {response.status_code}"
        )
        assert response.json()["error"]["code"]

    def test_an_analyst_cannot_perform_admin_actions(
        self, analyst_client: TestClient
    ) -> None:
        for verb, path, payload, required in ROLE_REQUIREMENTS:
            if required != "admin":
                continue
            response = analyst_client.request(verb, path, json=payload)
            assert response.status_code == 403, f"{verb.upper()} {path} let an analyst through"

    def test_an_analyst_may_perform_analyst_actions(
        self, analyst_client: TestClient, rules
    ) -> None:
        """The negative tests above would also pass if everything 403'd, so the
        positive case has to be asserted too."""
        response = analyst_client.post(
            "/api/v1/simulations/run", json={"scenario": "brute_force", "seed": 7}
        )
        assert response.status_code in (200, 201), response.text

    def test_the_audit_trail_is_admin_only(
        self, analyst_client: TestClient, admin_client: TestClient
    ) -> None:
        assert analyst_client.get("/api/v1/audit").status_code == 403

    def test_role_escalation_through_the_request_body_is_ignored(
        self, admin_client: TestClient, client: TestClient, users
    ) -> None:
        """Creating a user is admin-only, and the role comes from the body — so
        the check that matters is that a *viewer* cannot ask for an admin
        account."""
        token = token_for(client, "test-viewer", users["viewer"])
        response = client.post(
            "/api/v1/auth/users",
            json={"username": "escalated", "password": "a-long-enough-password", "role": "admin"},
            headers=auth_header(token),
        )
        assert response.status_code == 403


# ------------------------------------------------------------- error handling


class TestErrorEnvelope:
    def test_a_missing_resource_returns_a_structured_404(
        self, viewer_client: TestClient
    ) -> None:
        response = viewer_client.get("/api/v1/incidents/SX-2026-9999")
        assert response.status_code == 404
        body = response.json()
        assert body["error"]["code"]
        assert body["error"]["message"]

    def test_a_validation_failure_returns_422_with_details(
        self, analyst_client: TestClient
    ) -> None:
        response = analyst_client.post("/api/v1/simulations/run", json={"scenario": 12345})
        assert response.status_code == 422
        assert response.json()["error"]["code"]

    def test_error_bodies_never_leak_sql_or_stack_traces(
        self, viewer_client: TestClient
    ) -> None:
        probes = [
            ("/api/v1/incidents/' OR 1=1--", "' OR 1=1--"),
            ("/api/v1/incidents/1;DROP TABLE incidents", "1;DROP TABLE incidents"),
            ("/api/v1/events/%00", "\x00"),
            ("/api/v1/events/%27%20UNION%20SELECT%20NULL--", "' UNION SELECT NULL--"),
            ("/api/v1/hosts/../../etc/passwd", "../../etc/passwd"),
            ("/api/v1/iocs/<script>alert(1)</script>", "<script>alert(1)</script>"),
        ]
        forbidden = ("Traceback", "SELECT ", "sqlalchemy", "psycopg", "/home/", "site-packages")

        for probe, echoed in probes:
            response = viewer_client.get(probe)
            assert response.status_code < 500, f"{probe} produced a server error"
            assert response.json()["error"]["code"]

            # A "not found" message naming the identifier the caller asked for
            # is not a leak — it is the caller's own string coming back. Strip
            # that before looking for anything the server should never emit.
            residue = response.text.replace(echoed, "")
            for fragment in forbidden:
                assert fragment not in residue, f"{probe} leaked {fragment!r}"

    def test_a_nul_byte_in_the_url_is_refused_at_the_edge(
        self, viewer_client: TestClient
    ) -> None:
        """PostgreSQL raises on a NUL in a text comparison and SQLite does not,
        so a handler that passes the value through returns 404 in development
        and 500 in production. Rejecting it in the middleware makes the two
        behave the same, and a NUL in a URL is never legitimate anyway.
        """
        for probe in ("/api/v1/events/%00", "/api/v1/incidents/%00", "/api/v1/alerts?status=%00"):
            response = viewer_client.get(probe)
            assert response.status_code == 400, f"{probe} -> {response.status_code}"
            assert response.json()["error"]["code"] == "INVALID_REQUEST"

    def test_reflected_identifiers_cannot_be_interpreted_as_markup(
        self, viewer_client: TestClient
    ) -> None:
        """Error messages echo the identifier that was asked for, so the
        response must be unambiguously JSON and must not be sniffable into
        HTML."""
        response = viewer_client.get("/api/v1/incidents/<img src=x onerror=alert(1)>")
        assert response.headers["content-type"].startswith("application/json")
        assert response.headers["x-content-type-options"] == "nosniff"

    def test_an_absurdly_long_identifier_is_rejected_not_echoed_whole(
        self, viewer_client: TestClient
    ) -> None:
        """An unbounded echo turns every 404 into an amplification primitive."""
        response = viewer_client.get("/api/v1/incidents/" + "A" * 5000)
        assert response.status_code < 500
        assert len(response.content) < 4096

    def test_unknown_paths_return_a_clean_404(self, viewer_client: TestClient) -> None:
        response = viewer_client.get("/api/v1/does-not-exist")
        assert response.status_code == 404
        assert "Traceback" not in response.text


class TestAnonymousSurface:
    """What an unauthenticated caller can learn just by connecting."""

    def test_the_root_route_does_not_advertise_the_version(
        self, client: TestClient
    ) -> None:
        """`/system/health` deliberately withholds version numbers from
        anonymous callers. Publishing the version at `/` would hand back
        exactly what that endpoint refuses."""
        body = client.get("/").json()
        assert "version" not in body
        assert body["name"]
        assert body["api"]

    def test_health_reports_liveness_and_nothing_else(self, client: TestClient) -> None:
        response = client.get("/api/v1/system/health")
        assert response.status_code == 200
        body = response.json()
        for leaky in ("version", "database_url", "environment", "secret", "config"):
            assert leaky not in body, f"/system/health exposes {leaky}"

    def test_the_version_requires_authentication(
        self, client: TestClient, viewer_client: TestClient
    ) -> None:
        assert client.get("/api/v1/system/info").status_code == 401
        assert viewer_client.get("/api/v1/system/info").json()["version"]


# ---------------------------------------------------------- transport hardening


class TestSecurityHeaders:
    def test_security_headers_are_present_on_every_response(
        self, viewer_client: TestClient
    ) -> None:
        response = viewer_client.get("/api/v1/system/info")
        headers = {k.lower() for k in response.headers}
        assert "x-content-type-options" in headers
        assert "x-frame-options" in headers
        assert "content-security-policy" in headers
        assert response.headers["x-content-type-options"] == "nosniff"

    def test_security_headers_are_present_on_errors_too(self, client: TestClient) -> None:
        """An error path that skips the headers is an error path an attacker
        will aim for."""
        response = client.get("/api/v1/incidents/SX-2026-9999")
        assert response.status_code == 401
        assert "x-content-type-options" in {k.lower() for k in response.headers}

    def test_every_response_carries_a_request_id(self, viewer_client: TestClient) -> None:
        response = viewer_client.get("/api/v1/system/info")
        assert response.headers.get("x-request-id")

    def test_the_server_does_not_advertise_its_stack(
        self, viewer_client: TestClient
    ) -> None:
        response = viewer_client.get("/api/v1/system/info")
        assert "x-powered-by" not in {k.lower() for k in response.headers}


# ------------------------------------------------------------- read endpoints


class TestReadSurface:
    """Every read endpoint must answer correctly on an empty database.

    An endpoint that only works once data exists is one an operator meets for
    the first time on a fresh deployment, and it will be broken.
    """

    EMPTY_DB_ENDPOINTS = [
        "/api/v1/alerts",
        "/api/v1/alerts/stats",
        "/api/v1/incidents",
        "/api/v1/events",
        "/api/v1/events/sources",
        "/api/v1/events/timeline",
        "/api/v1/hosts",
        "/api/v1/users",
        "/api/v1/iocs",
        "/api/v1/iocs/provenance",
        "/api/v1/detections",
        "/api/v1/detections/status",
        "/api/v1/mitre/tactics",
        "/api/v1/mitre/techniques",
        "/api/v1/mitre/coverage",
        "/api/v1/cloud/overview",
        "/api/v1/cloud/accounts",
        "/api/v1/cloud/identities",
        "/api/v1/cloud/iam-changes",
        "/api/v1/stats/dashboard",
        "/api/v1/stats/kpis",
        "/api/v1/reports",
        "/api/v1/response/actions",
        "/api/v1/response/playbooks",
        "/api/v1/response/actions/history",
        "/api/v1/simulations/scenarios",
        "/api/v1/simulations/runs",
        "/api/v1/evaluation/runs",
        "/api/v1/evaluation/methodology",
        "/api/v1/hunt/schema",
        "/api/v1/hunt/saved",
        "/api/v1/ai/status",
        "/api/v1/system/info",
        "/api/v1/auth/roles",
        "/api/v1/auth/me",
    ]

    @pytest.mark.parametrize("path", EMPTY_DB_ENDPOINTS)
    def test_reads_cleanly_on_an_empty_database(
        self, viewer_client: TestClient, path: str
    ) -> None:
        response = viewer_client.get(path)
        assert response.status_code == 200, f"{path} -> {response.status_code}: {response.text[:300]}"

    def test_pagination_bounds_are_enforced(self, viewer_client: TestClient) -> None:
        """An unbounded `limit` is a denial-of-service parameter."""
        assert viewer_client.get("/api/v1/alerts", params={"limit": 100000}).status_code == 422
        assert viewer_client.get("/api/v1/alerts", params={"limit": 0}).status_code == 422
        assert viewer_client.get("/api/v1/alerts", params={"offset": -1}).status_code == 422

    def test_search_requires_a_term(self, viewer_client: TestClient) -> None:
        assert viewer_client.get("/api/v1/search").status_code == 422

    def test_system_info_states_the_simulation_boundary(
        self, viewer_client: TestClient
    ) -> None:
        """A reader should not have to infer that this is a simulation from the
        absence of a disclaimer."""
        body = viewer_client.get("/api/v1/system/info").json()
        assert body["boundaries"]
        assert "data" in body and "simulated_events" in body["data"]

    def test_ai_status_reports_unavailable_without_a_key(
        self, viewer_client: TestClient
    ) -> None:
        body = viewer_client.get("/api/v1/ai/status").json()
        assert body["available"] is False
        assert body["message"]
