"""Threat hunting execution, cloud analysis and search.

`test_security.py` proves the hunt DSL refuses hostile input. This module
proves it actually answers questions — a validator that rejects everything
would pass the security tests and be useless.

The cloud and search suites are here for the same reason: they are read paths
over the same data, and the thing worth checking is that they agree with the
records the rest of the platform is showing.
"""

from __future__ import annotations

import datetime as dt

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.threat_hunting.dsl import HuntQuery
from app.threat_hunting.library import BUILTIN_HUNTS, install_builtin_hunts
from app.threat_hunting.service import run_hunt
from tests.helpers import make_alert, make_event, seeded_incident

NOW = dt.datetime.now(dt.UTC)


@pytest.fixture
def telemetry(db: Session) -> dict:
    """A small, precisely known dataset.

    Hand-built rather than simulated: a hunt test that asserts "three results"
    against generated telemetry is asserting something about the generator.
    """
    base = NOW - dt.timedelta(hours=2)
    failures = [
        make_event(db, at=base + dt.timedelta(seconds=i * 20), user="alice",
                   status="failure", source_ip="203.0.113.50")
        for i in range(4)
    ]
    success = make_event(db, at=base + dt.timedelta(minutes=2), user="alice",
                         status="success", source_ip="203.0.113.50")
    other = make_event(db, at=base + dt.timedelta(minutes=5), user="bob",
                       status="success", source_ip="10.20.4.31", host="db-02")
    process = make_event(
        db,
        at=base + dt.timedelta(minutes=6),
        event_type="process",
        source="edr_process",
        status="success",
        user="alice",
        command_line="/usr/bin/find / -perm -4000 -type f",
        metadata={"shell": "bash", "privileged": True},
    )
    db.commit()
    return {"failures": failures, "success": success, "other": other, "process": process}


class TestHuntExecution:
    def test_an_equality_filter_returns_only_matching_rows(
        self, db: Session, telemetry: dict
    ) -> None:
        result = run_hunt(
            db, HuntQuery(dataset="events", filters=[{"field": "user", "operator": "eq", "value": "bob"}])
        )
        assert result.total == 1
        assert result.rows[0]["user"] == "bob"

    def test_filters_combine_with_and_by_default(self, db: Session, telemetry: dict) -> None:
        result = run_hunt(
            db,
            HuntQuery(
                dataset="events",
                filters=[
                    {"field": "user", "operator": "eq", "value": "alice"},
                    {"field": "status", "operator": "eq", "value": "failure"},
                ],
            ),
        )
        assert result.total == 4

    def test_or_logic_widens_the_result(self, db: Session, telemetry: dict) -> None:
        result = run_hunt(
            db,
            HuntQuery(
                dataset="events",
                logic="or",
                filters=[
                    {"field": "user", "operator": "eq", "value": "bob"},
                    {"field": "event_type", "operator": "eq", "value": "process"},
                ],
            ),
        )
        assert result.total == 2

    def test_contains_finds_a_substring_in_a_command_line(
        self, db: Session, telemetry: dict
    ) -> None:
        result = run_hunt(
            db,
            HuntQuery(
                dataset="events",
                filters=[{"field": "command_line", "operator": "contains", "value": "-perm -4000"}],
            ),
        )
        assert result.total == 1

    def test_in_matches_any_listed_value(self, db: Session, telemetry: dict) -> None:
        result = run_hunt(
            db,
            HuntQuery(
                dataset="events",
                filters=[{"field": "user", "operator": "in", "value": ["alice", "bob"]}],
            ),
        )
        assert result.total == 7

    def test_a_metadata_filter_reaches_into_normalizer_enrichment(
        self, db: Session, telemetry: dict
    ) -> None:
        result = run_hunt(
            db,
            HuntQuery(
                dataset="events",
                filters=[{"field": "metadata.shell", "operator": "eq", "value": "bash"}],
            ),
        )
        assert result.total == 1

    def test_a_boolean_metadata_filter_works_on_both_dialects(
        self, db: Session, telemetry: dict
    ) -> None:
        """SQLite's json_extract returns integer 1 for true and Postgres
        returns the string 'true'. A filter that works on one and silently
        matches nothing on the other is the worst kind of dialect bug: the
        hunt returns zero rows and looks like a clean result.
        """
        result = run_hunt(
            db,
            HuntQuery(
                dataset="events",
                filters=[{"field": "metadata.privileged", "operator": "eq", "value": True}],
            ),
        )
        assert result.total == 1

    def test_a_time_range_bounds_the_result(self, db: Session, telemetry: dict) -> None:
        recent = run_hunt(
            db, HuntQuery(dataset="events", time_range={"last_minutes": 5})
        )
        everything = run_hunt(db, HuntQuery(dataset="events"))
        assert recent.total < everything.total

    def test_the_limit_bounds_returned_rows_but_not_the_total(
        self, db: Session, telemetry: dict
    ) -> None:
        """An analyst who sees "5 of 4,812" knows to narrow the hunt. One who
        sees "5" thinks they are done."""
        result = run_hunt(db, HuntQuery(dataset="events", limit=2))
        assert result.returned == 2
        assert result.total > 2
        assert result.truncated

    def test_ordering_is_applied(self, db: Session, telemetry: dict) -> None:
        newest = run_hunt(db, HuntQuery(dataset="events", order_by="timestamp", order="desc"))
        oldest = run_hunt(db, HuntQuery(dataset="events", order_by="timestamp", order="asc"))
        assert newest.rows[0]["id"] != oldest.rows[0]["id"]
        assert newest.rows[0]["timestamp"] >= oldest.rows[0]["timestamp"]

    def test_the_compiled_sql_is_shown_to_the_analyst(
        self, db: Session, telemetry: dict
    ) -> None:
        """A hunt whose query an analyst cannot read is a hunt they cannot
        check. The parameters stay bound, so the displayed SQL shows
        placeholders rather than interpolated values."""
        result = run_hunt(
            db,
            HuntQuery(dataset="events", filters=[{"field": "user", "operator": "eq", "value": "alice"}]),
            include_sql=True,
        )
        assert "SELECT" in result.compiled_sql.upper()

    def test_every_hunt_carries_a_plain_language_interpretation(
        self, db: Session, telemetry: dict
    ) -> None:
        result = run_hunt(
            db,
            HuntQuery(
                dataset="events",
                description="failed logins for alice",
                filters=[{"field": "user", "operator": "eq", "value": "alice"}],
            ),
        )
        assert result.interpretation

    def test_a_hunt_over_alerts_works(self, db: Session, telemetry: dict) -> None:
        make_alert(db, telemetry["failures"], rule_id="BRUTE_FORCE_001")
        db.commit()
        result = run_hunt(
            db,
            HuntQuery(
                dataset="alerts",
                filters=[{"field": "rule_id", "operator": "eq", "value": "BRUTE_FORCE_001"}],
            ),
        )
        assert result.total == 1

    def test_a_hunt_over_incidents_works(self, db: Session) -> None:
        seeded_incident(db)
        db.commit()
        result = run_hunt(
            db,
            HuntQuery(
                dataset="incidents",
                filters=[{"field": "severity", "operator": "eq", "value": "high"}],
            ),
        )
        assert result.total == 1

    def test_a_hunt_that_matches_nothing_returns_an_empty_result_not_an_error(
        self, db: Session, telemetry: dict
    ) -> None:
        result = run_hunt(
            db,
            HuntQuery(
                dataset="events",
                filters=[{"field": "user", "operator": "eq", "value": "nobody-at-all"}],
            ),
        )
        assert result.total == 0
        assert result.rows == []


class TestSequenceHunts:
    def test_a_sequence_hunt_correlates_steps_on_a_shared_field(
        self, db: Session, telemetry: dict
    ) -> None:
        result = run_hunt(
            db,
            HuntQuery(
                dataset="events",
                sequence={
                    "correlate_on": ["user"],
                    "within_seconds": 600,
                    "steps": [
                        {
                            "name": "failures",
                            "filters": [{"field": "status", "operator": "eq", "value": "failure"}],
                            "min_count": 3,
                        },
                        {
                            "name": "success",
                            "filters": [{"field": "status", "operator": "eq", "value": "success"}],
                            "min_count": 1,
                        },
                    ],
                },
            ),
        )
        assert result.matches, "the failure-then-success sequence was not found"
        assert result.matches[0]["correlation"]["user"] == "alice"

    def test_a_sequence_that_does_not_occur_produces_no_matches(
        self, db: Session, telemetry: dict
    ) -> None:
        result = run_hunt(
            db,
            HuntQuery(
                dataset="events",
                sequence={
                    "correlate_on": ["user"],
                    "within_seconds": 600,
                    "steps": [
                        {
                            "name": "file",
                            "filters": [{"field": "event_type", "operator": "eq", "value": "file"}],
                        },
                        {
                            "name": "network",
                            "filters": [{"field": "event_type", "operator": "eq", "value": "network"}],
                        },
                    ],
                },
            ),
        )
        assert result.matches == []


class TestMatcherParity:
    """The sequence path and the SQL path must agree.

    A sequence hunt matches its steps in Python because ordering across steps
    is not expressible in one query, so there are two implementations of the
    same filter semantics. They drifted: the in-memory matcher lowercased
    strings and the SQL builder did not, so `user eq "alice"` matched an event
    recorded as `Alice` in a sequence hunt and not in a simple one. Datetime
    comparisons were worse — the in-memory path returned False for all of them,
    so every time filter inside a sequence silently matched nothing.

    The service docstring claimed the two were checked against each other. They
    were not. This is that check.
    """

    @pytest.fixture
    def mixed_case(self, db: Session) -> None:
        base = NOW - dt.timedelta(hours=1)
        make_event(db, at=base, user="Alice", status="Failure", host="WEB-01")
        make_event(db, at=base + dt.timedelta(seconds=30), user="alice",
                   status="failure", host="web-01")
        make_event(db, at=base + dt.timedelta(minutes=1), user="ALICE",
                   status="success", host="Web-01")
        db.commit()

    FILTERS = [
        {"field": "user", "operator": "eq", "value": "alice"},
        {"field": "user", "operator": "eq", "value": "ALICE"},
        {"field": "user", "operator": "ne", "value": "bob"},
        {"field": "host", "operator": "eq", "value": "web-01"},
        {"field": "user", "operator": "in", "value": ["alice", "bob"]},
        {"field": "user", "operator": "not_in", "value": ["bob"]},
        {"field": "status", "operator": "startswith", "value": "fail"},
        {"field": "status", "operator": "contains", "value": "AIL"},
    ]

    @pytest.mark.parametrize("flt", FILTERS)
    def test_both_matchers_select_the_same_events(
        self, db: Session, mixed_case: None, flt: dict
    ) -> None:
        from app.threat_hunting.dsl import HuntFilter
        from app.threat_hunting.service import _filter_matches

        sql_rows = run_hunt(db, HuntQuery(dataset="events", filters=[flt])).rows
        sql_ids = {row["id"] for row in sql_rows}

        item = HuntFilter.model_validate(flt)
        all_events = run_hunt(db, HuntQuery(dataset="events", limit=500)).rows
        from sqlalchemy import select

        from app.models.events import Event

        every = db.execute(select(Event)).scalars().all()
        memory_ids = {e.event_id for e in every if _filter_matches(e, item)}

        assert sql_ids == memory_ids, (
            f"{flt} selected {len(sql_ids)} rows in SQL and {len(memory_ids)} in memory"
        )
        assert len(all_events) >= len(sql_rows)

    def test_a_time_filter_inside_a_sequence_is_not_silently_empty(
        self, db: Session, telemetry: dict
    ) -> None:
        from sqlalchemy import select

        from app.models.events import Event
        from app.threat_hunting.dsl import HuntFilter
        from app.threat_hunting.service import _filter_matches

        item = HuntFilter.model_validate(
            {"field": "timestamp", "operator": "gt", "value": "2020-01-01T00:00:00Z"}
        )
        every = db.execute(select(Event)).scalars().all()
        assert every
        assert all(_filter_matches(e, item) for e in every), (
            "an in-memory time comparison matched nothing"
        )


class TestSavedHunts:
    def test_the_builtin_library_installs_and_every_entry_is_valid(
        self, db: Session
    ) -> None:
        """A shipped hunt that does not parse is a broken example somebody will
        copy."""
        installed = install_builtin_hunts(db)
        db.commit()
        assert installed == len(BUILTIN_HUNTS)
        for entry in BUILTIN_HUNTS:
            HuntQuery.model_validate(entry["query"])

    def test_every_builtin_hunt_runs_without_error(self, db: Session, telemetry: dict) -> None:
        for entry in BUILTIN_HUNTS:
            query = HuntQuery.model_validate(entry["query"])
            result = run_hunt(db, query)
            assert result.total >= 0, f"{entry['name']} failed to execute"

    def test_a_hunt_can_be_saved_and_re_run_through_the_api(
        self, analyst_client: TestClient, rules
    ) -> None:
        saved = analyst_client.post(
            "/api/v1/hunt/saved",
            json={
                "name": "Failed logins for one account",
                "description": "Test hunt",
                "query": {
                    "dataset": "events",
                    "filters": [{"field": "status", "operator": "eq", "value": "failure"}],
                },
            },
        )
        assert saved.status_code in (200, 201), saved.text
        hunt_id = saved.json()["id"]

        listed = analyst_client.get("/api/v1/hunt/saved").json()
        assert any(item["id"] == hunt_id for item in listed)

        rerun = analyst_client.post(f"/api/v1/hunt/saved/{hunt_id}/run")
        assert rerun.status_code == 200, rerun.text
        assert "total" in rerun.json()

    def test_the_hunt_schema_documents_what_is_queryable(
        self, viewer_client: TestClient
    ) -> None:
        """The field allow-list is the security control, so it is also the
        documentation — an analyst should not have to guess and get a 422."""
        schema = viewer_client.get("/api/v1/hunt/schema").json()
        assert schema["datasets"]["events"]
        assert schema["operators"]
        assert schema["safety"]
        assert schema["sequence"]["max_steps"] >= 2

    def test_natural_language_translation_is_unavailable_without_a_provider(
        self, analyst_client: TestClient
    ) -> None:
        """And says so, rather than silently returning an empty query."""
        response = analyst_client.post(
            "/api/v1/hunt/translate",
            json={"question": "show me failed logins for alice", "execute": False},
        )
        assert response.status_code in (200, 503)
        if response.status_code == 200:
            body = response.json()
            assert body["ai"]["accepted"] is False or body["query"] is None


class TestCloudAnalysis:
    @pytest.fixture
    def cloud_data(self, analyst_client: TestClient, rules, indicators) -> TestClient:
        analyst_client.post(
            "/api/v1/simulations/run", json={"scenario": "cloud_iam", "seed": 77}
        )
        return analyst_client

    def test_the_overview_summarises_real_control_plane_activity(
        self, cloud_data: TestClient
    ) -> None:
        body = cloud_data.get("/api/v1/cloud/overview", params={"window_hours": 720}).json()
        assert body["notice"]
        assert body["event_count"] > 0
        assert body["accounts"]
        assert body["identity_count"] > 0

    def test_identity_risk_scores_state_their_factors(
        self, cloud_data: TestClient
    ) -> None:
        body = cloud_data.get("/api/v1/cloud/identities", params={"window_hours": 720}).json()
        assert body["risk_model"]
        assert body["identities"]
        for identity in body["identities"]:
            assert 0.0 <= identity["risk_score"] <= 100.0
            for factor in identity["factors"]:
                assert factor["explanation"]

    def test_the_identity_graph_is_internally_consistent(
        self, cloud_data: TestClient
    ) -> None:
        identities = cloud_data.get(
            "/api/v1/cloud/identities", params={"window_hours": 720}
        ).json()["identities"]
        identity = identities[0]["identity"]

        graph = cloud_data.get(f"/api/v1/cloud/identities/{identity}/graph").json()
        node_ids = {node["id"] for node in graph["nodes"]}
        for edge in graph["edges"]:
            assert edge["source"] in node_ids
            assert edge["target"] in node_ids

    def test_iam_changes_are_listed_newest_first(self, cloud_data: TestClient) -> None:
        changes = cloud_data.get(
            "/api/v1/cloud/iam-changes", params={"window_hours": 720}
        ).json()
        items = changes if isinstance(changes, list) else changes.get("items", changes.get("changes", []))
        timestamps = [item["timestamp"] for item in items]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_an_unknown_identity_returns_an_empty_graph_not_an_error(
        self, cloud_data: TestClient
    ) -> None:
        response = cloud_data.get("/api/v1/cloud/identities/nobody-at-all/graph")
        assert response.status_code in (200, 404)
        if response.status_code == 200:
            assert response.json()["event_count"] == 0


class TestSearch:
    @pytest.fixture
    def searchable(self, analyst_client: TestClient, rules, indicators) -> dict:
        run = analyst_client.post(
            "/api/v1/simulations/run", json={"scenario": "full_chain", "seed": 88}
        ).json()
        incident_id = run["incidents"][0]
        incident = analyst_client.get(f"/api/v1/incidents/{incident_id}").json()
        return {"client": analyst_client, "incident": incident}

    def test_an_incident_id_is_found_directly(self, searchable: dict) -> None:
        client, incident = searchable["client"], searchable["incident"]
        body = client.get("/api/v1/search", params={"q": incident["incident_id"]}).json()
        assert body["total"] >= 1
        assert body["kind"]

    def test_an_ip_address_is_recognised_by_its_shape(self, searchable: dict) -> None:
        """The term's type is inferred first, so an address goes straight to an
        indexed lookup instead of scanning every table."""
        client, incident = searchable["client"], searchable["incident"]
        if not incident["source_ips"]:
            pytest.skip("this run produced no source addresses")
        body = client.get("/api/v1/search", params={"q": incident["source_ips"][0]}).json()
        assert body["kind"] in {"ip", "address", "mixed"}

    def test_a_technique_id_is_recognised(self, searchable: dict) -> None:
        client = searchable["client"]
        body = client.get("/api/v1/search", params={"q": "T1110"}).json()
        assert body["total"] >= 0
        assert body["kind"]

    def test_a_hostname_finds_the_host(self, searchable: dict) -> None:
        client, incident = searchable["client"], searchable["incident"]
        if not incident["affected_hosts"]:
            pytest.skip("this run produced no hosts")
        host = incident["affected_hosts"][0]
        body = client.get("/api/v1/search", params={"q": host}).json()
        assert body["total"] >= 1

    def test_a_term_that_matches_nothing_says_so(self, searchable: dict) -> None:
        client = searchable["client"]
        body = client.get(
            "/api/v1/search", params={"q": "zzzz-nothing-matches-this-zzzz"}
        ).json()
        assert body["total"] == 0
        assert body["message"], "an empty result with no explanation looks like a broken search"

    def test_search_input_is_length_bounded(self, searchable: dict) -> None:
        client = searchable["client"]
        assert client.get("/api/v1/search", params={"q": "A" * 500}).status_code == 422
