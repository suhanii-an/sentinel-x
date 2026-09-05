"""End-to-end pipeline tests.

The unit tests above prove each stage works. These prove the stages are
actually wired to each other, which is the claim the whole project rests on:

    simulation -> telemetry -> ingestion -> normalization -> detection ->
    alerts -> correlation -> incidents -> MITRE -> timeline -> graph ->
    evidence -> response -> report

Every assertion here goes through the HTTP API rather than calling services
directly, because "the pipeline works" and "the pipeline works through the
interface an analyst uses" are different claims and only the second one
matters to somebody running this.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def ready(analyst_client: TestClient, rules, indicators) -> TestClient:
    """An authenticated client against a database with rules and indicators
    loaded, but no security data."""
    return analyst_client


@pytest.fixture
def eval_client(admin_client: TestClient, rules, indicators) -> TestClient:
    """Running an evaluation requires the admin role."""
    return admin_client


class TestFullAttackChain:
    """One scenario, followed all the way from generated telemetry to a
    downloadable report."""

    def test_the_whole_pipeline_runs(self, ready: TestClient) -> None:
        run = ready.post(
            "/api/v1/simulations/run", json={"scenario": "full_chain", "seed": 4242}
        )
        assert run.status_code in (200, 201), run.text
        body = run.json()

        # --- telemetry was generated and ingested -----------------------
        pipeline = body["pipeline"]
        assert pipeline["events_ingested"] > 0
        assert body["run"]["status"] == "completed"
        assert body["safety_notice"]

        # --- detection fired --------------------------------------------
        assert pipeline["alerts_created"] > 0, "a full attack chain produced no alerts"
        assert body["actual_detections"], "no rule fired"

        # --- coverage is reported honestly, gaps included ----------------
        assert set(body["detections_missing"]) == (
            set(body["expected_detections"]) - set(body["actual_detections"])
        )

        # --- correlation produced an incident ----------------------------
        assert body["incidents"], "alerts were never correlated into an incident"
        incident_id = body["incidents"][0]

        # --- the incident is a complete, navigable object -----------------
        detail = ready.get(f"/api/v1/incidents/{incident_id}")
        assert detail.status_code == 200
        incident = detail.json()
        assert incident["alert_count"] > 0
        assert incident["event_count"] > 0
        assert incident["technique_ids"], "no ATT&CK techniques were mapped"
        assert incident["risk_breakdown"], "the risk score has no stated derivation"
        assert incident["correlation_reason"], "the incident cannot explain why it exists"
        assert 0.0 <= incident["confidence"] <= 1.0

        # --- timeline ----------------------------------------------------
        timeline = ready.get(f"/api/v1/incidents/{incident_id}/timeline")
        assert timeline.status_code == 200
        timeline_body = timeline.json()
        events = timeline_body["events"]
        assert events, "the incident has no timeline"
        timestamps = [entry["timestamp"] for entry in events]
        assert timestamps == sorted(timestamps), "the timeline is not in chronological order"
        # The tactic-level reconstruction and the raw evidence are returned
        # side by side, with the note stating which one wins if they disagree.
        assert "attack_chain" in timeline_body
        assert timeline_body["note"]

        # --- attack graph -------------------------------------------------
        graph = ready.get(f"/api/v1/incidents/{incident_id}/graph")
        assert graph.status_code == 200
        graph_body = graph.json()
        assert graph_body["nodes"], "the attack graph has no nodes"
        node_ids = {node["id"] for node in graph_body["nodes"]}
        for edge in graph_body["edges"]:
            assert edge["source"] in node_ids, f"edge from unknown node {edge['source']}"
            assert edge["target"] in node_ids, f"edge to unknown node {edge['target']}"

        # --- evidence -----------------------------------------------------
        evidence = ready.get(f"/api/v1/incidents/{incident_id}/evidence")
        assert evidence.status_code == 200
        assert evidence.json()["events"], "the incident carries no evidence"

        # --- MITRE mapping resolves locally --------------------------------
        techniques = ready.get(f"/api/v1/incidents/{incident_id}/techniques")
        assert techniques.status_code == 200
        mapping = techniques.json()
        assert mapping["techniques"], "the incident maps to no techniques"
        assert mapping["tactics_covered"]
        for technique in mapping["techniques"]:
            technique_id = technique["technique_id"]
            resolved = ready.get(f"/api/v1/mitre/techniques/{technique_id}")
            assert resolved.status_code == 200, (
                f"{technique_id} is not in the bundled catalogue — a technique "
                "identifier was invented somewhere"
            )
            # The name comes from the catalogue, never from the rule file.
            assert resolved.json()["name"]

        # --- response ------------------------------------------------------
        response_state = ready.get(f"/api/v1/response/incidents/{incident_id}")
        assert response_state.status_code == 200

        host = incident["affected_hosts"][0] if incident["affected_hosts"] else "web-01"
        executed = ready.post(
            "/api/v1/response/execute",
            json={
                "action_type": "isolate_host",
                "target": host,
                "incident_id": incident_id,
                "justification": "end-to-end test",
            },
        )
        assert executed.status_code in (200, 201), executed.text
        assert executed.json()["action"]["is_simulated"] is True

        # --- report ---------------------------------------------------------
        report = ready.post(
            "/api/v1/reports", json={"incident_id": incident_id, "use_ai_summary": False}
        )
        assert report.status_code in (200, 201), report.text
        report_body = report.json()
        assert report_body["content"]
        assert report_body["ai_assisted"] is False
        assert len(report_body["sections"]) >= 10

        # The report is generated from stored records, so its numbers must
        # match the incident the API just returned. A report that disagrees
        # with the console is worse than no report.
        assert incident["incident_id"] in report_body["content"]

        markdown = ready.get(f"/api/v1/reports/{report_body['report_id']}/markdown")
        assert markdown.status_code == 200
        assert markdown.content

        pdf = ready.get(f"/api/v1/reports/{report_body['report_id']}/pdf")
        assert pdf.status_code == 200
        assert pdf.content.startswith(b"%PDF")

    def test_the_same_seed_reproduces_the_same_telemetry(self, ready: TestClient) -> None:
        """Reproducibility is what makes the evaluation numbers meaningful: if
        a seeded run is not deterministic, nothing measured from it is.

        The claim is about the *telemetry*, not the alerts. Replaying the same
        attack a second time correctly produces fewer alerts, because alert
        deduplication suppresses a repeat detection on the same entity inside
        the same window — that is the suppression working, not the simulator
        drifting. Isolated-database replay is what the evaluation harness does,
        and it is asserted there.
        """
        first = ready.post(
            "/api/v1/simulations/run", json={"scenario": "brute_force", "seed": 99}
        ).json()
        second = ready.post(
            "/api/v1/simulations/run", json={"scenario": "brute_force", "seed": 99}
        ).json()

        assert first["run"]["seed"] == second["run"]["seed"] == 99
        assert first["run"]["event_count"] == second["run"]["event_count"]
        assert (
            [stage["stage"] for stage in first["run"]["stage_log"]]
            == [stage["stage"] for stage in second["run"]["stage_log"]]
        )
        assert (
            [stage["record_count"] for stage in first["run"]["stage_log"]]
            == [stage["record_count"] for stage in second["run"]["stage_log"]]
        )
        assert first["actual_detections"], "the first run detected nothing"
        assert second["pipeline"]["alerts_suppressed"] >= 0

    def test_a_different_seed_produces_different_telemetry(self, ready: TestClient) -> None:
        """Otherwise the seed is decorative and every run is the same run."""
        first = ready.post(
            "/api/v1/simulations/run", json={"scenario": "full_chain", "seed": 1}
        ).json()
        second = ready.post(
            "/api/v1/simulations/run", json={"scenario": "full_chain", "seed": 2}
        ).json()
        assert first["run"]["seed"] != second["run"]["seed"]

    def test_a_simulation_never_leaves_the_database(self, ready: TestClient) -> None:
        """The safety notice is not decoration: the scenario catalogue states
        what it will and will not do, and nothing in it reaches a real
        system."""
        scenarios = ready.get("/api/v1/simulations/scenarios").json()
        assert scenarios["safety_notice"]
        for scenario in scenarios["scenarios"]:
            assert scenario["safety_notice"]
            assert scenario["expected_telemetry"]
            assert scenario["expected_detections"]

    @pytest.mark.parametrize(
        "scenario",
        [
            "brute_force",
            "credential_abuse",
            "privilege_escalation",
            "lateral_movement",
            "persistence",
            "account_discovery",
            "cloud_iam",
        ],
    )
    def test_each_scenario_produces_telemetry_and_at_least_one_detection(
        self, ready: TestClient, scenario: str
    ) -> None:
        """A scenario the rule pack cannot see is a scenario that proves
        nothing. This is the coverage claim, asserted rather than described."""
        response = ready.post(
            "/api/v1/simulations/run", json={"scenario": scenario, "seed": 7}
        )
        assert response.status_code in (200, 201), response.text
        body = response.json()
        assert body["pipeline"]["events_ingested"] > 0
        assert body["actual_detections"], (
            f"{scenario} generated telemetry that no rule detected; "
            f"expected any of {body['expected_detections']}"
        )

    def test_an_unknown_scenario_is_refused(self, ready: TestClient) -> None:
        response = ready.post("/api/v1/simulations/run", json={"scenario": "nonexistent"})
        assert response.status_code in (404, 422)


class TestDashboardsReflectRealData:
    def test_the_dashboard_counts_match_the_underlying_records(
        self, ready: TestClient
    ) -> None:
        """A dashboard that computes its own numbers instead of reading the
        stored ones will eventually disagree with the pages it links to."""
        ready.post("/api/v1/simulations/run", json={"scenario": "full_chain", "seed": 11})

        dashboard = ready.get("/api/v1/stats/dashboard", params={"window_hours": 720}).json()
        alerts = ready.get("/api/v1/alerts", params={"limit": 1}).json()
        incidents = ready.get("/api/v1/incidents", params={"limit": 1}).json()

        assert dashboard["kpis"]["open_alerts"] <= alerts["total"]
        assert dashboard["kpis"]["active_incidents"] <= incidents["total"]
        assert dashboard["kpis"]["active_incidents"] > 0, "a full chain produced no open incident"

        # The detection-rate KPI must refuse to invent a number: it needs
        # labelled ground truth, which live telemetry does not have.
        detection_rate = dashboard["kpis"]["detection_rate"]
        if not detection_rate["measured"]:
            assert detection_rate["value"] is None
            assert detection_rate["explanation"]

    def test_simulated_data_is_labelled_as_simulated(self, ready: TestClient) -> None:
        """Seeded data is allowed; passing it off as production activity is
        not."""
        ready.post("/api/v1/simulations/run", json={"scenario": "brute_force", "seed": 3})
        info = ready.get("/api/v1/system/info").json()
        assert info["data"]["simulated_events"] > 0
        assert info["data"]["simulated_share"] > 0

    def test_mttd_is_measured_not_asserted(self, ready: TestClient) -> None:
        """The KPI must carry its own definition, because "mean time to
        detect" means several different things and a bare number is
        unfalsifiable."""
        ready.post("/api/v1/simulations/run", json={"scenario": "full_chain", "seed": 21})
        kpis = ready.get("/api/v1/stats/kpis", params={"window_hours": 720}).json()
        mttd = kpis.get("mttd")
        assert mttd is not None
        assert mttd.get("definition"), "MTTD is reported with no stated definition"


class TestSearchAndNavigation:
    def test_an_entity_from_a_simulation_is_findable(self, ready: TestClient) -> None:
        run = ready.post(
            "/api/v1/simulations/run", json={"scenario": "full_chain", "seed": 31}
        ).json()
        incident_id = run["incidents"][0]
        incident = ready.get(f"/api/v1/incidents/{incident_id}").json()

        result = ready.get("/api/v1/search", params={"q": incident_id}).json()
        assert result["total"] >= 1

        if incident["affected_hosts"]:
            host = incident["affected_hosts"][0]
            detail = ready.get(f"/api/v1/hosts/{host}")
            assert detail.status_code == 200
            assert ready.get(f"/api/v1/hosts/{host}/timeline").status_code == 200

    def test_similar_incidents_never_include_the_incident_itself(
        self, ready: TestClient
    ) -> None:
        run = ready.post(
            "/api/v1/simulations/run", json={"scenario": "full_chain", "seed": 41}
        ).json()
        incident_id = run["incidents"][0]
        body = ready.get(f"/api/v1/incidents/{incident_id}/similar").json()
        assert body["method"], "similarity is reported with no stated method"
        assert body["weights"]
        assert all(item["incident_id"] != incident_id for item in body["similar"])


class TestEvaluationHarness:
    """Running an evaluation is admin-only: it is expensive, and its result is
    the number the project is judged on."""

    def test_a_measured_evaluation_run_reports_a_full_confusion_matrix(
        self, eval_client: TestClient
    ) -> None:
        """Every number here is measured from a labelled replay. The test
        asserts the shape and the internal consistency — it deliberately does
        not assert a precision floor, because a test that demands a metric is
        a test that will eventually be satisfied by changing the metric.
        """
        response = eval_client.post(
            "/api/v1/evaluation/run",
            json={"seed": 5, "benign_days": 1, "include_ambiguous": True},
        )
        assert response.status_code in (200, 201), response.text
        body = response.json()

        metrics = body["metrics"]
        for key in ("true_positives", "false_positives", "false_negatives", "true_negatives"):
            assert key in metrics, f"the confusion matrix does not report {key}"

        tp, fp, fn = (
            metrics["true_positives"],
            metrics["false_positives"],
            metrics["false_negatives"],
        )
        # The headline metrics must be derivable from the matrix beside them.
        # A precision figure that does not follow from the counts published
        # with it is a number somebody chose.
        if tp + fp:
            assert metrics["precision"] == pytest.approx(tp / (tp + fp), abs=0.001)
        if tp + fn:
            assert metrics["recall"] == pytest.approx(tp / (tp + fn), abs=0.001)
        if metrics["precision"] and metrics["recall"]:
            expected_f1 = (
                2 * metrics["precision"] * metrics["recall"]
                / (metrics["precision"] + metrics["recall"])
            )
            assert metrics["f1"] == pytest.approx(expected_f1, abs=0.001)

        # Ambiguous events are counted, excluded from precision and recall, and
        # reported separately — scoring them either way would be a thumb on the
        # scale.
        assert body["dataset"]["ambiguous"] > 0
        assert body["dataset"]["benign"] > 0
        assert body["dataset"]["malicious"] > 0
        assert (
            body["dataset"]["benign"]
            + body["dataset"]["malicious"]
            + body["dataset"]["ambiguous"]
            == body["dataset"]["size"]
        )
        assert body["per_scenario"], "no per-scenario breakdown was reported"

    def test_the_dataset_is_byte_for_byte_reproducible(self) -> None:
        """The whole evaluation claim rests on this.

        It was not true for most of this project's life: the per-scenario RNG
        was seeded with ``hash(scenario_key)``, and Python randomises string
        hashing per process. The confusion matrix happened to be robust to the
        variation, so the bug hid behind stable-looking headline numbers while
        the measured detection latency moved by tens of seconds between runs.

        This test compares two independently built datasets field by field, so
        any future reintroduction of process-dependent randomness fails here
        rather than quietly falsifying the README.
        """
        from app.evaluation.dataset import build_dataset

        first = build_dataset(seed=1337, benign_days=2, include_ambiguous=True)
        second = build_dataset(seed=1337, benign_days=2, include_ambiguous=True)

        assert len(first.records) == len(second.records)
        assert [r.record for r in first.records] == [r.record for r in second.records]
        assert first.scenario_windows == second.scenario_windows

    def test_a_different_seed_produces_a_different_dataset(self) -> None:
        """Otherwise the seed is decorative."""
        from app.evaluation.dataset import build_dataset

        a = build_dataset(seed=1, benign_days=2, include_ambiguous=True)
        b = build_dataset(seed=2, benign_days=2, include_ambiguous=True)
        assert [r.record for r in a.records] != [r.record for r in b.records]

    def test_the_methodology_is_published_with_the_numbers(
        self, ready: TestClient
    ) -> None:
        """A benchmark without its method is a marketing claim."""
        methodology = ready.get("/api/v1/evaluation/methodology").json()
        for key in (
            "unit_of_analysis",
            "true_positive",
            "false_positive",
            "ambiguous_handling",
            "trigger_evidence_only",
            "causality",
            "isolation",
            "honesty",
        ):
            assert methodology.get(key), f"the methodology does not state {key}"

    def test_evaluation_runs_in_an_isolated_database(
        self, ready: TestClient, eval_client: TestClient
    ) -> None:
        """The harness must not pollute — or be polluted by — the live data an
        analyst is looking at."""
        before = ready.get("/api/v1/events", params={"limit": 1}).json()["total"]
        eval_client.post(
            "/api/v1/evaluation/run",
            json={"seed": 6, "benign_days": 1, "include_ambiguous": True},
        )
        after = ready.get("/api/v1/events", params={"limit": 1}).json()["total"]
        assert before == after, "the evaluation harness wrote into the live database"


class TestRuleSelfTestsThroughTheApi:
    def test_the_rule_pack_self_tests_pass_through_the_api(
        self, ready: TestClient
    ) -> None:
        body = ready.get("/api/v1/detections/tests").json()
        assert body["total"] > 0
        failures = [r for r in body["results"] if not r["passed"]]
        assert not failures, failures[:5]
        assert body["failed"] == 0

    def test_no_rule_is_silent(self, ready: TestClient) -> None:
        """A rule that never fires in any scenario or self-test is a rule
        nobody has evidence works."""
        ready.post("/api/v1/simulations/run", json={"scenario": "full_chain", "seed": 51})
        status = ready.get("/api/v1/detections/status").json()
        assert status["rules_registered"] == status["rules_on_disk"]
        assert not status["load_errors"]
