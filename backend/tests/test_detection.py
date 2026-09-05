"""Detection engine tests.

The rule pack ships its own positive and negative cases, and those are run here
as a first-class part of the suite rather than as an optional extra — a rule
with no negative case is a rule nobody has checked for false positives.

Beyond that, the tests below cover the parts of the engine where a subtle bug
would be invisible in an end-to-end run: the condition language's operator
handling, the threshold detector's window arithmetic, the sequence detector's
ordering and cross-step constraints, and the anomaly detector's refusal to call
normal working hours anomalous.

Detectors take plain objects and never touch a database, so none of these tests
needs a session.
"""

from __future__ import annotations

import datetime as dt

import pytest
from pydantic import ValidationError

from app.core.config import settings
from app.detection.conditions import ConditionError, matches
from app.detection.engine import DetectionEngine
from app.detection.results import BaselineSnapshot, DetectionContext, IOCIndex
from app.detection.rules import RuleDefinition, load_rules
from app.detection.testing import run_all_rule_tests
from app.models.events import Event

BASE = dt.datetime(2026, 3, 2, 14, 0, tzinfo=dt.UTC)


def make_event(offset_seconds: int = 0, **fields) -> Event:
    defaults = {
        "event_id": f"EVT-{offset_seconds:06d}-{fields.get('user_ref', 'x')}",
        "timestamp": BASE + dt.timedelta(seconds=offset_seconds),
        "event_type": "authentication",
        "source": "linux_auth",
        "action": "login",
        "status": "failure",
        "host_ref": "web-01",
        "user_ref": "alice",
        "source_ip": "203.0.113.10",
        "meta": {},
        "raw_event": {},
    }
    defaults.update(fields)
    defaults["event_id"] = fields.get("event_id", f"EVT-{id(defaults) % 10**6}-{offset_seconds}")
    return Event(**defaults)


def context(events: list[Event], **kwargs) -> DetectionContext:
    """A context in which every supplied event counts as newly ingested.

    Stateful rules only fire on something new, so a test that forgot to
    populate ``new_event_ids`` would see silence and pass for the wrong reason.
    """
    return DetectionContext(
        events=events,
        now=kwargs.pop("now", BASE + dt.timedelta(minutes=30)),
        iocs=kwargs.pop("iocs", IOCIndex()),
        baselines=kwargs.pop("baselines", BaselineSnapshot()),
        new_event_ids=kwargs.pop("new_event_ids", {e.event_id for e in events}),
        **kwargs,
    )


def rule_from(**overrides) -> RuleDefinition:
    spec: dict = {
        "id": "TEST_RULE",
        "name": "Test rule",
        "description": "d",
        "type": "match",
        "severity": "low",
        "confidence": 0.5,
        "selection": {"status": "failure"},
        "mitre": {"techniques": ["T1110"], "tactics": ["TA0006"]},
        "tests": [],
    }
    spec.update(overrides)
    return RuleDefinition.model_validate(spec)


# --------------------------------------------------------------- the rule pack


@pytest.fixture(scope="module")
def rule_pack() -> list[RuleDefinition]:
    rules, errors = load_rules(settings.rules_path)
    assert not errors, f"the shipped rule pack does not load cleanly: {errors}"
    assert rules, "no rules found on disk"
    return rules


def test_rule_pack_loads_without_errors(rule_pack: list[RuleDefinition]) -> None:
    assert len(rule_pack) >= 20


def test_every_rule_has_a_positive_and_a_negative_test(rule_pack: list[RuleDefinition]) -> None:
    """A rule with only positive cases has never been checked for noise."""
    missing_positive = [r.id for r in rule_pack if not any(t.expect == "match" for t in r.tests)]
    missing_negative = [
        r.id for r in rule_pack if not any(t.expect == "no_match" for t in r.tests)
    ]
    assert not missing_positive, f"rules with no positive case: {missing_positive}"
    assert not missing_negative, f"rules with no negative case: {missing_negative}"


def test_shipped_rule_self_tests_all_pass(rule_pack: list[RuleDefinition]) -> None:
    summary = run_all_rule_tests(rule_pack)
    failures = [r for r in summary.results if not r.passed]
    assert not failures, "\n".join(f"{r.rule_id}/{r.test_name}: {r.detail}" for r in failures)
    assert summary.total >= len(rule_pack) * 2


def test_every_rule_maps_to_a_technique_in_the_local_catalogue(
    rule_pack: list[RuleDefinition],
) -> None:
    """Technique IDs are never invented — every one resolves locally."""
    from app.mitre import catalog

    unknown = [
        (rule.id, technique_id)
        for rule in rule_pack
        for technique_id in rule.mitre.techniques
        if catalog.technique(technique_id) is None
    ]
    assert not unknown, f"rules referencing techniques not in the catalogue: {unknown}"


def test_every_rule_documents_its_false_positives(rule_pack: list[RuleDefinition]) -> None:
    """An analyst triaging an alert needs to know what benign activity looks
    like from the rule's point of view."""
    silent = [r.id for r in rule_pack if not r.false_positives]
    assert not silent, f"rules with no documented false positives: {silent}"


def test_rule_ids_are_unique(rule_pack: list[RuleDefinition]) -> None:
    ids = [r.id for r in rule_pack]
    assert len(ids) == len(set(ids))


# ------------------------------------------------------- the condition language


class TestConditions:
    def test_equality_is_case_insensitive_by_default(self) -> None:
        event = make_event(user_ref="Administrator")
        assert matches(event, {"user": "administrator"})

    def test_case_sensitive_matching_is_opt_in(self) -> None:
        event = make_event(user_ref="Administrator")
        assert not matches(event, {"user": "administrator", "case_sensitive": True})

    def test_contains_on_a_scalar_is_a_substring_match(self) -> None:
        event = make_event(command_line="powershell -enc SQBFAFgA")
        assert matches(event, {"command_line": {"contains": "-enc"}})

    def test_contains_on_a_list_is_membership_not_substring(self) -> None:
        """A list-valued field must not be stringified and substring-matched.

        Without the list branch, `groups contains "admin"` matches a group
        called "admin-readonly" — a false positive on a privilege rule, which
        is the worst place to have one.
        """
        event = make_event(meta={"groups": ["admin-readonly", "users"]})
        assert not matches(event, {"metadata.groups": {"contains": "admin"}})
        assert matches(event, {"metadata.groups": {"contains": "admin-readonly"}})

    def test_a_bare_list_constraint_means_membership(self) -> None:
        event = make_event(process_name="mimikatz.exe")
        assert matches(event, {"process": ["procdump.exe", "mimikatz.exe"]})
        assert not matches(event, {"process": ["procdump.exe", "rundll32.exe"]})

    def test_regex_matches_against_the_field_value_only(self) -> None:
        event = make_event(command_line="whoami /priv")
        assert matches(event, {"command_line": {"regex": r"^whoami\b"}})
        assert not matches(event, {"command_line": {"regex": r"^priv"}})

    def test_all_top_level_entries_must_hold(self) -> None:
        event = make_event(status="failure", user_ref="alice")
        assert matches(event, {"status": "failure", "user": "alice"})
        assert not matches(event, {"status": "failure", "user": "bob"})

    def test_any_of_requires_only_one_branch(self) -> None:
        event = make_event(process_name="mimikatz.exe")
        assert matches(
            event, {"any_of": [{"process": "mimikatz.exe"}, {"process": "procdump.exe"}]}
        )
        assert not matches(
            event, {"any_of": [{"process": "rundll32.exe"}, {"process": "procdump.exe"}]}
        )

    def test_not_inverts_a_branch(self) -> None:
        event = make_event(user_ref="alice")
        assert matches(event, {"not": {"user": "svc-backup"}})
        assert not matches(event, {"not": {"user": "alice"}})

    def test_missing_field_does_not_match_and_does_not_raise(self) -> None:
        event = make_event(meta={})
        assert not matches(event, {"metadata.absent": "anything"})

    def test_unknown_operator_is_refused_rather_than_ignored(self) -> None:
        """Silently skipping an unrecognised operator turns a typo into a rule
        that matches everything it is asked about."""
        event = make_event()
        with pytest.raises(ConditionError):
            matches(event, {"user": {"exec": "alice"}})

    def test_numeric_comparisons_work_on_numeric_fields(self) -> None:
        event = make_event(destination_port=3389)
        assert matches(event, {"destination_port": {"gte": 3000, "lt": 4000}})
        assert not matches(event, {"destination_port": {"lt": 1024}})

    def test_regex_subject_is_length_capped(self) -> None:
        """A pathological pattern must never be handed an unbounded subject."""
        from app.detection.conditions import MAX_REGEX_SUBJECT

        event = make_event(command_line="a" * (MAX_REGEX_SUBJECT * 2))
        # Truncation means the trailing marker is not visible to the pattern.
        long_line = "a" * (MAX_REGEX_SUBJECT * 2)
        event.command_line = long_line + "MARKER"
        assert not matches(event, {"command_line": {"regex": "MARKER$"}})


# ------------------------------------------------------------- threshold rules


class TestThresholdDetector:
    def rule(self, **overrides) -> RuleDefinition:
        base: dict = {
            "id": "TEST_THRESHOLD",
            "type": "threshold",
            "severity": "high",
            "confidence": 0.8,
            "selection": {"event_type": "authentication", "status": "failure"},
            "group_by": ["user"],
            "threshold": {"count": 5, "window_seconds": 300},
        }
        base.update(overrides)
        return rule_from(**base)

    def test_fires_when_the_count_is_reached_inside_the_window(self) -> None:
        events = [make_event(i * 10, event_id=f"a{i}") for i in range(5)]
        assert len(DetectionEngine([self.rule()]).evaluate(context(events))) == 1

    def test_does_not_fire_one_short_of_the_threshold(self) -> None:
        events = [make_event(i * 10, event_id=f"b{i}") for i in range(4)]
        assert DetectionEngine([self.rule()]).evaluate(context(events)) == []

    def test_does_not_fire_when_events_are_spread_beyond_the_window(self) -> None:
        events = [make_event(i * 120, event_id=f"c{i}") for i in range(5)]
        assert DetectionEngine([self.rule()]).evaluate(context(events)) == []

    def test_grouping_keeps_separate_accounts_separate(self) -> None:
        """Three failures for alice and three for bob is not six for anyone."""
        events = [make_event(i * 10, user_ref="alice", event_id=f"d{i}") for i in range(3)]
        events += [make_event(100 + i * 10, user_ref="bob", event_id=f"e{i}") for i in range(3)]
        assert DetectionEngine([self.rule()]).evaluate(context(events)) == []

    def test_evidence_includes_every_event_in_the_window(self) -> None:
        """Not only the first N that satisfied the count.

        An analyst opening a brute-force alert that reports nine failures and
        finds five events attached has been shown a truncated attack.
        """
        events = [make_event(i * 10, event_id=f"f{i}") for i in range(9)]
        results = DetectionEngine([self.rule()]).evaluate(context(events))
        assert len(results) == 1
        assert len(results[0].evidence) == 9

    def test_distinct_field_requirement_separates_spraying_from_guessing(self) -> None:
        """Five failures against one account is guessing; against five accounts
        it is spraying, and the rule that wants spraying must not match the
        first case."""
        rule = self.rule(
            group_by=["source_ip"],
            threshold={
                "count": 5,
                "window_seconds": 300,
                "distinct_field": "user",
                "distinct_count": 5,
            },
        )
        engine = DetectionEngine([rule])

        one_account = [make_event(i * 10, event_id=f"g{i}") for i in range(5)]
        assert engine.evaluate(context(one_account)) == []

        five_accounts = [
            make_event(i * 10, user_ref=f"user{i}", event_id=f"h{i}") for i in range(5)
        ]
        assert len(engine.evaluate(context(five_accounts))) == 1

    def test_does_not_refire_on_history_alone(self) -> None:
        """A stateful rule may look back over history, but it must only fire
        when the window contains something newly ingested — otherwise every
        ingestion re-detects the whole database.

        An empty ``new_event_ids`` means "novelty is not being tracked" (rule
        self-tests and evaluation replay use that), so this test supplies a
        non-empty set that names none of the events in the window.
        """
        events = [make_event(i * 10, event_id=f"i{i}") for i in range(5)]
        ctx = context(events, new_event_ids={"an-unrelated-event"})
        assert DetectionEngine([self.rule()]).evaluate(ctx) == []


# -------------------------------------------------------------- sequence rules


class TestSequenceDetector:
    def rule(self, **overrides) -> RuleDefinition:
        base: dict = {
            "id": "TEST_SEQUENCE",
            "type": "sequence",
            "severity": "critical",
            "confidence": 0.85,
            "selection": None,
            "group_by": ["user"],
            "window_seconds": 600,
            "steps": [
                {
                    "name": "failures",
                    "selection": {"event_type": "authentication", "status": "failure"},
                    "min_count": 3,
                },
                {
                    "name": "success",
                    "selection": {"event_type": "authentication", "status": "success"},
                    "min_count": 1,
                },
            ],
        }
        base.update(overrides)
        return rule_from(**base)

    def test_fires_when_steps_occur_in_order(self) -> None:
        events = [make_event(i * 10, event_id=f"j{i}") for i in range(3)]
        events.append(make_event(60, status="success", event_id="j-ok"))
        assert len(DetectionEngine([self.rule()]).evaluate(context(events))) == 1

    def test_does_not_fire_when_the_order_is_reversed(self) -> None:
        """A success followed by failures is somebody mistyping a new password,
        not a compromise."""
        events = [make_event(0, status="success", event_id="k-ok")]
        events += [make_event(10 + i * 10, event_id=f"k{i}") for i in range(3)]
        assert DetectionEngine([self.rule()]).evaluate(context(events)) == []

    def test_does_not_fire_across_different_accounts(self) -> None:
        events = [make_event(i * 10, user_ref="alice", event_id=f"l{i}") for i in range(3)]
        events.append(make_event(60, status="success", user_ref="bob", event_id="l-ok"))
        assert DetectionEngine([self.rule()]).evaluate(context(events)) == []

    def test_does_not_fire_outside_the_window(self) -> None:
        events = [make_event(i * 10, event_id=f"m{i}") for i in range(3)]
        events.append(make_event(3600, status="success", event_id="m-ok"))
        assert DetectionEngine([self.rule()]).evaluate(context(events)) == []

    def test_evidence_spans_every_step(self) -> None:
        events = [make_event(i * 10, event_id=f"n{i}") for i in range(4)]
        events.append(make_event(60, status="success", event_id="n-ok"))
        result = DetectionEngine([self.rule()]).evaluate(context(events))[0]
        assert {ref.step for ref in result.evidence if ref.step} == {"failures", "success"}
        # Every failure belongs to the story, not only the three that satisfied
        # the minimum count.
        assert len(result.evidence) == 5

    def test_cross_step_distinct_constraint_is_enforced(self) -> None:
        rule = self.rule(constraints=[{"distinct_field": "source_ip", "min_distinct": 3}])
        engine = DetectionEngine([rule])

        one_address = [make_event(i * 10, event_id=f"o{i}") for i in range(3)]
        one_address.append(make_event(60, status="success", event_id="o-ok"))
        assert engine.evaluate(context(one_address)) == []

        three_addresses = [
            make_event(i * 10, source_ip=f"203.0.113.{10 + i}", event_id=f"p{i}")
            for i in range(3)
        ]
        three_addresses.append(make_event(60, status="success", event_id="p-ok"))
        assert len(engine.evaluate(context(three_addresses))) == 1


# --------------------------------------------------------------- anomaly rules


class TestAnomalyDetector:
    def rule(self, **params) -> RuleDefinition:
        defaults = {
            "min_observations": 8,
            "threshold": 0.20,
            "weight_new_source_ip": 0.30,
            "weight_external_source": 0.25,
            "weight_off_hours": 0.25,
            "weight_new_host": 0.20,
        }
        defaults.update(params)
        return rule_from(
            id="TEST_ANOMALY",
            type="anomaly",
            severity="medium",
            confidence=0.6,
            selection=None,
            anomaly={"detector": "anomalous_authentication", "params": defaults},
        )

    def baselines(
        self,
        *,
        hours: dict[int, int] | None = None,
        observations: int = 200,
        ips: dict[str, int] | None = None,
        hosts: dict[str, int] | None = None,
    ) -> BaselineSnapshot:
        snapshot = BaselineSnapshot()
        if hours is not None:
            key = ("user", "alice", "login_hours")
            snapshot.entries[key] = {"hours": {str(h): c for h, c in hours.items()}}
            snapshot.counts[key] = observations
        key_ip = ("user", "alice", "source_ips")
        snapshot.entries[key_ip] = {"ips": ips if ips is not None else {"203.0.113.10": 200}}
        snapshot.counts[key_ip] = observations
        key_host = ("user", "alice", "hosts")
        snapshot.entries[key_host] = {"hosts": hosts if hosts is not None else {"web-01": 200}}
        snapshot.counts[key_host] = observations
        return snapshot

    def factors_for(self, event: Event, baselines: BaselineSnapshot, **params) -> list[dict]:
        results = DetectionEngine([self.rule(**params)]).evaluate(
            context([event], baselines=baselines)
        )
        return results[0].extra.get("factors", []) if results else []

    def test_stays_silent_without_enough_history(self) -> None:
        """Calling the first login of a new account anomalous is not detection,
        it is a coin toss."""
        working_hours = dict.fromkeys(range(9, 18), 1)
        baselines = self.baselines(hours=working_hours, observations=3)
        event = make_event(status="success", timestamp=BASE.replace(hour=3), event_id="q1")
        assert DetectionEngine([self.rule()]).evaluate(context([event], baselines=baselines)) == []

    def test_activity_inside_the_observed_range_is_not_off_hours(self) -> None:
        """Membership of the exact hour is the wrong test.

        An account seen 09:00-12:00 and 14:00-17:00 has never been observed at
        13:00 because it takes lunch. Flagging 13:00 would produce a daily
        false positive for every office worker in the estate.
        """
        sparse = {9: 40, 10: 30, 11: 25, 12: 20, 14: 30, 15: 28, 16: 22, 17: 15}
        baselines = self.baselines(hours=sparse, observations=210)
        at_lunch = make_event(status="success", timestamp=BASE.replace(hour=13), event_id="q2")
        assert not any(f["name"] == "off_hours" for f in self.factors_for(at_lunch, baselines))

    def test_activity_far_outside_the_observed_range_is_flagged(self) -> None:
        sparse = {9: 40, 10: 30, 11: 25, 12: 20, 14: 30, 15: 28, 16: 22, 17: 15}
        baselines = self.baselines(hours=sparse, observations=210)
        at_three_am = make_event(status="success", timestamp=BASE.replace(hour=3), event_id="q3")
        assert any(f["name"] == "off_hours" for f in self.factors_for(at_three_am, baselines))

    def test_an_account_active_around_the_clock_is_never_off_hours(self) -> None:
        """A service account with 24-hour activity has no off-hours to be
        outside of, so the factor suppresses itself rather than inventing a
        boundary."""
        always_on = dict.fromkeys(range(24), 20)
        baselines = self.baselines(hours=always_on, observations=480)
        for hour in (2, 9, 15, 23):
            event = make_event(
                status="success", timestamp=BASE.replace(hour=hour), event_id=f"q4-{hour}"
            )
            assert not any(
                f["name"] == "off_hours" for f in self.factors_for(event, baselines)
            )

    def test_two_observed_hours_are_not_a_schedule(self) -> None:
        """Below the distinct-hour floor, "outside its hours" claims more than
        the data supports."""
        barely = {9: 100, 10: 100}
        baselines = self.baselines(hours=barely, observations=200)
        event = make_event(status="success", timestamp=BASE.replace(hour=2), event_id="q5")
        assert not any(f["name"] == "off_hours" for f in self.factors_for(event, baselines))

    def test_a_documentation_range_address_counts_as_external(self) -> None:
        """RFC 5737 documentation addresses are what the simulator uses for the
        adversary. Python's ``ipaddress.is_private`` calls them private, so a
        naive check would classify every simulated attacker as internal and the
        external-source factor would never fire.
        """
        baselines = self.baselines(
            hours=dict.fromkeys(range(9, 18), 30), observations=270, ips={"10.20.4.31": 270}
        )
        event = make_event(
            status="success",
            timestamp=BASE.replace(hour=11),
            source_ip="203.0.113.77",
            event_id="q6",
        )
        factors = {f["name"] for f in self.factors_for(event, baselines)}
        assert "external_source" in factors

    def test_every_firing_explains_which_factors_contributed(self) -> None:
        baselines = self.baselines(
            hours=dict.fromkeys(range(9, 18), 30), observations=270, ips={"10.20.4.31": 270}
        )
        event = make_event(
            status="success",
            timestamp=BASE.replace(hour=4),
            source_ip="198.51.100.7",
            host_ref="db-09",
            event_id="q7",
        )
        results = DetectionEngine([self.rule()]).evaluate(context([event], baselines=baselines))
        assert results, "expected an anomaly on an unseen host, address and hour"
        factors = results[0].extra["factors"]
        assert factors, "an anomaly alert with no stated reason is not explainable"
        for factor in factors:
            assert factor.get("reason"), f"factor {factor} carries no stated reason"
        assert results[0].explanation

    def test_failed_logins_are_not_anomaly_material(self) -> None:
        """Failures are the threshold rules' business; scoring them here would
        double-count the same behaviour."""
        baselines = self.baselines(hours=dict.fromkeys(range(9, 18), 30), observations=270)
        event = make_event(status="failure", timestamp=BASE.replace(hour=3), event_id="q8")
        assert DetectionEngine([self.rule()]).evaluate(context([event], baselines=baselines)) == []


# ------------------------------------------------------------ engine guardrails


def test_a_rule_that_raises_does_not_stop_the_others(monkeypatch) -> None:
    """One broken rule must not blind the whole detection pass."""
    from app.detection import engine as engine_module

    good = rule_from(id="GOOD")
    bad = rule_from(id="BAD")
    original = engine_module.DETECTORS["match"]

    def explode(rule, ctx):
        if rule.id == "BAD":
            raise RuntimeError("detector blew up")
        return original(rule, ctx)

    monkeypatch.setitem(engine_module.DETECTORS, "match", explode)
    results = DetectionEngine([bad, good]).evaluate(context([make_event(event_id="r1")]))
    assert [r.rule_id for r in results] == ["GOOD"]


def test_results_are_deterministically_ordered() -> None:
    """Evaluation compares runs to each other; unstable ordering would make
    that comparison meaningless."""
    rule = rule_from(id="ORDER")
    events = [make_event(i * 5, event_id=f"s{i}") for i in range(6)]
    engine = DetectionEngine([rule])
    first = [(r.rule_id, r.detected_at) for r in engine.evaluate(context(events))]
    second = [
        (r.rule_id, r.detected_at) for r in engine.evaluate(context(list(reversed(events))))
    ]
    assert first == second


def test_disabled_rules_never_run() -> None:
    rule = rule_from(id="OFF", enabled=False)
    assert DetectionEngine([rule]).evaluate(context([make_event(event_id="t1")])) == []


def test_only_rule_ids_restricts_the_pass() -> None:
    engine = DetectionEngine([rule_from(id="ONE"), rule_from(id="TWO")])
    results = engine.evaluate(context([make_event(event_id="u1")]), only_rule_ids={"TWO"})
    assert [r.rule_id for r in results] == ["TWO"]


class TestRuleValidation:
    """Rule loading is a trust boundary: a malformed rule is refused, never
    loaded in a degraded form that silently matches nothing."""

    def test_a_threshold_rule_without_a_threshold_is_refused(self) -> None:
        rule = rule_from(id="BADTHRESH", type="threshold", group_by=["user"])
        assert rule.structural_errors()

    def test_a_sequence_rule_needs_at_least_two_steps(self) -> None:
        rule = rule_from(
            id="BADSEQ",
            type="sequence",
            window_seconds=300,
            group_by=["user"],
            steps=[{"name": "only", "selection": {"status": "failure"}}],
        )
        assert rule.structural_errors()

    def test_an_unknown_field_in_a_selection_is_refused(self) -> None:
        rule = rule_from(id="BADFIELD", selection={"nonexistent_field": "x"})
        assert rule.structural_errors()

    def test_grouping_on_a_free_text_field_is_refused(self) -> None:
        """Grouping by command_line makes one group per event and silently
        disables the threshold."""
        with pytest.raises(ValidationError):
            rule_from(id="BADGROUP", type="threshold", group_by=["command_line"])

    def test_an_invented_technique_id_shape_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            rule_from(id="BADMITRE", mitre={"techniques": ["not-a-technique"], "tactics": []})

    def test_an_anomaly_rule_cannot_name_an_unregistered_detector(self) -> None:
        """The detector is a registry key, never an import path — rule content
        can never introduce executable code."""
        rule = rule_from(
            id="BADANOM",
            type="anomaly",
            anomaly={"detector": "os.system", "params": {}},
        )
        assert rule.structural_errors()
