"""Correlation, risk scoring and confidence tests.

Correlation is where SENTINEL-X stops being an alert firehose and starts being
an investigation tool, so the properties worth pinning down are the ones that
decide whether an analyst sees one intrusion or thirty unrelated alerts:

* alerts that share an entity *and* fall close together group into one incident;
* alerts that share neither do not;
* an incident's risk score is the sum of stated, inspectable contributions and
  never a number with no derivation;
* confidence is a separate axis from risk, and never reaches certainty.
"""

from __future__ import annotations

import datetime as dt
import itertools

import pytest
from sqlalchemy.orm import Session

from app.core.ids import alert_id
from app.correlation import risk
from app.correlation.confidence import compute_confidence
from app.correlation.engine import cluster_alerts, correlate
from app.models.alerts import Alert, AlertEvent
from app.models.enums import IncidentStatus
from app.models.events import Event

BASE = dt.datetime(2026, 3, 2, 14, 0, tzinfo=dt.UTC)


_SEQUENCE = itertools.count()


def make_alert(
    db: Session | None = None,
    *,
    offset_seconds: int = 0,
    duration: int = 30,
    entity_keys: list[str] | None = None,
    severity: str = "high",
    confidence: float = 0.8,
    rule_id: str = "TEST_RULE",
    techniques: list[str] | None = None,
    tactics: list[str] | None = None,
    with_evidence: bool = True,
) -> Alert:
    """An alert, optionally with real evidence events attached.

    Evidence is attached by default because that is how every detector produces
    one: an alert with no supporting events is not a state the pipeline can
    reach, and correlation derives most of an incident's entity set from those
    events.
    """
    first = BASE + dt.timedelta(seconds=offset_seconds)
    keys = entity_keys if entity_keys is not None else ["host:web-01", "user:alice"]
    alert = Alert(
        alert_id=alert_id(),
        rule_id=rule_id,
        rule_name=rule_id.replace("_", " ").title(),
        rule_type="threshold",
        title=f"{rule_id} fired",
        description="",
        severity=severity,
        confidence=confidence,
        status="new",
        detected_at=first + dt.timedelta(seconds=duration),
        first_event_at=first,
        last_event_at=first + dt.timedelta(seconds=duration),
        entity_keys=keys,
        technique_ids=techniques or ["T1110"],
        tactics=tactics or ["TA0006"],
        explanation=["because"],
        risk_score=50.0,
        risk_breakdown=[],
        dedup_key=f"{rule_id}:{offset_seconds}",
    )
    if db is None:
        return alert

    db.add(alert)
    db.flush()

    if with_evidence:
        event = Event(
            event_id=f"EVT-{next(_SEQUENCE):06d}",
            timestamp=first,
            event_type="authentication",
            source="linux_auth",
            action="login",
            status="failure",
            host_ref=_key_value(keys, "host"),
            user_ref=_key_value(keys, "user"),
            source_ip=_key_value(keys, "ip") or "203.0.113.10",
            meta={},
            raw_event={},
        )
        db.add(event)
        db.flush()
        db.add(AlertEvent(alert_pk=alert.id, event_pk=event.id, role="trigger"))
        db.flush()

    return alert


def _key_value(keys: list[str], prefix: str) -> str | None:
    for key in keys:
        kind, _, value = key.partition(":")
        if kind == prefix:
            return value
    return None


# ------------------------------------------------------------------ clustering


class TestClustering:
    def test_alerts_sharing_an_entity_and_time_cluster_together(self) -> None:
        alerts = [
            make_alert(offset_seconds=0, entity_keys=["user:alice"]),
            make_alert(offset_seconds=120, entity_keys=["user:alice", "host:db-02"]),
        ]
        clusters = cluster_alerts(alerts, window=1800)
        assert len(clusters) == 1
        assert len(clusters[0]) == 2

    def test_alerts_with_no_shared_entity_stay_apart(self) -> None:
        """Two unrelated attacks happening at the same moment are two
        incidents, not one — the shared clock is not evidence."""
        alerts = [
            make_alert(offset_seconds=0, entity_keys=["user:alice"]),
            make_alert(offset_seconds=10, entity_keys=["user:bob"]),
        ]
        assert len(cluster_alerts(alerts, window=1800)) == 2

    def test_alerts_far_apart_in_time_stay_apart(self) -> None:
        """The same account attacked in January and again in June is two
        incidents."""
        alerts = [
            make_alert(offset_seconds=0, entity_keys=["user:alice"]),
            make_alert(offset_seconds=86_400, entity_keys=["user:alice"]),
        ]
        assert len(cluster_alerts(alerts, window=1800)) == 2

    def test_clustering_is_transitive_through_a_shared_entity(self) -> None:
        """A links to B by user, B links to C by host: all three are one
        intrusion even though A and C share nothing directly. This is what an
        attacker moving laterally actually looks like.
        """
        alerts = [
            make_alert(offset_seconds=0, entity_keys=["user:alice"]),
            make_alert(offset_seconds=60, entity_keys=["user:alice", "host:db-02"]),
            make_alert(offset_seconds=120, entity_keys=["host:db-02"]),
        ]
        clusters = cluster_alerts(alerts, window=1800)
        assert len(clusters) == 1
        assert len(clusters[0]) == 3

    def test_overlapping_windows_count_as_zero_gap(self) -> None:
        alerts = [
            make_alert(offset_seconds=0, duration=600, entity_keys=["user:alice"]),
            make_alert(offset_seconds=300, duration=60, entity_keys=["user:alice"]),
        ]
        assert len(cluster_alerts(alerts, window=1)) == 1

    def test_an_alert_with_no_entities_does_not_absorb_everything(self) -> None:
        """An empty entity set intersects nothing, so a rule that forgets to
        populate entities produces its own incident rather than swallowing the
        estate."""
        alerts = [
            make_alert(offset_seconds=0, entity_keys=[]),
            make_alert(offset_seconds=10, entity_keys=["user:alice"]),
            make_alert(offset_seconds=20, entity_keys=["user:bob"]),
        ]
        assert len(cluster_alerts(alerts, window=1800)) == 3

    def test_no_alerts_produces_no_clusters(self) -> None:
        assert cluster_alerts([], window=1800) == []


# ------------------------------------------------------- incidents in the database


class TestCorrelateIntoIncidents:
    def test_a_cluster_becomes_one_incident(self, db: Session) -> None:
        alerts = [
            make_alert(db, offset_seconds=0, entity_keys=["user:alice"], rule_id="RULE_A"),
            make_alert(db, offset_seconds=60, entity_keys=["user:alice"], rule_id="RULE_B"),
        ]
        incidents = correlate(db, alerts, window=1800)
        assert len(incidents) == 1
        assert incidents[0].alert_count == 2

    def test_unrelated_alerts_become_separate_incidents(self, db: Session) -> None:
        alerts = [
            make_alert(db, offset_seconds=0, entity_keys=["user:alice"], rule_id="RULE_A"),
            make_alert(db, offset_seconds=60, entity_keys=["user:bob"], rule_id="RULE_B"),
        ]
        incidents = correlate(db, alerts, window=1800)
        assert len(incidents) == 2

    def test_a_later_related_alert_joins_the_existing_incident(self, db: Session) -> None:
        """Rather than opening a second incident for the same intrusion, which
        is how an analyst loses the thread."""
        first = make_alert(db, offset_seconds=0, entity_keys=["user:alice"], rule_id="RULE_A")
        opened = correlate(db, [first], window=1800)
        assert len(opened) == 1
        original_id = opened[0].incident_id

        later = make_alert(db, offset_seconds=300, entity_keys=["user:alice"], rule_id="RULE_B")
        updated = correlate(db, [later], window=1800)
        assert len(updated) == 1
        assert updated[0].incident_id == original_id
        assert updated[0].alert_count == 2

    def test_a_resolved_incident_is_not_reopened_silently(self, db: Session) -> None:
        """Closing an incident is an analyst decision; new activity opens a new
        incident rather than quietly amending a closed record."""
        first = make_alert(db, offset_seconds=0, entity_keys=["user:alice"], rule_id="RULE_A")
        incident = correlate(db, [first], window=1800)[0]
        incident.status = IncidentStatus.RESOLVED
        db.flush()

        later = make_alert(db, offset_seconds=120, entity_keys=["user:alice"], rule_id="RULE_B")
        reopened = correlate(db, [later], window=1800)
        assert reopened[0].incident_id != incident.incident_id

    def test_the_incident_records_why_its_alerts_were_joined(self, db: Session) -> None:
        """A correlation an analyst cannot audit is a correlation they cannot
        disagree with."""
        alerts = [
            make_alert(db, offset_seconds=0, entity_keys=["user:alice"], rule_id="RULE_A"),
            make_alert(db, offset_seconds=60, entity_keys=["user:alice"], rule_id="RULE_B"),
        ]
        incident = correlate(db, alerts, window=1800)[0]
        assert incident.correlation_reason
        assert incident.entity_keys

    def test_incident_severity_follows_its_worst_alert(self, db: Session) -> None:
        alerts = [
            make_alert(db, offset_seconds=0, severity="low", entity_keys=["user:alice"], rule_id="RULE_A"),
            make_alert(db, offset_seconds=60, severity="critical", entity_keys=["user:alice"], rule_id="RULE_B"),
        ]
        assert correlate(db, alerts, window=1800)[0].severity == "critical"

    def test_technique_ids_are_unioned_across_alerts(self, db: Session) -> None:
        alerts = [
            make_alert(
                db, offset_seconds=0, entity_keys=["user:alice"], rule_id="RULE_A",
                techniques=["T1110"], tactics=["TA0006"],
            ),
            make_alert(
                db, offset_seconds=60, entity_keys=["user:alice"], rule_id="RULE_B",
                techniques=["T1078"], tactics=["TA0001"],
            ),
        ]
        incident = correlate(db, alerts, window=1800)[0]
        assert set(incident.technique_ids) >= {"T1110", "T1078"}

    def test_correlating_nothing_creates_nothing(self, db: Session) -> None:
        assert correlate(db, [], window=1800) == []


# --------------------------------------------------------------- risk scoring


class TestRiskScore:
    def base_kwargs(self, **overrides) -> dict:
        kwargs = {
            "severity": "high",
            "confidence": 0.8,
            "asset_criticalities": [3],
            "privileged_user": False,
            "behavioural_flags": [],
            "anomaly_score": None,
            "ioc_count": 0,
            "ioc_confidence": 0.0,
            "event_count": 5,
            "alert_count": 1,
            "distinct_tactics": 1,
        }
        kwargs.update(overrides)
        return kwargs

    def test_score_is_bounded_to_zero_and_one_hundred(self) -> None:
        maxed = risk.score_incident(
            **self.base_kwargs(
                severity="critical",
                confidence=1.0,
                asset_criticalities=[5, 5, 5],
                privileged_user=True,
                behavioural_flags=["lateral_movement", "privilege_escalation", "data_staging"],
                anomaly_score=1.0,
                ioc_count=20,
                ioc_confidence=1.0,
                event_count=500,
                alert_count=40,
                distinct_tactics=9,
            )
        )
        assert 0.0 <= maxed.score <= 100.0

        floor = risk.score_incident(
            **self.base_kwargs(
                severity="info", confidence=0.0, asset_criticalities=[], event_count=0,
                distinct_tactics=0,
            )
        )
        assert floor.score >= 0.0

    def test_every_component_states_its_weight_value_and_reason(self) -> None:
        """A risk number an analyst cannot take apart is a number they have to
        take on faith."""
        score = risk.score_incident(**self.base_kwargs())
        assert score.components
        for component in score.breakdown():
            assert component["explanation"]
            assert 0.0 <= component["value"] <= 1.0
            assert component["weight"] > 0

    def test_contributions_sum_to_the_score(self) -> None:
        score = risk.score_incident(**self.base_kwargs())
        total = sum(c["contribution"] for c in score.breakdown())
        assert score.score == pytest.approx(min(100.0, total), abs=0.1)

    def test_higher_severity_scores_higher_all_else_equal(self) -> None:
        low = risk.score_incident(**self.base_kwargs(severity="low"))
        critical = risk.score_incident(**self.base_kwargs(severity="critical"))
        assert critical.score > low.score

    def test_indicator_corroboration_raises_the_score(self) -> None:
        without = risk.score_incident(**self.base_kwargs())
        with_ioc = risk.score_incident(**self.base_kwargs(ioc_count=3, ioc_confidence=0.9))
        assert with_ioc.score > without.score

    def test_a_critical_asset_raises_the_score(self) -> None:
        commodity = risk.score_incident(**self.base_kwargs(asset_criticalities=[1]))
        crown_jewel = risk.score_incident(**self.base_kwargs(asset_criticalities=[5]))
        assert crown_jewel.score > commodity.score

    def test_the_band_follows_the_score(self) -> None:
        low = risk.score_incident(
            **self.base_kwargs(severity="info", confidence=0.1, asset_criticalities=[1],
                               event_count=1, distinct_tactics=0)
        )
        high = risk.score_incident(
            **self.base_kwargs(severity="critical", confidence=1.0, asset_criticalities=[5],
                               privileged_user=True, ioc_count=5, ioc_confidence=0.95,
                               event_count=100, alert_count=10, distinct_tactics=6)
        )
        assert low.band in {"info", "low", "medium"}
        assert high.band in {"high", "critical"}
        assert high.score > low.score

    def test_scoring_is_deterministic(self) -> None:
        a = risk.score_incident(**self.base_kwargs())
        b = risk.score_incident(**self.base_kwargs())
        assert a.score == b.score
        assert a.breakdown() == b.breakdown()

    def test_an_unknown_asset_does_not_score_as_a_crown_jewel(self) -> None:
        """Absent inventory data must not be read as maximum criticality."""
        unknown = risk.score_incident(**self.base_kwargs(asset_criticalities=[]))
        critical = risk.score_incident(**self.base_kwargs(asset_criticalities=[5]))
        assert unknown.score < critical.score


# ----------------------------------------------------------------- confidence


class TestConfidence:
    def base_kwargs(self, **overrides) -> dict:
        kwargs = {
            "alert_confidences": [0.8, 0.9],
            "event_count": 12,
            "entity_key_sets": [["user:alice"], ["user:alice", "host:db-02"]],
            "alert_times": [BASE, BASE + dt.timedelta(seconds=300)],
            "distinct_tactics": 3,
            "ioc_match_count": 1,
        }
        kwargs.update(overrides)
        return kwargs

    def test_confidence_never_reaches_certainty(self) -> None:
        """A detection platform that reports 100% confidence in its own
        inference is lying about what it can know."""
        maxed = compute_confidence(
            **self.base_kwargs(
                alert_confidences=[1.0] * 10,
                event_count=1000,
                entity_key_sets=[["user:alice", "host:a", "ip:203.0.113.1"]] * 10,
                alert_times=[BASE + dt.timedelta(seconds=i * 30) for i in range(10)],
                distinct_tactics=9,
                ioc_match_count=25,
            )
        )
        assert maxed.value < 1.0

    def test_confidence_is_between_zero_and_one(self) -> None:
        score = compute_confidence(**self.base_kwargs())
        assert 0.0 <= score.value <= 1.0

    def test_every_confidence_factor_is_explained(self) -> None:
        score = compute_confidence(**self.base_kwargs())
        assert score.components
        for component in score.breakdown():
            assert component["explanation"]

    def test_more_corroborating_tactics_raise_confidence(self) -> None:
        narrow = compute_confidence(**self.base_kwargs(distinct_tactics=1))
        broad = compute_confidence(**self.base_kwargs(distinct_tactics=5))
        assert broad.value > narrow.value

    def test_indicator_matches_raise_confidence(self) -> None:
        without = compute_confidence(**self.base_kwargs(ioc_match_count=0))
        with_ioc = compute_confidence(**self.base_kwargs(ioc_match_count=4))
        assert with_ioc.value > without.value

    def test_confidence_is_independent_of_risk(self) -> None:
        """High confidence in a low-impact finding must not inflate its risk,
        and a high-risk guess must not masquerade as a certainty. The two
        numbers answer different questions and are computed separately.
        """
        certain_but_minor = compute_confidence(
            **self.base_kwargs(alert_confidences=[0.95, 0.95], distinct_tactics=5, ioc_match_count=5)
        )
        minor_risk = risk.score_incident(
            severity="low", confidence=0.95, asset_criticalities=[1], privileged_user=False,
            behavioural_flags=[], anomaly_score=None, ioc_count=5, ioc_confidence=0.95,
            event_count=12, alert_count=2, distinct_tactics=5,
        )
        assert certain_but_minor.value > 0.5
        assert minor_risk.score < 80.0
