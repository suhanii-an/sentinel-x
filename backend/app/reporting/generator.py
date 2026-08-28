"""Incident report generation.

The report is assembled from stored records only.  Every figure in it — counts,
durations, scores, latencies — is read from the database rather than recomputed
or estimated at render time, so the report and the UI can never disagree.

The executive summary is written deterministically by default.  When an AI
provider is configured the analyst may substitute an AI-drafted version, and the
report records which was used.  Provenance is part of the document, not a UI
detail: a manager reading a summary is entitled to know whether a human-reviewable
template or a language model wrote it.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.ids import report_id as new_report_id
from app.core.netutils import is_external
from app.core.timeutils import iso, utcnow
from app.mitre import catalog
from app.models.detections import DetectionRule
from app.models.entities import Host, User
from app.models.incidents import Incident
from app.models.operations import Report, ResponseAction
from app.response.service import incident_playbooks
from app.services.timeline import build_incident_timeline

SECTION_ORDER = [
    "Executive Summary",
    "Incident Overview",
    "Severity and Risk Assessment",
    "Attack Timeline",
    "Affected Assets",
    "Accounts Involved",
    "Indicators of Compromise",
    "MITRE ATT&CK Mapping",
    "Evidence",
    "Root Cause Hypothesis",
    "Detection Logic",
    "Response Actions",
    "Recommendations",
    "Analyst Notes",
    "Methodology and Limitations",
]


def _fmt_duration(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds} seconds"
    minutes, remainder = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {remainder}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m"


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows:
        return "_None recorded._\n"
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        cells = [str(c).replace("|", "\\|").replace("\n", " ") if c is not None else "-" for c in row]
        out.append("| " + " | ".join(cells) + " |")
    return "\n".join(out) + "\n"


def deterministic_executive_summary(incident: Incident) -> str:
    """Plain-language summary written from stored facts.

    Written for a reader who does not know what ATT&CK is. No technique IDs, no
    rule names, no tool vocabulary.
    """
    hosts = incident.affected_hosts
    users = incident.affected_users
    targeted = incident.targeted_users

    host_text = (
        "one system" if len(hosts) == 1
        else f"{len(hosts)} systems" if hosts else "no identified system"
    )
    account_text = (
        "one account" if len(users) == 1
        else f"{len(users)} accounts" if users else "no account"
    )
    stages = [stage["tactic"].lower() for stage in (incident.attack_chain or [])]
    stage_text = ""
    if stages:
        stage_text = (
            " The activity progressed through "
            + ", ".join(stages[:-1])
            + (f" and then {stages[-1]}" if len(stages) > 1 else stages[0])
            + "."
        )

    origin = ""
    external = [ip for ip in incident.source_ips if is_external(ip)]
    if external:
        origin = f" The activity originated from {external[0]}, an address outside the organisation's network."

    targeted_text = ""
    if targeted:
        targeted_text = (
            f" A further {len(targeted)} account(s) were targeted without success and do not "
            "appear to have been compromised."
        )

    confidence_text = (
        "The evidence is strong and mutually corroborating." if incident.confidence >= 0.8
        else "The evidence is consistent but would benefit from further corroboration."
        if incident.confidence >= 0.6
        else "The evidence is limited and this assessment should be treated as provisional."
    )

    return (
        f"Between {iso(incident.first_seen)} and {iso(incident.last_seen)}, security monitoring "
        f"detected a sequence of related suspicious activity affecting {host_text} and "
        f"{account_text}, lasting {_fmt_duration(incident.duration_seconds)}.{stage_text}{origin}"
        f"{targeted_text} "
        f"The platform assessed this as a {incident.severity.upper()} incident with a risk score of "
        f"{incident.risk_score:.0f} out of 100, correlating {incident.alert_count} separate detections "
        f"across {incident.event_count} security events. {confidence_text} "
        f"The incident is currently {incident.status.replace('_', ' ')}."
    )


def build_report_sections(
    db: Session,
    incident: Incident,
    *,
    ai_summary: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    timeline = build_incident_timeline(db, incident)
    alerts = sorted(incident.alerts, key=lambda a: a.detected_at)
    actions = list(
        db.execute(
            select(ResponseAction).where(ResponseAction.incident_pk == incident.id)
            .order_by(ResponseAction.created_at.asc())
        ).scalars().all()
    )
    hosts = (
        db.execute(select(Host).where(Host.host_id.in_(incident.affected_hosts))).scalars().all()
        if incident.affected_hosts else []
    )
    users = (
        db.execute(select(User).where(User.user_id.in_(incident.affected_users))).scalars().all()
        if incident.affected_users else []
    )
    rule_ids = sorted({a.rule_id for a in alerts})
    rules = (
        db.execute(select(DetectionRule).where(DetectionRule.rule_id.in_(rule_ids))).scalars().all()
        if rule_ids else []
    )

    sections: list[dict[str, str]] = []

    # ---------------------------------------------------- executive summary
    if ai_summary:
        body = ai_summary.get("summary", "")
        if ai_summary.get("business_impact"):
            body += f"\n\n**Operational impact.** {ai_summary['business_impact']}"
        if ai_summary.get("key_points"):
            body += "\n\n" + "\n".join(f"- {p}" for p in ai_summary["key_points"])
        body += (
            "\n\n> _This summary was drafted by the AI investigation assistant from the evidence "
            "recorded below, and validated against that evidence before inclusion. The factual "
            "content of every other section is generated directly from stored records._"
        )
    else:
        body = deterministic_executive_summary(incident)
    sections.append({"title": "Executive Summary", "body": body})

    # ------------------------------------------------------------ overview
    overview = _table(
        ["Field", "Value"],
        [
            ["Incident ID", incident.incident_id],
            ["Title", incident.title],
            ["Status", incident.status.replace("_", " ").title()],
            ["Severity", incident.severity.upper()],
            ["Risk score", f"{incident.risk_score:.1f} / 100"],
            ["Correlation confidence", f"{incident.confidence:.0%}"],
            ["First observed", iso(incident.first_seen)],
            ["Last observed", iso(incident.last_seen)],
            ["Duration", _fmt_duration(incident.duration_seconds)],
            ["Detections correlated", incident.alert_count],
            ["Security events", incident.event_count],
            ["Assigned to", incident.assigned_to or "Unassigned"],
            ["Time to first containment",
             _fmt_duration(incident.mttr_seconds) if incident.mttr_seconds is not None
             else "No containment action recorded"],
            ["Contains simulated data", "Yes" if incident.is_demo else "No"],
        ],
    )
    reason = incident.correlation_reason or {}
    overview += (
        f"\n### Why these detections were correlated into one incident\n\n"
        f"Method: {reason.get('method', 'shared-entity temporal correlation')}, "
        f"window {reason.get('window_seconds', 1800)} seconds.\n\n"
    )
    linking = reason.get("linking_entities", [])
    if linking:
        overview += _table(
            ["Shared entity", "Appears in N detections"],
            [[e["entity"], e["alert_count"]] for e in linking[:8]],
        )
    by_type = reason.get("events_by_type", {})
    if by_type:
        overview += "\nEvidence composition: " + ", ".join(
            f"{count} {name.replace('_', ' ')} event(s)" for name, count in by_type.items()
        ) + ".\n"
    sections.append({"title": "Incident Overview", "body": overview})

    # ------------------------------------------------------ severity / risk
    risk_body = (
        "The risk score is a weighted sum of six components, each bounded to the range 0-1 and "
        "scaled to 100. The full formula is documented in `docs/detection-engine.md`.\n\n"
        + _table(
            ["Component", "Weight", "Value", "Contribution", "Basis"],
            [
                [c["factor"], f"{c['weight']:.2f}", f"{c['value']:.2f}",
                 f"{c['contribution']:.1f}", c["explanation"]]
                for c in (incident.risk_breakdown or [])
            ],
        )
        + f"\n**Total: {incident.risk_score:.1f} / 100 -> {incident.severity.upper()}**\n\n"
        + "### Correlation confidence\n\n"
        + "Confidence measures how certain the platform is that these detections describe a single "
        + "attack, and is deliberately separate from risk.\n\n"
        + _table(
            ["Component", "Weight", "Value", "Basis"],
            [
                [c["factor"], f"{c['weight']:.2f}", f"{c['value']:.2f}", c["explanation"]]
                for c in (incident.confidence_breakdown or [])
            ],
        )
        + f"\n**Attack chain confidence: {incident.confidence:.0%}**\n"
    )
    sections.append({"title": "Severity and Risk Assessment", "body": risk_body})

    # ------------------------------------------------------------ timeline
    chain = incident.attack_chain or []
    timeline_body = ""
    if chain:
        timeline_body += "### Attack progression\n\n" + _table(
            ["First detected", "Tactic", "Techniques", "Confidence"],
            [
                [
                    stage["detected_at"],
                    f"{stage['tactic']} ({stage['tactic_id']})",
                    ", ".join(t["technique_id"] for t in stage["techniques"]),
                    f"{stage['confidence']:.0%}",
                ]
                for stage in chain
            ],
        )
    timeline_body += "\n### Event timeline\n\n" + _table(
        ["Time", "Type", "Host", "Account", "Summary"],
        [
            [entry["timestamp"], entry["event_type"], entry["host"] or "-",
             entry["user"] or "-", entry["summary"]]
            for entry in timeline[:120]
        ],
    )
    if len(timeline) > 120:
        timeline_body += f"\n_{len(timeline) - 120} further events omitted; see the platform for the full record._\n"
    sections.append({"title": "Attack Timeline", "body": timeline_body})

    # -------------------------------------------------------------- assets
    sections.append({
        "title": "Affected Assets",
        "body": _table(
            ["Host", "Hostname", "OS", "Criticality", "Environment", "Containment state"],
            [
                [h.host_id, h.hostname, f"{h.os_family} {h.os_version or ''}".strip(),
                 f"{h.criticality}/5", h.environment,
                 "Isolated (simulated)" if h.is_isolated else "Active"]
                for h in sorted(hosts, key=lambda h: h.criticality, reverse=True)
            ],
        ),
    })

    # ------------------------------------------------------------ accounts
    accounts_body = "### Accounts with successful activity\n\n" + _table(
        ["Account", "Name", "Type", "Privileged", "State"],
        [
            [u.user_id, u.display_name or "-", u.user_type,
             "Yes" if u.is_privileged else "No",
             "Disabled (simulated)" if u.is_disabled else "Active"]
            for u in users
        ],
    )
    if incident.targeted_users:
        accounts_body += (
            "\n### Accounts targeted without success\n\n"
            "These accounts appear only on failed authentication attempts. They were attacked but "
            "show no evidence of compromise, and are listed separately so that remediation is not "
            "applied indiscriminately.\n\n"
            + "\n".join(f"- `{u}`" for u in incident.targeted_users) + "\n"
        )
    sections.append({"title": "Accounts Involved", "body": accounts_body})

    # ----------------------------------------------------------- indicators
    ioc_body = _table(
        ["Indicator", "Type", "Matched field", "Feed confidence", "Source"],
        [
            [m["indicator"], m["ioc_type"], m["matched_field"],
             f"{m['confidence']:.0%}", m.get("source", "-")]
            for m in (incident.ioc_matches or [])
        ],
    )
    observed = "\n### Network addresses observed\n\n"
    observed += "Source: " + (", ".join(f"`{ip}`" for ip in incident.source_ips) or "none recorded") + "\n\n"
    observed += "Destination: " + (", ".join(f"`{ip}`" for ip in incident.destination_ips) or "none recorded") + "\n"
    sections.append({"title": "Indicators of Compromise", "body": ioc_body + observed})

    # ---------------------------------------------------------------- mitre
    mitre_body = _table(
        ["Technique", "Name", "Tactic", "Confidence", "Evidence", "Detected by"],
        [
            [
                t.technique_id,
                catalog.technique_name(t.technique_id),
                catalog.tactic_names().get(t.tactic_id or "", t.tactic_id or "-"),
                f"{t.confidence:.0%}",
                f"{len(t.evidence_event_ids)} event(s)",
                ", ".join(t.source_rule_ids),
            ]
            for t in sorted(incident.techniques, key=lambda t: t.first_observed)
        ],
    )
    mitre_body += (
        "\nTechnique identifiers follow MITRE ATT&CK Enterprise. Every mapping above is derived "
        "from a detection rule's declared technique set and is backed by the listed evidence; no "
        "technique is inferred without a rule firing.\n"
    )
    sections.append({"title": "MITRE ATT&CK Mapping", "body": mitre_body})

    # ------------------------------------------------------------- evidence
    evidence_body = "### Detections\n\n" + _table(
        ["Alert", "Detected", "Rule", "Severity", "Confidence", "Detection latency", "Title"],
        [
            [a.alert_id, iso(a.detected_at), a.rule_id, a.severity.upper(),
             f"{a.confidence:.0%}", f"{a.detection_latency_ms / 1000:.1f}s", a.title]
            for a in alerts
        ],
    )
    evidence_body += "\n### Why each detection fired\n\n"
    for alert in alerts:
        evidence_body += f"**{alert.alert_id} - {alert.rule_id}**\n\n"
        for line in (alert.explanation or [])[:6]:
            evidence_body += f"- {line}\n"
        evidence_body += "\n"
    sections.append({"title": "Evidence", "body": evidence_body})

    # ------------------------------------------------- root cause hypothesis
    sections.append({"title": "Root Cause Hypothesis", "body": _root_cause(incident, timeline)})

    # ------------------------------------------------------- detection logic
    detection_body = _table(
        ["Rule", "Type", "Severity", "Techniques", "Description"],
        [
            [r.rule_id, r.rule_type, r.severity.upper(),
             ", ".join(r.mitre_techniques or []), (r.description or "").strip().replace("\n", " ")[:200]]
            for r in sorted(rules, key=lambda r: r.rule_id)
        ],
    )
    detection_body += (
        "\nAll detections are deterministic: rule-based, threshold-based, sequence-based, "
        "indicator matching, or statistical baselining. No machine-learning model and no language "
        "model participated in producing any detection in this incident.\n"
    )
    known_fps = [(r.rule_id, fp) for r in rules for fp in (r.false_positives or [])]
    if known_fps:
        detection_body += "\n### Documented false-positive conditions for the rules that fired\n\n"
        detection_body += _table(["Rule", "Known benign cause"], [list(fp) for fp in known_fps])
    sections.append({"title": "Detection Logic", "body": detection_body})

    # ------------------------------------------------------ response actions
    response_body = _table(
        ["Time", "Action", "Target", "Status", "Simulated", "Requested by"],
        [
            [iso(a.created_at), a.action_type, a.target, a.status,
             "Yes" if a.is_simulated else "No", a.requested_by]
            for a in actions
        ],
    )
    response_body += (
        "\n> **All containment actions in this deployment are simulated.** SENTINEL-X records that an "
        "action was rehearsed and updates its own state accordingly. No host was isolated, no account "
        "was disabled, and no network control was modified on any real system. Evidence collection is "
        "the exception and is genuinely performed.\n"
    )
    sections.append({"title": "Response Actions", "body": response_body})

    # ------------------------------------------------------- recommendations
    sections.append({"title": "Recommendations", "body": _recommendations(db, incident)})

    # ------------------------------------------------------------- notes
    notes = incident.notes
    notes_body = _table(
        ["Time", "Analyst", "Note"],
        [[iso(n.created_at), n.author, n.body] for n in sorted(notes, key=lambda n: n.created_at)],
    )
    sections.append({"title": "Analyst Notes", "body": notes_body})

    # ------------------------------------------------------- methodology
    sections.append({"title": "Methodology and Limitations", "body": _methodology(incident)})

    return sections


def _root_cause(incident: Incident, timeline: list[dict[str, Any]]) -> str:
    """A hypothesis derived from the earliest evidence, labelled as one.

    Root cause is an inference, and the report says so rather than presenting it
    with the same authority as the timeline.
    """
    if not timeline:
        return "_Insufficient evidence to form a root cause hypothesis._\n"

    first = timeline[0]
    chain = incident.attack_chain or []
    initial_tactic = chain[0]["tactic"] if chain else "unclassified activity"

    entry_hypothesis = "The initial access vector could not be determined from the available telemetry."
    techniques = set(incident.technique_ids or [])
    if {"T1110", "T1110.001", "T1110.003"} & techniques:
        entry_hypothesis = (
            "The most probable entry vector is credential guessing against an internet-reachable "
            "authentication service. The telemetry shows repeated failed authentication from a single "
            "external source followed by a success, which is the signature of a successful brute-force "
            "attack rather than a legitimate session."
        )
    elif {"T1078", "T1078.004"} & techniques:
        entry_hypothesis = (
            "The most probable entry vector is the use of credentials obtained elsewhere. The telemetry "
            "shows successful authentication with no preceding failures, which indicates the actor already "
            "held a working credential. The source of that credential is outside the visibility of this "
            "deployment."
        )

    contributing = []
    if any("uid_zero" in str(entry.get("highlights", {})) for entry in timeline):
        contributing.append("A second UID 0 account was created, indicating the actor obtained root.")
    if {"T1098", "T1098.004"} & techniques:
        contributing.append(
            "Account or key material was modified, providing access that survives a password reset."
        )
    if {"T1562", "T1562.008"} & techniques:
        contributing.append(
            "Audit logging was disabled, so activity after that point may not be represented here."
        )
    if incident.mttr_seconds is None:
        contributing.append("No containment action has been recorded for this incident.")

    body = (
        f"> **This section is an inference, not an observation.** Everything above is derived directly "
        f"from telemetry; the following is the analyst-facing hypothesis that best fits it.\n\n"
        f"The earliest recorded evidence is {first['event_id']} at {first['timestamp']}: "
        f"{first['summary']}. This falls under {initial_tactic}.\n\n"
        f"{entry_hypothesis}\n"
    )
    if contributing:
        body += "\n**Contributing factors observed in the evidence:**\n\n"
        body += "\n".join(f"- {factor}" for factor in contributing) + "\n"
    body += (
        f"\n**Confidence in this hypothesis: {incident.confidence:.0%}**, inherited from the "
        "correlation confidence. Where the hypothesis and the evidence disagree, the evidence is "
        "authoritative.\n"
    )
    return body


def _recommendations(db: Session, incident: Incident) -> str:
    from app.response.service import recommended_actions

    proposals = recommended_actions(db, incident)
    body = "### Immediate\n\n"
    if proposals:
        body += _table(
            ["Priority", "Action", "Target", "Rationale"],
            [[p["priority"].upper(), p["action_type"], p["target"], p["rationale"]] for p in proposals],
        )
    else:
        body += "_All proposed containment actions have already been taken._\n"

    playbooks = incident_playbooks(incident)
    if playbooks:
        primary = playbooks[0]
        body += f"\n### Follow the {primary['name']} playbook\n\n"
        for step in primary["steps"]:
            body += f"{step['order']}. **{step['title']}** ({step['phase']}) - {step['detail']}\n"

    body += (
        "\n### Longer term\n\n"
        "- Review whether the detections in this incident fired as early as they could have; "
        "the detection latency column in the Evidence section shows how far into the attack each "
        "rule triggered.\n"
        "- Confirm the asset criticality values used in the risk score reflect the current estate. "
        "Risk scoring is only as good as the inventory behind it.\n"
        "- Add any benign cause identified during triage to the relevant rule's documented "
        "false-positive conditions, so the next analyst does not repeat the work.\n"
    )
    return body


def _methodology(incident: Incident) -> str:
    return (
        "### How this incident was produced\n\n"
        "1. Telemetry was normalized into a single schema at ingestion.\n"
        "2. A deterministic detection engine evaluated version-controlled rules against it.\n"
        "3. Alerts sharing an entity within the correlation window were grouped into this incident.\n"
        "4. ATT&CK techniques were taken from the rules that fired, each backed by named evidence.\n"
        "5. Risk and confidence were computed from documented formulas; both breakdowns are above.\n\n"
        "### Limitations\n\n"
        "- **Simulated telemetry.** This deployment generates synthetic security events. It has not "
        "been validated against production telemetry, and real-world false-positive rates will differ.\n"
        "- **Simulated response.** Containment actions are recorded, not performed.\n"
        "- **Bounded visibility.** The platform can only reason about telemetry it received. Absence "
        "of evidence for a stage does not establish that the stage did not occur.\n"
        "- **Correlation is a heuristic.** Shared-entity temporal correlation can merge concurrent "
        "unrelated activity on a busy host, or split one campaign that shares no entity across stages. "
        f"Confidence for this incident is {incident.confidence:.0%}, and the breakdown above shows why.\n"
        "- **Baselines need history.** Behavioural anomaly detection is silent for accounts with "
        "insufficient observed history, by design.\n"
        + ("- **Demo data.** This incident includes data generated by the attack simulator and is "
           "labelled as simulated throughout the platform.\n" if incident.is_demo else "")
    )


def render_markdown(incident: Incident, sections: list[dict[str, str]], *, generated_by: str) -> str:
    header = (
        f"# Incident Report {incident.incident_id}\n\n"
        f"**{incident.title}**\n\n"
        f"| | |\n|---|---|\n"
        f"| Severity | {incident.severity.upper()} |\n"
        f"| Risk score | {incident.risk_score:.1f} / 100 |\n"
        f"| Status | {incident.status.replace('_', ' ').title()} |\n"
        f"| Generated | {iso(utcnow())} |\n"
        f"| Generated by | {generated_by} |\n"
        f"| Platform | SENTINEL-X |\n\n"
    )
    if incident.is_demo:
        header += (
            "> **DEMO DATA.** This incident was produced by the SENTINEL-X attack simulator. "
            "It describes synthetic activity against a synthetic estate and does not represent "
            "a real security incident.\n\n"
        )
    header += "---\n\n"

    body = "\n\n---\n\n".join(
        f"## {section['title']}\n\n{section['body']}" for section in sections
    )
    return header + body + "\n"


def generate_report(
    db: Session,
    incident: Incident,
    *,
    generated_by: str = "analyst",
    ai_summary: dict[str, Any] | None = None,
) -> Report:
    sections = build_report_sections(db, incident, ai_summary=ai_summary)
    markdown = render_markdown(incident, sections, generated_by=generated_by)

    report = Report(
        report_id=new_report_id(),
        incident_pk=incident.id,
        created_at=utcnow(),
        generated_by=generated_by,
        title=f"Incident Report {incident.incident_id} - {incident.title}"[:255],
        content=markdown,
        sections=[s["title"] for s in sections],
        ai_assisted=ai_summary is not None,
    )
    db.add(report)
    db.flush()
    return report
