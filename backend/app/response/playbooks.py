"""Incident response playbooks.

A playbook here is a *checklist with provenance*, not an automation script.  Each
step says what to do, why, and — where SENTINEL-X can answer the question itself —
which view or action provides the answer.

Deliberately investigation-heavy.  The steps that matter in a real response are
the ones that establish scope before anything is contained: isolating the wrong
host is disruptive, and isolating the right host before you know where else the
actor is simply tells them you noticed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.models.enums import ResponseActionType


@dataclass(frozen=True, slots=True)
class PlaybookStep:
    order: int
    title: str
    detail: str
    #: investigate | contain | eradicate | recover | report
    phase: str
    #: A response action this step suggests, if any.
    suggested_action: str | None = None
    #: Where in SENTINEL-X the analyst answers this step.
    reference: str | None = None


@dataclass(frozen=True, slots=True)
class Playbook:
    playbook_id: str
    name: str
    description: str
    #: Rule IDs and ATT&CK techniques that make this playbook relevant.
    trigger_rule_ids: tuple[str, ...]
    trigger_techniques: tuple[str, ...]
    steps: tuple[PlaybookStep, ...]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "playbook_id": self.playbook_id,
            "name": self.name,
            "description": self.description,
            "trigger_rule_ids": list(self.trigger_rule_ids),
            "trigger_techniques": list(self.trigger_techniques),
            "steps": [
                {
                    "order": s.order,
                    "title": s.title,
                    "detail": s.detail,
                    "phase": s.phase,
                    "suggested_action": s.suggested_action,
                    "reference": s.reference,
                }
                for s in self.steps
            ],
        }


BRUTE_FORCE = Playbook(
    playbook_id="PB-BRUTE-FORCE",
    name="Brute Force / Credential Guessing",
    description=(
        "For authentication attacks. The decisive question is whether any attempt "
        "succeeded - everything after that branches on the answer."
    ),
    trigger_rule_ids=("BRUTE_FORCE_001", "BRUTE_FORCE_002", "BRUTE_FORCE_003"),
    trigger_techniques=("T1110", "T1110.001", "T1110.003", "T1078"),
    steps=(
        PlaybookStep(1, "Establish whether authentication succeeded", phase="investigate",
                     detail="Filter the incident's events to authentication with status=success from the "
                            "same source address. If none exist this is an attempt, not a compromise, and "
                            "the response is perimeter-side. If one exists, treat the account as owned.",
                     reference="Incident > Timeline, filtered to authentication events"),
        PlaybookStep(2, "Validate the source address", phase="investigate",
                     detail="Check whether the address appears in the indicator store, whether it has "
                            "reached other hosts, and whether it is in any account's baseline. A source "
                            "already in a user's baseline suggests a misconfigured client rather than an attack.",
                     reference="IOCs page; Hunt: authentication by source_ip"),
        PlaybookStep(3, "Enumerate every account targeted", phase="investigate",
                     detail="Distinguish accounts that were merely attempted from accounts that were used. "
                            "The incident separates these; only the latter need credential resets.",
                     reference="Incident > Overview > affected vs targeted accounts"),
        PlaybookStep(4, "Review activity after the successful authentication", phase="investigate",
                     detail="Everything the session did after login is in scope: enumeration, privilege "
                            "changes, file writes, outbound connections. This is what determines whether "
                            "the incident stops here.",
                     reference="Incident > Timeline from the success event onward"),
        PlaybookStep(5, "Check for lateral movement from the compromised host", phase="investigate",
                     detail="Hunt for the same account authenticating to other hosts within the window.",
                     reference="Hunt: 'Account authenticated to unusually many hosts'"),
        PlaybookStep(6, "Block the source address", phase="contain",
                     detail="Only after scope is established - blocking early tells the actor they were seen.",
                     suggested_action=ResponseActionType.BLOCK_IOC,
                     reference="Response > Block indicator"),
        PlaybookStep(7, "Reset credentials for accounts that authenticated", phase="eradicate",
                     detail="Password, keys and active sessions. A password reset alone leaves SSH keys "
                            "and API tokens working.",
                     suggested_action=ResponseActionType.RESET_CREDENTIALS,
                     reference="Response > Force credential reset"),
        PlaybookStep(8, "Preserve evidence and report", phase="report",
                     detail="Collect the evidence package before state changes further, then generate the "
                            "incident report.",
                     suggested_action=ResponseActionType.COLLECT_EVIDENCE,
                     reference="Response > Collect evidence; Report tab"),
    ),
)

PRIVILEGE_ESCALATION = Playbook(
    playbook_id="PB-PRIVESC",
    name="Privilege Escalation",
    description=(
        "For escalation to root or administrator. Assume the host is fully "
        "controlled and work outward from there."
    ),
    trigger_rule_ids=("PRIVESC_SUID_ENUM_001", "PRIVESC_SUDO_CHAIN_001",
                      "PRIVESC_GROUP_CHANGE_001", "PRIVESC_WINDOWS_SPECIAL_PRIV_001"),
    trigger_techniques=("T1548", "T1548.001", "T1548.003", "T1068", "T1134", "T1098"),
    steps=(
        PlaybookStep(1, "Identify the host and the account that escalated", phase="investigate",
                     detail="Establish which account elevated, from what starting privilege, and by what "
                            "mechanism (sudo, setuid, group membership, token).",
                     reference="Incident > Overview; Attack graph 'escalated on' edges"),
        PlaybookStep(2, "Reconstruct the process chain", phase="investigate",
                     detail="Walk parent-child relationships around the escalation. A shell spawned by a "
                            "web service is a very different finding from one spawned by a login session.",
                     reference="Incident > Evidence, process events"),
        PlaybookStep(3, "Determine how access was obtained in the first place", phase="investigate",
                     detail="Escalation is never the first step. Look earlier in the timeline for the "
                            "initial access - if it is not present, telemetry is missing and that is itself "
                            "a finding.",
                     reference="Incident > Timeline, earliest events"),
        PlaybookStep(4, "Search for persistence established with the new privilege", phase="investigate",
                     detail="Root access is usually spent immediately on keeping it. Check cron, systemd, "
                            "authorized_keys, new accounts and group changes on this host.",
                     reference="Hunt: 'Persistence mechanisms created'"),
        PlaybookStep(5, "Check for credential material accessed after escalation", phase="investigate",
                     detail="Root can read every credential on the host. Anything readable should be "
                            "considered compromised regardless of whether a read was observed.",
                     reference="Hunt: credential file access on this host"),
        PlaybookStep(6, "Isolate the host", phase="contain",
                     detail="With root compromised, host-level containment is the only reliable boundary.",
                     suggested_action=ResponseActionType.ISOLATE_HOST,
                     reference="Response > Isolate host"),
        PlaybookStep(7, "Disable the involved account pending investigation", phase="contain",
                     detail="Applies to the account that escalated and to any account created during the incident.",
                     suggested_action=ResponseActionType.DISABLE_ACCOUNT,
                     reference="Response > Disable account"),
        PlaybookStep(8, "Plan rebuild rather than cleanup", phase="recover",
                     detail="A host where an actor held root cannot be returned to service by removing the "
                            "artefacts that were found. Rebuild from known-good media and rotate every "
                            "credential the host held.",
                     reference="Report > Recommendations"),
    ),
)

PERSISTENCE = Playbook(
    playbook_id="PB-PERSISTENCE",
    name="Persistence Removal",
    description=(
        "For established footholds. The failure mode to avoid is removing one "
        "mechanism and declaring the host clean."
    ),
    trigger_rule_ids=("PERSISTENCE_SCHEDULED_TASK_001", "PERSISTENCE_BACKDOOR_ACCOUNT_001",
                      "PERSISTENCE_SERVICE_INSTALL_001"),
    trigger_techniques=("T1053", "T1053.003", "T1543", "T1543.002", "T1136", "T1136.001", "T1098.004"),
    steps=(
        PlaybookStep(1, "Inventory every mechanism in the incident", phase="investigate",
                     detail="Each persistence alert is a separate foothold. Enumerate all of them before "
                            "removing any - removal is observable, and a partial removal leaves the actor "
                            "warned and still present.",
                     reference="Incident > Alerts filtered to persistence rules"),
        PlaybookStep(2, "Establish who created each mechanism and when", phase="investigate",
                     detail="Attribute each artefact to an account and a session. Mechanisms created by "
                            "different accounts suggest either multiple actors or successful escalation.",
                     reference="Incident > Evidence, file and account events"),
        PlaybookStep(3, "Search the estate for the same mechanism", phase="investigate",
                     detail="Persistence deployed by tooling is deployed identically everywhere. Hunt the "
                            "same paths and account names across all hosts.",
                     reference="Hunt: 'Persistence mechanisms created', unfiltered by host"),
        PlaybookStep(4, "Identify backdoor accounts", phase="investigate",
                     detail="Check for accounts created during the incident window, UID 0 accounts, and "
                            "additions to privileged groups.",
                     reference="Hunt: account events in the incident window"),
        PlaybookStep(5, "Isolate before removal", phase="contain",
                     detail="Remove footholds with the host off the network so the actor cannot re-establish "
                            "them while you work.",
                     suggested_action=ResponseActionType.ISOLATE_HOST,
                     reference="Response > Isolate host"),
        PlaybookStep(6, "Disable backdoor accounts", phase="eradicate",
                     detail="Disable rather than delete, so the account remains available as evidence.",
                     suggested_action=ResponseActionType.DISABLE_ACCOUNT,
                     reference="Response > Disable account"),
        PlaybookStep(7, "Preserve evidence before remediation", phase="report",
                     detail="Capture the artefacts and their metadata before anything is removed.",
                     suggested_action=ResponseActionType.COLLECT_EVIDENCE,
                     reference="Response > Collect evidence"),
    ),
)

LATERAL_MOVEMENT = Playbook(
    playbook_id="PB-LATERAL",
    name="Lateral Movement",
    description=(
        "For an actor moving between hosts. Scope determination comes first: "
        "containing the hosts you know about while missing one achieves nothing."
    ),
    trigger_rule_ids=("LATERAL_MOVEMENT_001", "LATERAL_BREADTH_001", "LATERAL_TOOL_TRANSFER_001"),
    trigger_techniques=("T1021", "T1021.004", "T1570", "T1105", "T1078"),
    steps=(
        PlaybookStep(1, "Map every host the account touched", phase="investigate",
                     detail="Build the full set before containing anything. The attack graph shows the "
                            "movement path; the breadth hunt catches hosts with no network telemetry.",
                     reference="Incident > Attack graph; Hunt: authentication breadth by account"),
        PlaybookStep(2, "Identify the credential that enabled movement", phase="investigate",
                     detail="Movement without further authentication failures means the actor holds a valid "
                            "credential - find where they obtained it.",
                     reference="Incident > Timeline, credential access events"),
        PlaybookStep(3, "Check each reached host for follow-on activity", phase="investigate",
                     detail="Discovery, tool staging, escalation and persistence on each host. A host that "
                            "was only authenticated to is lower priority than one where tooling was staged.",
                     reference="Hosts page, per-host timeline"),
        PlaybookStep(4, "Assess the highest-criticality host reached", phase="investigate",
                     detail="Rank by asset criticality, not by order of access. The database host reached "
                            "last matters more than the staging host reached first.",
                     reference="Incident > Overview > affected assets"),
        PlaybookStep(5, "Disable the account used for movement", phase="contain",
                     detail="This is the single control that stops movement everywhere at once, and it is "
                            "usually preferable to isolating hosts one at a time.",
                     suggested_action=ResponseActionType.DISABLE_ACCOUNT,
                     reference="Response > Disable account"),
        PlaybookStep(6, "Isolate hosts where tooling was staged", phase="contain",
                     detail="Hosts with transferred tools or established persistence, in criticality order.",
                     suggested_action=ResponseActionType.ISOLATE_HOST,
                     reference="Response > Isolate host"),
        PlaybookStep(7, "Rotate credentials held by every reached host", phase="eradicate",
                     detail="Service accounts, SSH keys and tokens present on any reached host must be "
                            "considered compromised.",
                     suggested_action=ResponseActionType.RESET_CREDENTIALS,
                     reference="Response > Force credential reset"),
    ),
)

CLOUD_IAM = Playbook(
    playbook_id="PB-CLOUD-IAM",
    name="Cloud Identity Compromise",
    description=(
        "For abuse of a cloud identity. Credentials an actor created themselves "
        "survive a password reset, which is what makes this class distinctive."
    ),
    trigger_rule_ids=("CLOUD_IAM_PRIVESC_001", "CLOUD_IAM_KEY_CHAIN_001",
                      "CLOUD_LOG_TAMPERING_001", "CLOUD_DISCOVERY_001", "CLOUD_IAM_ANOMALY_001"),
    trigger_techniques=("T1078.004", "T1098", "T1098.001", "T1098.003", "T1562", "T1562.008", "T1526"),
    steps=(
        PlaybookStep(1, "Confirm audit logging is still enabled", phase="investigate",
                     detail="Do this first. If logging was disabled, everything after that moment is "
                            "invisible and the investigation window is bounded by it.",
                     reference="Cloud > Recent IAM changes, defense_evasion category"),
        PlaybookStep(2, "Enumerate every permission change the identity made", phase="investigate",
                     detail="Policy attachments, role assumptions, trust policy edits and group additions - "
                            "on the identity itself and on any identity it modified.",
                     reference="Cloud > IAM changes filtered to this identity"),
        PlaybookStep(3, "Find credentials the identity created", phase="investigate",
                     detail="Access keys, login profiles and service-account keys created during the "
                            "incident. These are the persistence mechanism and they outlive a password reset.",
                     reference="Hunt: metadata.iam_category = credential_creation"),
        PlaybookStep(4, "Determine what data was reached", phase="investigate",
                     detail="Storage reads, database access and secret retrieval performed with the "
                            "escalated permissions.",
                     reference="Cloud > identity activity graph"),
        PlaybookStep(5, "Check for changes to network exposure", phase="investigate",
                     detail="Security group rules, bucket policies and public access settings modified "
                            "during the window.",
                     reference="Cloud > IAM changes, resource_exposure and network_exposure categories"),
        PlaybookStep(6, "Revoke sessions and deactivate created credentials", phase="contain",
                     detail="Session revocation and key deactivation together - either alone leaves a path.",
                     suggested_action=ResponseActionType.REVOKE_CLOUD_SESSION,
                     reference="Response > Revoke cloud sessions"),
        PlaybookStep(7, "Remove the granted permissions", phase="eradicate",
                     detail="Detach policies added during the incident and revert trust policy changes. "
                            "Verify against the pre-incident permission set rather than by inspection.",
                     reference="Cloud > IAM changes"),
        PlaybookStep(8, "Re-enable and verify audit logging", phase="recover",
                     detail="Confirm the trail is recording again and note the blind window in the report.",
                     reference="Report > Timeline"),
    ),
)

PLAYBOOKS: dict[str, Playbook] = {
    p.playbook_id: p
    for p in (BRUTE_FORCE, PRIVILEGE_ESCALATION, PERSISTENCE, LATERAL_MOVEMENT, CLOUD_IAM)
}


def match_playbooks(rule_ids: list[str], technique_ids: list[str]) -> list[Playbook]:
    """Rank playbooks by how strongly they match an incident's detections.

    Rule matches weigh more than technique matches: a rule firing is direct
    evidence of the behaviour, while a technique may be shared across very
    different attacks.
    """
    rules = {r.upper() for r in rule_ids}
    techniques = {t.upper() for t in technique_ids}

    scored: list[tuple[int, Playbook]] = []
    for playbook in PLAYBOOKS.values():
        score = 3 * len(rules & set(playbook.trigger_rule_ids))
        score += len(techniques & set(playbook.trigger_techniques))
        if score:
            scored.append((score, playbook))

    scored.sort(key=lambda item: item[0], reverse=True)
    return [playbook for _, playbook in scored]
