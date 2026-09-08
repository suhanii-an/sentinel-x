# Incidents and response

## Correlation

An alert is a rule's opinion about some events. An incident is the claim that
several of those opinions describe **one adversary doing one thing**.

Getting that claim wrong is costly in both directions. Over-merge and two
intrusions become one ticket that hides half the story. Under-merge and the
analyst reconstructs the attack by hand across forty alerts.

The rule is deliberately simple and deliberately stated:

> Two alerts belong to the same incident when they **share at least one entity**
> (host, account, address or cloud account) **and** their activity windows fall
> within `CORRELATION_WINDOW_SECONDS` of one another.

Both halves are necessary. Entity overlap alone merges everything that ever
touches a busy jump host. Time proximity alone merges unrelated activity that
happens to coincide — two attacks at the same moment are two incidents, because
a shared clock is not evidence.

Clustering is transitive (union-find). Alert A links to B by account, B links to
C by host: all three are one incident even though A and C share nothing
directly. That is exactly what an attacker moving laterally looks like.

Every incident stores its `correlation_reason`, so the interface can show *why*
the alerts were joined rather than asserting it. A correlation an analyst cannot
audit is a correlation they cannot disagree with.

### Joining, merging, and not reopening

A new alert that matches an existing open incident joins it rather than opening
a second one. When a cluster matches several incidents they are merged, and the
**oldest wins** — analysts reference incident IDs, so the long-lived one keeps
its identity, and the merge is recorded in `correlation_reason.merged_from`.

A **resolved** incident is never silently reopened. Closing an incident is an
analyst's decision; new activity opens a new incident rather than quietly
amending a closed record.

### Derived state is rebuilt, not patched

`refresh_incident` recomputes every derived field from the incident's current
alerts. Idempotent and total. Incremental updates to correlated state are where
"the timeline shows six events but the header says nine" bugs come from.

One detail: an account seen only on **failures** was attacked, not compromised.
It appears in `targeted_users`, not `affected_users` — but it still contributes
an entity key, so a later event involving that account still correlates.

---

## Two scores

### Risk — how much this matters (0–100)

| Component | What it measures |
|---|---|
| Severity | The rule's declared severity |
| Confidence | How sure the detection is |
| Assets | Criticality of the hosts involved; whether a privileged account is in scope |
| Behavioural | Lateral movement, privilege escalation, data staging, anomaly score |
| Indicators | Known-bad corroboration, weighted by the indicator's own confidence |
| Correlation | Evidence volume, distinct tactics, contributing alerts |

Each component reports its weight, its value, its contribution and a sentence of
explanation, and the contributions sum to the score. A risk number an analyst
cannot take apart is a number they have to take on faith.

An asset with no inventory record does **not** score as maximum criticality.
Missing data is missing data, not a crown jewel.

### Confidence — is this one real attack (0–1)

Built from mean detection confidence, evidence volume, entity cohesion, temporal
cohesion, tactic breadth and indicator corroboration.

**Capped below 1.0.** A platform that reports total certainty in its own
inference is lying about what it can know.

The two are computed separately on purpose. A certain finding about something
trivial should not inherit a high risk score, and a high-impact guess should not
masquerade as a certainty.

---

## Response

Nine action types. **All simulated**, with one stated exception.

| Action | Target | Destructive | Would do in production |
|---|---|---|---|
| `isolate_host` | host | yes | Move the host to a quarantine VLAN / EDR containment |
| `release_host` | host | no | Restore normal network access |
| `disable_account` | user | yes | Disable the directory account |
| `enable_account` | user | no | Re-enable it |
| `reset_credentials` | user | yes | Force a password reset and revoke sessions |
| `revoke_cloud_session` | cloud identity | yes | Revoke active session tokens |
| `block_ioc` | indicator | yes | Push a block to the perimeter |
| `collect_evidence` | incident | no | **Genuinely performed** |
| `escalate_incident` | incident | no | Raise severity and notify |

A simulated action updates this platform's own state and records what it would
have done. Nothing reaches real infrastructure. `tests/test_security.py` asserts
this by grepping the response package for process and network primitives — the
guarantee is that the code cannot reach a real system, not that it promises not
to. A separate test asserts that every *destructive* action is simulated, so the
exception below can never widen.

**Evidence collection is real.** Snapshotting an incident's own evidence needs
nothing outside this database, so SENTINEL-X can do it correctly and completely.
Calling it simulated would be the dishonest choice. The catalogue marks it, the
API reports it, and the interface shows it.

Every execution is authorised (analyst role minimum), audited, and linked to the
incident it was taken on.

---

## Playbooks

A playbook is a suggested sequence, matched to an incident by its rule IDs and
techniques. Each step has a phase (identify, contain, eradicate, recover,
lessons), a detail, and optionally a suggested action from the catalogue.

Playbooks **suggest**. Nothing executes automatically. A platform that
auto-contains on a detection is a platform that takes production down on a false
positive, and the false-positive numbers in `README.md` are exactly why that is
not a hypothetical.

---

## Reporting

Fifteen fixed sections, in order: executive summary, incident overview, severity
and risk, attack timeline, affected assets, accounts involved, indicators,
ATT&CK mapping, evidence, root-cause hypothesis, detection logic, response
actions, recommendations, analyst notes, methodology and limitations.

Every figure is **read back from the stored record** rather than recomputed at
render time, so the report and the console can never disagree. A report that
contradicts the page it was generated from is worse than no report.

The executive summary can optionally be AI-drafted. The other fourteen sections
stay deterministic, the report records which summary it shipped with, and if the
drafted summary fails grounding validation the deterministic one is used
instead. A report whose summary was AI-drafted says so on its face.

Exports to Markdown and PDF. Every export is written to the audit trail.

The report viewer renders Markdown into React elements, never into HTML.
Reports contain attacker-controlled strings — command lines, usernames,
user-agents — and rendering those through `dangerouslySetInnerHTML` would turn
the viewer into a stored-XSS sink. That is the one class of bug a security tool
must not ship.
