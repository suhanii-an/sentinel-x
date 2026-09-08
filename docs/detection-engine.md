# Detection engine

## A rule is a document, not code

Rules live in `detection-rules/` as YAML. The engine interprets them. There is
no `eval`, no dynamic import, and no path from rule content to executable
logic — an anomaly rule names a detector from a registry, never an import path.
This matters because a rule file is the thing most likely to be edited by
somebody who is not a Python developer.

```yaml
id: BRUTE_FORCE_001
name: Repeated Authentication Failures From Single Source
description: >
  A single source address produced repeated authentication failures against the
  estate within a short window.
type: threshold
severity: high
confidence: 0.80
category: brute-force

mitre:
  techniques: [T1110, T1110.001]
  tactics: [TA0006]

selection:
  event_type: authentication
  status: failure
  action: login

group_by: [source_ip]

threshold:
  count: 5
  window_seconds: 300

title_template: "Brute force: {source_ip} produced repeated authentication failures"
dedup_window_seconds: 900

false_positives:
  - "Misconfigured service accounts retrying with a stale password after a rotation."
  - "A user whose saved credential is out of date."
  - "Vulnerability scanners and authenticated monitoring probes."

tests:
  - name: five failures from one source in three minutes
    expect: match
    events: [...]
  - name: four failures stays under the threshold
    expect: no_match
    events: [...]
```

Every field except the tests is self-explanatory. The tests are the point.

---

## The five detectors

The type is not decoration — it decides what question the rule can ask.

### `match` — one event is enough

For observations that are sufficient on their own: an account created with UID
0, a CloudTrail `StopLogging` call, a file written to `/etc/cron.d`. No state,
no window.

### `threshold` — N of these, to one entity, inside a window

Brute force, spraying, scanning. `group_by` binds the count to an entity, which
is what makes "five failures" mean something: five failures against one account
is guessing; five against five accounts from one source is spraying, and
`distinct_field` / `distinct_count` separates them.

Two details that matter more than they look:

**The window is extended after the threshold is met.** Once five failures
satisfy the rule, every remaining event still inside the window is attached as
evidence. An analyst who opens an alert reporting eleven failures and finds five
events attached has been shown a truncated attack. This change alone raised
measured recall.

**Dedup keys bucket time.** A brute-force attempt that continues for an hour
produces a handful of alerts rather than one per event, without suppressing a
genuinely new occurrence tomorrow.

### `sequence` — these things, in this order, to one entity

The type that makes this a detection engine rather than a search box. "Failed
logins followed by a success from the same source" is a question about order,
and no amount of field filtering can express it.

Steps are matched greedily against an anchor, bound to an entity by `group_by`,
and bounded by `window_seconds`. `constraints` express cross-step requirements
the per-event condition language cannot: "the same account authenticated to at
least two different hosts" is exactly the shape of lateral movement, and without
it the rule matches a user logging into one machine three times.

Evidence expansion applies here too: all events belonging to a step are
attached, not only the minimum that satisfied `min_count`.

### `anomaly` — unusual *for this entity*, with reasons

**This is not machine learning, and the interface says so.** The baselines are
frequency tables: which addresses this account has authenticated from, which
hours it is active, which hosts it touches. The detector scores composite
factors, each with a weight and a sentence of explanation.

Three refinements the evaluation harness forced, each of which fixed a real
false positive:

**Range, not exact-hour membership.** An account seen 09:00–12:00 and 14:00–17:00
has never been observed at 13:00 because it takes lunch. Flagging 13:00 would
produce a daily false positive for every office worker in the estate. The
comparison is against the observed *range*, which still catches 02:13 against a
09:00–18:00 pattern.

**Minimum hour coverage.** An account seen at only two distinct hours has not
demonstrated a schedule, so "outside its hours" claims more than the data
supports. Below the coverage floor the factor stays silent.

**Always-on suppression.** An identity active across most of the day has no
meaningful off-hours, so the factor suppresses itself rather than inventing a
boundary.

And the single most important line in the module: **below `min_observations`,
the detector stays silent entirely.** Calling the first login of a new account
anomalous is not detection, it is a coin toss.

### `ioc` — does this touch a known-bad value

Matches indicators against configured fields. An indicator hit is
*corroboration*, not proof — the resulting alert inherits the indicator's own
confidence, and the Indicators page states the feed's provenance rather than
implying a live commercial feed.

---

## The condition language

A *selection* is a mapping of field → constraint. All entries must hold.
`any_of`, `all_of` and `not` compose.

```yaml
selection:
  event_type: process              # equality
  process: [mimikatz.exe, procdump.exe]   # a bare list means membership
  command_line:
    contains: "-enc"               # operator form
  destination_port:
    in: [22, 3389, 5985]
  any_of:
    - {status: failure}
    - {metadata.privileged: true}
```

Operators come from a fixed set: `eq`, `not_eq`, `in`, `not_in`, `contains`,
`not_contains`, `startswith`, `endswith`, `regex`, `not_regex`, `gt`, `gte`,
`lt`, `lte`, `exists`, `is_null`. An unrecognised operator raises rather than
being skipped — silently ignoring a typo turns it into a rule that matches
everything it is asked about.

**String comparison is case-insensitive by default.** Security telemetry is not
case-consistent: `ADMINISTRATOR`, `Administrator` and `administrator` are the
same principal, and a rule that misses because of casing is a detection gap, not
a nuance. `case_sensitive: true` opts out.

**`contains` on a list field is membership, not substring.** Without that
branch, `groups contains "admin"` matches a group called `admin-readonly` — a
false positive on a privilege rule, which is the worst place to have one.

**Regex subjects are length-capped** before matching, so a pathological pattern
cannot be handed an unbounded input. Patterns come from version-controlled rule
files, never from API input.

`metadata.*` reaches into normalizer enrichment. `raw.*` reaches the original
record.

---

## Validation at load time

Catching a typo when the rule file loads is the difference between a rule that
errors and a rule that silently matches nothing forever. Refused at load:

- unknown field names in a selection
- a `threshold` rule with no `threshold` block (and the same for each type)
- a `sequence` rule with fewer than two steps, no window, or no `group_by`
- duplicate sequence step names, or every step marked optional
- grouping on a free-text field such as `command_line` — that makes one group
  per event and silently disables the threshold
- a malformed technique or tactic identifier
- an anomaly rule naming a detector that is not in the registry

A rule that fails validation is not loaded in a degraded form. It is refused,
reported through `/detections/status`, and shown in the interface.

One broken rule never stops the pass: a detector that raises is logged loudly
and the remaining rules still run, because a single bad rule must not blind the
whole engine.

---

## Rules test themselves

Every rule carries positive **and** negative cases, run in-process with no
database:

```bash
curl localhost:8000/api/v1/detections/tests    # 50 cases
```

The Detections page runs them too. CI fails if any case fails **and** if any
rule has no negative case — a rule with only positive cases has never been
checked for noise, and noise is what makes analysts stop reading alerts.

---

## Writing a rule

1. Write the failing test first: a `no_match` case describing the benign
   activity that most resembles what you are detecting.
2. Add the `match` case.
3. Write the selection.
4. Fill in `false_positives` honestly. An analyst triaging at 3am needs to know
   what benign activity looks like from this rule's point of view.
5. Map to ATT&CK using IDs only. Never write a technique name into a rule file —
   names come from the catalogue.
6. Run `pytest tests/test_detection.py` and check the evaluation harness. If
   recall went up and precision went down, say so.

The rule that catches everything is not a good rule. The measured
false-positive pressure on the ambiguous class in `README.md` is what that
tradeoff looks like when it is reported honestly.
