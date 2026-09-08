# SENTINEL-X

A working miniature Security Operations Centre: attack simulation, telemetry
ingestion, deterministic detection, correlation into incidents, ATT&CK mapping,
threat hunting, grounded AI investigation, simulated response and reporting.

Every stage in that sentence is implemented and runs. The pipeline is:

```
attack simulation → telemetry → ingestion → normalization → detection →
alerts → correlation → incidents → MITRE ATT&CK → timeline → attack graph →
threat hunting → evidence → AI investigation → response → report
```

---

## The two rules this project is built around

**Detection is deterministic. AI is assistance.**
Detection, correlation, risk scoring, ATT&CK mapping, hunting and reporting all
run with no AI provider configured. The assistant explains results that were
already computed; it never decides them. Removing the API key removes
explanation, not detection.

**Nothing is faked.**
No hard-coded metrics, no invented technique IDs, no simulated screenshots of
features that do not exist. The numbers below were measured by a harness in this
repository against a labelled dataset in this repository, and you can reproduce
them with one command. Where something is simulated — every response action,
all demo telemetry — it is labelled as simulated in the database, in the API and
in the interface.

---

## Measured detection performance

Produced by `POST /api/v1/evaluation/run` (or the Evaluation page) against the
labelled dataset in `backend/app/evaluation/dataset.py`, seed `1337`,
14 days of benign history:

| Metric | Value |
|---|---|
| Precision | **0.973** |
| Recall | **0.900** |
| F1 | **0.935** |
| Accuracy | 0.995 |
| False-positive rate | 0.0012 |
| Scenarios detected | 8 / 8 |
| Median detection latency | 45.1 s (event time) |
| Dataset | 1,837 events — 1,731 benign, 80 malicious, 26 ambiguous |

Confusion matrix: 72 TP · 2 FP · 1,729 TN · 8 FN.

**How to read these.** The unit is one security event. A "positive" is an event
that is *trigger* evidence for at least one alert — alerts also carry context
events, and counting those as detections would credit a rule for every benign
event that happened to sit in the same window. The dataset is replayed in hourly
batches so stateful rules cannot see events that had not yet occurred; replaying
it in one pass would produce flattering recall. Each run executes in a temporary
database of its own.

**The ambiguous class is the interesting part.** 26 events are benign activity
that legitimately resembles an attack: an administrator enumerating a host, a
backup account sweeping the estate at 02:00, configuration management writing a
cron entry, a user mistyping a password four times. They are excluded from
precision and recall — scoring them either way would be a claim about ground
truth nobody can justify — and reported separately as false-positive pressure.
All 26 currently alert. That is a real and visible weakness of this rule set,
and it is on the Evaluation page rather than in a footnote.

Reproduce, exactly:

```bash
cd backend && python -c "
from app.evaluation.runner import evaluate
print(evaluate(seed=1337, benign_days=14, include_ambiguous=True)['metrics'])"
```

or, against a running instance (admin role required):

```bash
curl -X POST localhost:8000/api/v1/evaluation/run -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"seed": 1337, "benign_days": 14, "include_ambiguous": true}'
```

The seeded dataset is byte-for-byte reproducible, and a test asserts it. It was
not always: the per-scenario RNG was seeded with `hash(scenario_key)`, and
Python randomises string hashing per process, so the generated telemetry
differed between runs. The confusion matrix happened to be robust to that, but
the measured latency moved by tens of seconds — a metric quietly falsifying the
claim on this page. `test_the_dataset_is_byte_for_byte_reproducible` is there so
it cannot come back.

---

## Quick start

### Docker (full stack)

```bash
cp .env.example .env
# set SECRET_KEY:  python -c 'import secrets; print(secrets.token_urlsafe(48))'
# set POSTGRES_PASSWORD
docker compose up --build
```

Open <http://localhost:8080>. The API seeds a demo estate on first start and
prints the generated admin password once, in the `api` container logs. There is
no default password anywhere in this project.

### Local (SQLite, no services)

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt

export DATABASE_URL="sqlite+pysqlite:///./sentinelx.db"
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"

python ../scripts/seed_database.py --quick   # prints the admin password once
uvicorn app.main:app --reload
```

```bash
cd frontend && npm install && npm run dev    # http://localhost:5173
```

---

## What it actually does

### Attack simulation

Nine scenarios, each generating realistic multi-source telemetry with a
reproducible seed. `full_chain` runs an eight-stage intrusion end to end:
reconnaissance → brute force → valid-account use → discovery → privilege
escalation → persistence → lateral movement → cloud compromise.

Simulation writes log records to a database. It deploys nothing, exploits
nothing, touches no external system, and modifies no operating-system setting.
The test suite greps the simulator package for process execution, raw
sockets, SSH and every HTTP client in the dependency tree, and fails if it
finds one — the guarantee is that the code has no way to reach a real system,
not that it promises not to.

### Detection

22 rules in `detection-rules/`, expressed as YAML documents in a declarative
condition language with an operator allow-list. Five detector types:

| Type | Count | Answers |
|---|---|---|
| `match` | 10 | Is this single event sufficient on its own? |
| `threshold` | 5 | Did N of these happen to one entity within a window? |
| `sequence` | 4 | Did these things happen **in this order** to one entity? |
| `anomaly` | 2 | Is this unusual *for this account*, and why? |
| `ioc` | 1 | Does this touch a known-bad value? |

A rule is data, not code. There is no `eval`, no dynamic import, and no path
from rule content to executable logic — an anomaly rule names a detector from a
registry, never an import path.

Every rule ships positive **and** negative test cases: 50 cases, all passing,
runnable from the Detections page or from CI. A rule with no negative case is a
rule nobody has checked for false positives, and CI fails if one appears.

The anomaly detector is a set of inspectable frequency tables, not machine
learning, and says so. Each firing lists its contributing factors with a weight
and a sentence of explanation.

### Correlation

Two alerts belong to the same incident when they **share an entity** (host,
account, address or cloud account) **and** their activity windows fall within
the correlation window. Both halves are load-bearing: entity overlap alone
merges everything that touches a busy jump host; time proximity alone merges
unrelated activity that coincides. Clustering is transitive, so an attacker
moving laterally produces one incident rather than a chain of fragments.

Every incident stores *why* its alerts were joined.

### Scoring

Two separate numbers, because they answer different questions:

- **Risk (0–100)** — how much this matters: severity, detection confidence,
  asset criticality, behavioural flags, indicator corroboration, correlation
  breadth. Every component reports its weight, its value and a sentence of
  explanation, and the components sum to the score.
- **Confidence (0–1)** — how sure the platform is that this is one real attack.
  Capped below 1.0: a system that reports total certainty in its own inference
  is lying about what it can know.

### ATT&CK mapping

62 techniques across 14 tactics, from a locally generated catalogue
(`scripts/build_mitre_catalog.py`). The rule set covers 37 of them. Technique
*names* always come from the catalogue and are never written into a rule file,
and a technique ID that does not resolve locally is an error rather than a
guess. The coverage matrix shows uncovered techniques with the same weight as
covered ones — a coverage view that only lights up what you detect tells an
analyst nothing about where they are blind.

### Threat hunting

A validated query DSL over events, alerts and incidents, including sequence
hunts ("failed logins followed by a success from the same source", which no
amount of field filtering can express). The path is:

```
natural language → structured query document → validation → safe query builder → database
```

There is no path from user text to raw SQL. Field names are checked against a
per-dataset allow-list, operators against a fixed set, values travel as bound
parameters, and `LIKE` wildcards inside a value are escaped. The test suite runs nine
SQL-injection payloads at every position a caller controls: field names,
`order_by`, the dataset, sequence-step filters, correlation fields and metadata
keys.

### AI investigation (optional)

Provider-agnostic, off by default. When enabled it can explain an incident,
answer a question about it, propose next steps and draft a report's executive
summary. Four controls sit between the model and the analyst:

1. **Evidence allow-listing.** The model receives a bundle assembled from stored
   records — nothing else is reachable.
2. **Delimiter fencing.** Telemetry is wrapped in a data block that content
   cannot terminate. This is the one structural boundary; the rest are heuristics.
3. **Injection scanning.** Instruction-shaped log content is flagged and shown
   to the analyst. The scanner is separator-tolerant, because an attacker
   planting a payload in a username cannot use spaces.
4. **Grounded output validation.** The response is parsed into a schema, and
   every cited event ID and technique ID is checked against what was actually
   supplied. Fabricated citations are stripped, the removal is recorded, and the
   analyst sees exactly what was taken out. In strict mode a degraded response is
   discarded entirely. Rejections are persisted for audit.

The model has no tools, executes nothing, and writes nothing to the database
except its own recorded answer.

### Response

Nine action types (isolate host, disable account, block indicator, revoke cloud
session, collect evidence, …), all **simulated**. They update this platform's own
state and record what they would have done against real infrastructure. Nothing
reaches a real system — asserted by a test that greps the response package for
process and network primitives.

The one exception is evidence collection, which is genuinely performed:
snapshotting an incident's own evidence needs nothing outside this database, and
calling it simulated would be the dishonest choice. The catalogue marks it, and
the test suite asserts that every *destructive* action is simulated.

### Reporting

Fifteen fixed sections, assembled from stored records rather than recomputed at
render time, so the report and the console can never disagree. Exports to
Markdown and PDF; every export is written to the audit trail. A report whose
summary was AI-drafted says so on its face.

---

## Security posture

| Control | Implementation |
|---|---|
| Authentication | JWT (8-hour expiry, no silent refresh), bcrypt (cost 12), no plaintext password anywhere |
| Authorization | Three roles enforced by dependency factories, re-checked server-side on every request |
| Account enumeration | Identical response and comparable timing for "no such user", "wrong password", "disabled" and "locked out" |
| Brute force | Per-address sign-in throttle, not configurable |
| Input validation | Every telemetry string length-bounded; IPs parsed, not pattern-matched; metadata depth and key count capped; NUL bytes refused at the edge |
| SQL injection | No string-built SQL anywhere; the hunt DSL validates before it builds |
| Prompt injection | Fenced data block, injection scanning, grounded output validation |
| Error handling | Structured envelope; no SQL, stack traces or paths ever reach a client |
| Secret handling | Log redaction filter; no secrets in the repository; `SECRET_KEY` has no usable default in production |
| Audit | Append-only; no endpoint updates or deletes an audit record |
| Transport | Strict CSP, `nosniff`, `frame-ancestors 'none'`, no server version advertised |

`docs/threat-model.md` states what this design does **not** defend against.

---

## Verification

```bash
cd backend  && pytest                 # 377 tests, ~26s, no services required
cd backend  && ruff check .
cd frontend && npm run lint && npm run typecheck && npm run build
cd frontend && npm test               # 24 browser tests against the real stack
```

The suite runs against SQLite by default and against PostgreSQL in CI, because
the ORM layer is dialect-neutral by design and a dialect bug — a JSON predicate
that silently matches nothing on one engine — is exactly the kind that ships
quietly. Running it on Postgres is how the NUL-byte handling bug in
`docs/testing.md` was found.

Coverage is 85%. The full breakdown, and what the untested 15% is, is in
`docs/testing.md`, along with the four bugs this strategy actually caught.

---

## Documentation

| Document | Contents |
|---|---|
| [architecture.md](docs/architecture.md) | Module layout, data flow, why it is a modular monolith |
| [threat-model.md](docs/threat-model.md) | Assets, adversaries, controls, and what is **not** defended |
| [detection-engine.md](docs/detection-engine.md) | Rule format, the five detectors, writing a rule |
| [mitre-mapping.md](docs/mitre-mapping.md) | The catalogue, coverage, why names are never hard-coded |
| [ai-security.md](docs/ai-security.md) | Injection defence, grounding, what the AI cannot do |
| [incident-response.md](docs/incident-response.md) | Correlation, scoring, playbooks, the simulation boundary |
| [attack-scenarios.md](docs/attack-scenarios.md) | The nine scenarios and what each should trigger |
| [testing.md](docs/testing.md) | Test strategy, evaluation methodology, known gaps |
| [deployment.md](docs/deployment.md) | Production checklist, scaling, what to change first |

---

## Known limitations

Stated here rather than discovered later:

- **All 26 ambiguous events currently alert.** The rules do not distinguish an
  administrator enumerating a host from an attacker doing the same thing. This
  is the honest weakness of signature-and-threshold detection and the reason the
  ambiguous class exists in the dataset.
- **Baselines are frequency tables, not models.** Effective, inspectable, and
  not machine learning. The interface says so rather than implying otherwise.
- **The rate limiter is per-process.** N workers means N times the configured
  budget. `docs/deployment.md` says when this has to move to Redis.
- **The indicator feed is local demo data.** Real feed integration is not
  implemented, and the Indicators page states its own provenance rather than
  implying a live feed.
- **ATT&CK coverage is against a curated subset**, not the full Enterprise
  matrix. The percentage says so wherever it appears.
- **Tokens last eight hours and cannot be revoked.** Signing out clears the
  browser's copy and writes an audit entry, but the token stays valid until it
  expires. There is no server-side deny list; rotating `SECRET_KEY` is the only
  way to invalidate issued tokens, and it invalidates all of them.
- **Single-node.** No clustering, no hot standby, no multi-tenancy.

---

## Licence

MIT — see [LICENSE](LICENSE).

SENTINEL-X is an educational security platform. It simulates attacks against its
own database and simulates responses against its own state. It is not a
production SOC, and `docs/deployment.md` is explicit about the difference.
