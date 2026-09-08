# Testing and evaluation

```bash
cd backend  && pytest                 # 377 tests, ~26s, no services required
cd backend  && pytest --cov           # 85% coverage
cd backend  && ruff check .
cd frontend && npm run lint && npm run typecheck && npm run build
cd frontend && npm test               # 24 browser tests against the real stack
```

The suite runs with no Postgres, no Redis, no AI provider and no network.
Anything that cannot be tested that way is tested against an explicit fake
rather than skipped.

---

## The suites

| Module | Tests | What it pins down |
|---|---|---|
| `test_security.py` | 152 | Ingestion bounds, SQL-injection payloads at every DSL position, LIKE-wildcard handling, prompt injection, AI grounding, response simulation and role enforcement, secret handling, rate limits |
| `test_api.py` | 79 | Auth, RBAC, error envelopes, security headers, the anonymous surface, every read endpoint on an empty database |
| `test_detection.py` | 50 | The condition language, all five detectors, rule validation, and the 50 shipped rule self-tests |
| `test_hunting.py` | 42 | Hunt execution, sequence hunts, SQL/in-memory matcher parity, saved hunts, cloud analysis, search |
| `test_correlation.py` | 30 | Clustering, incident lifecycle, risk components, confidence |
| `test_end_to_end.py` | 24 | The whole pipeline through HTTP, every scenario, dataset reproducibility, evaluation, dashboard consistency |
| `frontend/tests/` | 24 | Every route renders signed in, sign-in and sign-out, and the claims the console makes about itself on screen |

### Three tests that earn their keep

**Every operation requires a token.** The test walks the OpenAPI schema rather
than a hand-maintained list, so an endpoint that forgets its auth dependency
fails CI the day it is written rather than the day it is exploited. It found
`/auth/roles` reachable anonymously.

The *role* requirements are a separate, hand-maintained table, and that
difference matters: it covers the twelve endpoints where the role is
load-bearing, and it is only as good as its labels. `POST /evaluation/run` was
labelled "analyst" while the endpoint requires admin, which silently excluded it
from the analyst-cannot-do-admin-things check — a downgrade to `RequireAnalyst`
would have passed CI. Fixed, and worth stating plainly rather than claiming the
table is exhaustive.

**Every rule has a negative case.** A rule with only positive cases has never
been checked for false positives, and noise is what makes analysts stop reading
alerts. CI fails if one appears.

**The response module cannot reach a real system.** A grep, deliberately. The
strongest guarantee that "simulated" is true is that the code has no way to do
otherwise.

---

## Evaluation methodology

Detection performance is **measured**, by a harness in this repository, against
a labelled dataset in this repository. There is no configuration, default or
seed value for any metric anywhere in the codebase.

### Definitions

- **Unit of analysis**: one security event.
- **Positive**: the event is *trigger* evidence for at least one alert.
- **TP**: malicious-labelled event that triggered an alert.
- **FP**: benign-labelled event that triggered an alert.
- **FN**: malicious-labelled event no alert triggered on.
- **TN**: benign-labelled event no alert triggered on.

### Four decisions that make the numbers honest

**Trigger evidence only.** Alerts also carry context events. Counting those as
detections would credit a rule for every benign event that happened to sit in
the same window — inflating recall and hollowing out precision at the same time.

**Hourly replay.** The dataset is replayed in hourly batches rather than as one
batch, so stateful rules cannot see events that had not yet occurred. Processing
it all at once produces optimistic recall from causality the platform would not
have had.

**Isolated database.** Each run executes in a temporary database of its own, so
evaluation never pollutes operational data and results are never influenced by
what was already there. A test asserts the live event count is unchanged by a
run.

**A three-class dataset.** Benign, malicious, and **ambiguous** — benign
activity that legitimately resembles an attack. Ambiguous events are excluded
from precision and recall, because scoring them either way would be a claim
about ground truth nobody can justify, and reported separately as
false-positive pressure.

### Current result

Seed 1337, 14 days of benign history:

```
precision 0.973   recall 0.900   F1 0.935   accuracy 0.995   FPR 0.0012
TP 72   FP 2   TN 1729   FN 8
scenarios detected 8/8    median detection latency 45.1s (event time)
dataset 1,837 events — 1,731 benign, 80 malicious, 26 ambiguous
ambiguous alert rate 26/26 (100%)
```

**That last line is the weakness.** Every ambiguous event alerts. The rule set
cannot distinguish an administrator enumerating a host from an attacker doing
the same thing. It is on the Evaluation page, in the README and here, rather
than in a footnote.

### The tests deliberately do not assert a metric floor

`test_end_to_end.py` asserts the *shape* and the *internal consistency* of an
evaluation result — that precision follows from the confusion matrix published
beside it, that F1 follows from precision and recall, that the dataset classes
sum to its size. It does not assert `precision > 0.9`.

A test that demands a metric is a test that will eventually be satisfied by
changing the metric. The number belongs in the README, where a human reads it
and can see it move.

---

## Four bugs the test strategy found

Worth recording, because they are the argument for the strategy — and because
three of the four were invisible to a green test suite.

**RFC 5737 addresses counted as private.** Python's `ipaddress.is_private`
answers "is this in an IANA special-purpose registry?", and that set includes
the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) this
project uses to represent adversary infrastructure. So every simulated attacker
address was classified internal and the `external_source` anomaly factor never
fired — silently, with no error anywhere. `app/core/netutils.py` now defines
internality against the ranges an enterprise actually routes internally, and
documents why.

**NUL bytes in a URL.** `GET /api/v1/events/%00` returns 404 on SQLite and
**500** on PostgreSQL, because Postgres cannot store a NUL in a text column and
raises rather than truncating. The suite ran green on SQLite for its whole life
and failed on the first Postgres run. This is the entire reason CI runs both
engines: a dialect difference that makes a query fail — or worse, silently match
nothing — is invisible in local development and appears in production. Rejected
at the edge now, with a regression test that runs on both.

**A seeded dataset that was not reproducible.** The per-scenario RNG was seeded
with `hash(scenario_key)`, and Python randomises string hashing per process
unless `PYTHONHASHSEED` is pinned. The generated telemetry genuinely differed
between runs. The confusion matrix was robust to the variation, so every
headline number looked stable while the measured detection latency moved by tens
of seconds — a metric quietly falsifying the project's central claim that a
seeded evaluation is reproducible. Nothing failed; the bug was found by running
the harness three times and comparing. `test_the_dataset_is_byte_for_byte_reproducible`
now compares two independently built datasets field by field.

**Browser tests that passed without a session.** The console keeps its token in
`sessionStorage` by design, and Playwright's `storageState` persists cookies and
`localStorage` only — so the shared session never restored. Fourteen route tests
asserted "an `h1` is visible", which the *sign-in page* also satisfies, so they
all passed while the browser sat on the login screen the whole time. A test that
cannot fail is worse than no test, because it is counted. The assertion is now
specifically "the signed-in console", and the session is replayed through an
init script.

---

## Coverage

85% overall, branch coverage on.

The uncovered remainder is mostly: provider HTTP clients (excluded — they talk
to external APIs and are exercised through a fake, so line coverage there would
only reward mocking them line by line), defensive branches for malformed input
shapes that validation already rejects, and `__repr__` methods.

Coverage is reported, not targeted. A suite optimised for a coverage number
tests the code that is easy to reach rather than the code that is dangerous to
get wrong.

---

## CI

Six jobs, on every push and pull request:

1. **Backend / sqlite** — ruff, then the full suite.
2. **Backend / postgres** — the same suite against real Postgres, plus
   `alembic upgrade head` and `alembic check`, so a model change with no
   migration fails the build rather than the first real upgrade.
3. **Detection rules** — every rule loads, every self-test passes, and every
   rule has a negative case.
4. **Frontend** — lint, typecheck, build.
5. **Dependency audit** — `pip-audit` and `npm audit` report; a tracked `.env`
   or key file **fails**.
6. **Container images** — both Dockerfiles build.
