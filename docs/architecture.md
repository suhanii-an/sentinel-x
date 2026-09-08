# Architecture

## Shape

A modular monolith: one FastAPI process, one PostgreSQL database, one static
frontend.

This is a deliberate choice, not a shortcut. A detection platform's hardest
correctness property is that **the detection, the alert, the incident, the
timeline and the report all agree with each other**. Splitting those into
services would replace a transaction with a distributed consistency problem and
buy nothing at this scale. Microservices for a single-node educational SOC would
be architecture theatre.

The module boundaries are real even though the process is one: detection knows
nothing about HTTP, detectors know nothing about the database, and the AI layer
cannot reach anything the context builder did not hand it.

---

## Data flow

```
 telemetry (raw, per-source)
        │
        ▼
 app/telemetry/normalizers/*      one normalizer per source format
        │                         → NormalizedEvent (the single contract)
        ▼
 app/services/ingestion.py        validate, bound, persist, resolve entities
        │
        ▼
 app/services/detection_runner.py assemble a DetectionContext
        │                         (candidate events, IOC index, baselines)
        ▼
 app/detection/engine.py          run every enabled rule
        │                         → DetectionResult (rule verdict + evidence)
        ▼
 app/services/alerts.py           dedup, score, persist as Alert + evidence links
        │
        ▼
 app/correlation/engine.py        cluster by shared entity + time → Incident
        │                         then refresh every derived field
        ▼
 app/mitre/catalog.py             map technique IDs → tactics, build attack chain
        │
        ├─→ app/services/timeline.py    chronological evidence
        ├─→ app/services/graph.py       entity graph
        ├─→ app/ai/service.py           optional, grounded explanation
        ├─→ app/response/service.py     simulated containment
        └─→ app/reporting/generator.py  fifteen sections from stored records
```

Each arrow is a function call inside one transaction. An alert and its evidence
links are written together or not at all.

---

## Module map

| Package | Responsibility | Depends on |
|---|---|---|
| `app/core/` | Config, database, security, logging, errors, time, network classification | nothing in the app |
| `app/models/` | SQLAlchemy models | `core` |
| `app/telemetry/` | Source-specific normalizers → `NormalizedEvent` | `core`, `models` |
| `app/detection/` | Rules, conditions, five detectors, engine | `core`, `models` |
| `app/correlation/` | Clustering, incidents, risk, confidence | `core`, `models`, `mitre` |
| `app/mitre/` | Local ATT&CK catalogue | `core` |
| `app/simulators/` | Attack scenario generators | `core`, `telemetry` |
| `app/threat_hunting/` | Hunt DSL, validator, safe query builder | `core`, `models` |
| `app/ai/` | Provider abstraction, guards, grounded service | `core`, `models` |
| `app/response/` | Action catalogue, playbooks, simulated execution | `core`, `models` |
| `app/reporting/` | Report generation, PDF rendering | `core`, `models` |
| `app/evaluation/` | Labelled dataset, replay harness, metrics | everything |
| `app/services/` | Orchestration across packages | everything |
| `app/api/` | HTTP surface, auth, RBAC | `services`, `schemas` |

The dependency direction is one-way. Nothing in `core` imports from a feature
package, and no detector imports from `api`.

---

## Decisions worth explaining

### One normalized event schema

Every log source is translated into a single `NormalizedEvent` before anything
else sees it. Rules are written against that schema, never against a source
format. Adding a log source is writing one normalizer; it touches no rule.

The schema is also the trust boundary. Ingestion is the one endpoint that
accepts attacker-influenced content by design — logs describe what an attacker
did, and the attacker chose some of the strings. So validation there is a
security control: every field length-bounded, IPs parsed rather than
pattern-matched, metadata depth and key count capped, unknown fields refused
rather than stored.

### Detectors are pure functions

A detector receives a `DetectionContext` — candidate events, the indicator
index, the behavioural baselines — and returns results. It never touches a
session. Two consequences:

- Unit-testing a detector takes three lines of setup and no database.
- Detection is deterministic. The same inputs always produce the same output,
  which is a precondition for the evaluation harness meaning anything.

### Rules are data

A rule is a YAML document interpreted by the engine. There is no `eval`, no
dynamic import, and no path from rule content to executable logic. An anomaly
rule names a detector from a registry rather than an import path, so a rule file
can never introduce code.

Rules are validated structurally at load time — unknown field names, missing
required blocks, ungroupable group-by fields, malformed technique IDs are all
refused. A rule that fails validation is not loaded in a degraded form; it is
refused and reported, because a partially-parsed detection rule is worse than no
rule at all.

### Two numbers, not one

Risk and confidence answer different questions and are computed separately. A
certain finding about something trivial should not inherit a high risk score,
and a high-impact guess should not masquerade as a certainty. Both are built
from weighted components that each carry a value and a sentence of explanation,
and both are stored on the incident rather than recomputed at render time.

### Derived state is rebuilt, never patched

`refresh_incident` recomputes every derived field from the incident's current
alerts. It is idempotent and total. Incremental updates to correlated state are
where "the timeline shows six events but the header says nine" bugs come from,
and they are very hard to find after the fact.

### Dialect-neutral ORM

Postgres in production, SQLite for tests and for a zero-dependency local run.
JSONB and its indexes are applied as dialect-conditional variants rather than
hard-coded, and timestamps go through a `TypeDecorator` that forces UTC in and
out — SQLite cannot store a timezone, and a naive datetime leaking into a
window calculation is a silent, wrong answer.

CI runs the whole suite against both engines. That is not belt-and-braces: a
dialect difference that makes a JSON predicate match nothing on one engine
produces a hunt that returns zero rows and *looks like a clean result*. The
NUL-byte handling bug described in `testing.md` was found exactly this way.

### The AI layer sits outside the pipeline

Not in it. The pipeline completes, writes its results, and only then can the AI
be asked to explain them. Removing the provider removes explanation, not
detection. A detection pipeline whose verdicts depend on a language model has no
reproducible behaviour to test, and therefore no meaningful evaluation.

---

## Frontend

React 18 + TypeScript + Vite, TanStack Query for server state, React Flow for
the attack graph, Recharts for analytics.

Two conventions do most of the work:

**`QueryBoundary` renders exactly one of loading / error / empty / content.**
No screen can show `undefined`, and no chart can render with no data in it.

**The attack graph is laid out in kill-chain columns, not by force.** Node
position carries meaning — source address, account, host, process, alert,
technique — so the picture is readable instead of a hairball.

Route-level code splitting keeps the graph and chart libraries out of the
initial bundle; an analyst opens the dashboard and the alert queue first.
