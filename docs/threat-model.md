# Threat model

A threat model that only lists defences is a marketing document. This one states
what SENTINEL-X protects, who would attack it, which controls exist, and — the
section that matters — what this design does **not** defend against.

---

## 1. What is worth stealing here

A detection platform is a high-value target precisely because of what it holds.

| Asset | Why an adversary wants it |
|---|---|
| **Security telemetry** | A map of the estate: hostnames, accounts, addresses, process names, cloud identities. Reconnaissance that would otherwise take weeks. |
| **Detection rules** | Knowing exactly what is detected tells an attacker exactly what is not. This is the single most valuable asset here. |
| **Incidents and evidence** | What defenders know, when they knew it, and what they have missed. |
| **Analyst accounts** | An analyst token reads everything. An admin token also edits detection rules — an attacker who disables a rule has silenced the alarm rather than tripping it. |
| **The JWT signing key** | Forges any identity at any role. |
| **The AI API key** | Directly monetisable, and a route to exfiltrating evidence through prompts. |

---

## 2. Who would attack it

**A1 — Unauthenticated network attacker.** Can reach the HTTP surface and
nothing else. Goal: authenticate, or find an endpoint that forgot to require it.

**A2 — Malicious log source.** The one adversary who is *inside* by design.
Security logs describe attacker activity, so the attacker chooses some of the
strings in them: usernames, command lines, user-agents, file paths. They control
data that will be parsed, stored, rendered in a browser, and placed in an LLM
context. This is the most interesting adversary in this model.

**A3 — Authenticated low-privilege user (viewer).** A legitimate account, or a
stolen one. Goal: act beyond their role.

**A4 — Compromised analyst account.** Valid credentials, valid role, hostile
intent. Goal: suppress detections, delete evidence, hide activity.

**A5 — Compromised AI provider.** The model returns whatever an attacker wants:
fabricated evidence, instructions, attempts to exfiltrate context.

**A6 — Supply-chain attacker.** A malicious dependency.

---

## 3. Trust boundaries

```
  A1, A3, A4                  A2                        A5
      │                        │                         │
      ▼                        ▼                         ▼
┌───────────┐          ┌──────────────┐          ┌──────────────┐
│  Browser  │          │  Log source  │          │ LLM provider │
└─────┬─────┘          └──────┬───────┘          └──────▲───┬───┘
      │ HTTPS                 │ HTTPS                   │   │
══════╪═══════════════════════╪═════════════════════════╪═══╪══════ TRUST
      ▼                       ▼                         │   ▼
┌─────────────────────────────────────────────────────────────────┐
│ FastAPI · auth · RBAC · rate limit · validation · headers       │
├─────────────────────────────────────────────────────────────────┤
│ Detection · correlation · scoring · hunting · response · report │
│                                                     ▲           │
│                          AI layer ──────────────────┘           │
│                          (fences, allow-lists, output validation)│
├─────────────────────────────────────────────────────────────────┤
│ PostgreSQL                                                      │
└─────────────────────────────────────────────────────────────────┘
```

Three boundaries carry real weight:

1. **Browser → API.** Everything is authenticated except sign-in and the health
   probe, and roles are re-checked server-side on every request.
2. **Log source → ingestion.** Content is *untrusted data* everywhere
   downstream: bounded on the way in, parameterised in every query, rendered as
   text and never as markup, and fenced before it reaches a model.
3. **API → LLM.** Bidirectionally untrusted. Everything sent is allow-listed
   from stored records; everything returned is schema-validated and
   grounding-checked before an analyst sees it.

---

## 4. Threats and controls

### T1 — Unauthenticated access to security data
**Control.** Every endpoint except `POST /auth/login` and `GET /system/health`
requires a valid token. This is enforced by a dependency, not by a check inside
each handler — a missing dependency is visible in the route signature, a
forgotten `if` is not. A test walks the OpenAPI schema and asserts that every
operation refuses an anonymous caller, so an endpoint that forgets fails CI the
day it is written.

### T2 — Credential attacks
**Control.** bcrypt at cost 12. Identical response *and* comparable timing for
every failure mode — no such user, wrong password, disabled account, locked
account — so sign-in is not an enumeration oracle. The lockout branch matters
most and was the one that leaked: it used to return a distinct "account
temporarily locked" message, reachable only for an account that exists, which
told an attacker in eight attempts whether a username was real. It now spends
the same bcrypt cost and returns the same message as every other failure. A per-address
throttle on sign-in, deliberately not configurable. Minimum password length
enforced at creation. No default password exists: the seed script generates a
random one and prints it once.

### T3 — Privilege escalation
**Control.** Three roles (viewer < analyst < admin) enforced by dependency
factories. The role comes from the signed token, never from the request body.
The interface hides controls a role cannot use, but that is a courtesy — the
server refuses the request regardless. Parameterised tests assert the required
role for the twelve endpoints where the role is load-bearing.

Response actions carry a second, finer check: `ActionSpec.requires_role` is
published by the API and rendered as a badge in the console, so it is a claim
the interface makes about authorization, and the service enforces it rather
than relying on the endpoint's blanket analyst requirement. It did not, until a
review pointed out that a published authorization control which is checked
nowhere is exactly the kind of thing this project says it does not ship.

### T4 — Token forgery or replay
**Control.** HS256 with a key that has no usable default in production; the
application refuses to start without one. Short expiry, no silent refresh.
Deactivating an account invalidates its existing tokens immediately, because
identity is re-resolved from the database on every request rather than trusted
from the token's claims. `alg: none` and wrong-key tokens are refused, both
asserted by tests.

### T5 — SQL injection
**Control.** No string-built SQL anywhere in the codebase. The hunt DSL is the
only place a user composes a query, and it validates a structured document
before building anything: field names against a per-dataset allow-list,
operators against a fixed set, values bound as parameters, values coerced to
their column's type (a string where a timestamp belongs used to reach the driver
and come back as a 500), and `LIKE` wildcards inside values escaped. Nine
payloads are tested at every position a caller controls: field names,
`order_by`, the dataset, sequence-step filters, correlation fields and metadata
keys.

### T6 — Stored XSS via telemetry (A2)
**Control.** The API returns JSON with `nosniff` and a CSP of
`default-src 'none'`. The console renders every value as a React text node —
never `dangerouslySetInnerHTML`. The report viewer parses Markdown into React
elements rather than into HTML, specifically so a crafted command line in a
report cannot execute script. Links inside report content are rendered as text,
because an anchor built from report content could carry a `javascript:` target.

### T6b — Filter bypass through LIKE metacharacters (A3)
**Control.** Every caller-supplied value that reaches a `LIKE` pattern is
escaped, and every pattern is passed with an explicit `escape=` — PostgreSQL
defaults to backslash and SQLite has no default at all, so escaping without
declaring the character works on one engine and silently matches nothing on the
other. Both halves are routed through `app/core/sqlutils.py` so no call site has
to remember them. Without this, `?host=%` returns every incident regardless of
host: not SQL injection, since the value is still a bound parameter, but a
filter that silently ignores itself, which is an analyst trusting the wrong set
of results.

### T7 — Denial of service through ingestion (A2)
**Control.** Request bodies capped before they are read into memory. Every
telemetry string length-bounded; metadata depth and key count capped. Regex
subjects truncated before matching, so a pathological pattern cannot be handed
an unbounded input. Pagination limits bounded server-side. Error messages capped
so a request for a 10 MB identifier is not answered with a 10 MB error body.
URLs containing NUL bytes are rejected at the edge — PostgreSQL raises on them
and SQLite does not, which is exactly the kind of difference that turns into a
production-only 500.

### T8 — Prompt injection (A2 → A5)
**Control.** Four layers, and the honest ordering matters:

1. **Structural (a real boundary).** Telemetry is wrapped in a delimited data
   block, and any occurrence of the delimiter inside content is neutralised. No
   log content can terminate the block and land in instruction position.
2. **Capability (a real boundary).** The model has no tools. It cannot execute
   anything, query anything, or write anything. The worst outcome of a fully
   successful injection is a wrong answer — which the next layer catches.
3. **Output grounding (a real boundary).** Every cited event and technique ID is
   checked against what was actually supplied. Fabricated citations are stripped
   and the removal is shown to the analyst.
4. **Scanning (a heuristic, and labelled as one).** Instruction-shaped content
   is flagged. Treating a pattern list as the defence is how injection filters
   get bypassed; it is here to inform the analyst, not to stop the attack.

### T9 — A compromised or lying model (A5)
**Control.** The AI is never the source of truth. Detection, correlation,
scoring, ATT&CK mapping and reporting run without it. Responses are parsed into
a Pydantic schema and rejected if they do not fit. Rejected responses are
persisted, because an AI failure nobody can review is an AI failure that happens
twice. Strict mode discards any response with a grounding failure.

### T10 — Evidence tampering (A4)
**Control.** The audit log is append-only by construction: no endpoint anywhere
in this API updates or deletes an audit record. Alerts and events are never
deleted through the API. Incident status changes record who made them and when.
Disabling a detection rule is admin-only and audited.

### T11 — Secret disclosure
**Control.** A redaction filter on every log record scrubs bearer tokens,
`sk-` keys, AWS access-key IDs, JWTs and credential-shaped assignments. No
endpoint returns a password hash. Error envelopes never carry SQL, stack traces
or filesystem paths. `.gitignore` excludes `.env` and key material, and CI fails
if a credential file is ever tracked.

### T12 — Supply chain (A6)
**Control.** Pinned version ranges, `npm ci` against a committed lockfile,
`pip-audit` and `npm audit` in CI. Containers run as non-root with
`no-new-privileges`. **Partial** — see below.

---

## 5. What this does NOT defend against

The section that makes the rest credible.

**Compromise of the host.** Root on the machine reads the database, the
environment and the signing key. Nothing here defends against that.

**A malicious administrator.** An admin can disable detection rules and delete
nothing but can silence everything. The audit log records it, which means the
control is *detective*, not preventive, and only works if somebody reads it.

**Sophisticated supply-chain attacks.** Advisory scanning catches known CVEs.
A backdoored dependency with no advisory is not caught. Dependencies are not
vendored and the build is not reproducible.

**Token theft from the browser.** The token is in `sessionStorage`, which is
readable by any script on the origin. The mitigations are the strict CSP and the
absence of any third-party script or font — not the storage choice. An XSS bug
in the console would defeat both.

Token lifetime is *not* a meaningful mitigation here and it would be dishonest
to list it as one: tokens last eight hours, there is no server-side deny list,
and signing out clears the browser's copy without invalidating the token.
Rotating `SECRET_KEY` invalidates every issued token and is the only revocation
mechanism. Lowering `ACCESS_TOKEN_EXPIRE_MINUTES` narrows the window; it does
not close it.

**Spoofed `X-Forwarded-For`.** The rate limiter keys on a client address that a
direct connection can set freely. This is safe only behind a proxy that
overwrites the header. The bundled nginx does exactly that — it sets
`X-Forwarded-For $remote_addr` rather than appending to what the client sent,
which it did until a review caught it — but a deployment that exposes the API
directly, or puts a different proxy in front, has a bypassable throttle and a
forgeable address in its audit log.

**Multi-worker rate limiting.** Counters are per-process. N workers means N
times the configured budget. `docs/deployment.md` says when this has to move to
shared state.

**Log source authentication.** Ingestion authenticates the *caller*, not the
*origin* of each record. A compromised forwarder can submit fabricated telemetry
under its own valid credential. Signed log records are not implemented.

**Denial of service at the network layer.** Application-level limits exist;
volumetric attacks are the network's problem.

**Data at rest.** No application-level encryption. Database-level encryption is
the deployment's responsibility.

**Timing side channels beyond sign-in.** Sign-in spends comparable time on a
missing account. Other endpoints are not hardened against timing analysis.

---

## 6. Simulation boundary

SENTINEL-X simulates attacks and simulates responses. This is a security
property, not a limitation to apologise for.

**Simulation writes log records to a database.** It does not deploy malware,
exploit vulnerabilities, scan networks, touch external systems, steal
credentials or modify OS security settings. The simulator package contains no
process-execution or network primitives, and a test asserts it.

**Response actions update this platform's own state.** Isolating a host sets a
flag here. Disabling an account sets a flag here. Nothing reaches real
infrastructure; each action records what it *would* do in production, so the gap
is explicit rather than implied. Evidence collection is the one action genuinely
performed, because it needs nothing outside this database — and that exception
is stated in the catalogue rather than hidden.

All simulated data is flagged in the database, counted in `/system/info` and
labelled `SIMULATED` in the interface. No figure anywhere in this console can
quietly pass seeded data off as production activity.

---

## 7. Residual risk

The single highest residual risk is **detection-rule disclosure**. An attacker
who reads `detection-rules/` knows the exact thresholds, windows and conditions,
and can shape an intrusion to stay underneath all of them. Password spraying
already works this way against per-account lockouts.

This is accepted deliberately. Open rules are auditable, testable and reviewable
by people who are not the author, and a rule set nobody can inspect is a rule
set nobody can improve. The mitigation is defence in depth — thresholds are not
the only detector type, and behavioural and sequence rules do not have a fixed
line to stay under — not secrecy.
