# Contributing

## Before you start

Read `docs/architecture.md` for the shape and `docs/threat-model.md` for what
this project is defending. Most review comments on a security tool are really
threat-model questions in disguise.

## Setup

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
export DATABASE_URL="sqlite+pysqlite:///./dev.db"
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
python ../scripts/seed_database.py --quick
pytest
```

```bash
cd frontend && npm install && npm run dev
```

## Before opening a pull request

```bash
cd backend  && ruff check . && pytest
cd frontend && npm run lint && npm run typecheck && npm run build
```

CI runs the backend suite against Postgres as well as SQLite. If your change
touches a query, run it both ways locally — a dialect difference that makes a
predicate silently match nothing is invisible otherwise.

## The rules that are not negotiable

**Nothing is faked.** No hard-coded metric, no invented technique identifier,
no placeholder that looks like a working feature. If something cannot be
implemented correctly, mark it `NOT IMPLEMENTED` or `SIMULATED` and say why.

**The AI is never the source of truth.** A change that makes detection,
correlation, scoring or mapping depend on a model response will be rejected.

**Response actions stay simulated.** A destructive action that touches a real
system does not belong here.

**No secrets, ever.** Not in code, not in tests, not in fixtures, not in
example files. Use reserved and documentation address ranges, invented
hostnames, and obviously fake account names.

## Adding a detection rule

1. Write the `no_match` case first — the benign activity that most resembles
   what you are detecting.
2. Then the `match` case.
3. Then the rule.
4. Fill in `false_positives` honestly. An analyst triaging at 3am needs it.
5. ATT&CK by identifier only. Names come from the catalogue.
6. Run the evaluation harness. If recall improved and precision fell, say so in
   the pull request. A tradeoff reported is a tradeoff; a tradeoff hidden is a
   regression.

`docs/detection-engine.md` has the full format.

## Adding an endpoint

- Use the role dependencies (`RequireViewer` / `RequireAnalyst` / `RequireAdmin`).
  A forgotten check inside a handler is invisible; a missing dependency is
  visible in the signature — and the auth test walks the OpenAPI schema, so it
  will fail.
- Raise the structured errors from `app/core/errors.py`. Never let a database
  exception reach a client.
- Bound every list parameter. An unbounded `limit` is a denial-of-service
  parameter.
- Audit anything that changes state.

## Style

Python: ruff, 110 columns, type hints on anything public. Frontend: ESLint,
TypeScript strict, no `any`.

**Comments explain *why*.** The code already says what it does. A comment that
restates the line above it is noise; a comment explaining why a window is
extended after the threshold is met is the reason the next person does not
"simplify" it back into a bug.

## Commit messages

Imperative, and say why:

```
Extend threshold windows to all events inside them

An alert reporting eleven failures with five events attached shows the
analyst a truncated attack. Raises measured recall.
```
