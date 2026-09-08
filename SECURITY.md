# Security policy

## Reporting a vulnerability

Open a GitHub security advisory on this repository, or open an issue **without
exploit details** and ask for a private channel.

Please include what you can: affected component, the impact, and a way to
reproduce it. A working proof of concept is welcome but not required — a clear
description of the flaw is worth more than a script.

There is no bounty. This is an educational project. Findings are credited in the
release notes unless you would rather they were not.

## Scope

In scope, and genuinely interesting:

- Authentication or authorization bypass
- SQL injection, particularly through the threat-hunting DSL
- Prompt injection that survives the guards in `docs/ai-security.md` —
  specifically, anything that escapes the data block, or any AI output that
  reaches an analyst carrying a fabricated citation
- Stored XSS through telemetry content, especially in the report viewer
- Secret disclosure through logs, errors or API responses
- A path by which a "simulated" response action does something real
- A way to make the evaluation harness report a number it did not measure

Out of scope, because they are documented limitations rather than bugs — see
`docs/threat-model.md` §5:

- Host compromise
- A malicious administrator (detective control only, by design)
- Token theft via an existing XSS (report the XSS instead)
- Spoofed `X-Forwarded-For` on a deployment that does not sit behind a proxy
- Rate-limit multiplication across multiple workers
- Volumetric denial of service

If you find something in the "out of scope" list that is **worse than the
document claims**, that is in scope. The threat model understating a risk is
itself a finding.

## What this project does about security

Summarised in `README.md`, specified in `docs/threat-model.md`, and asserted by
89 tests in `backend/tests/test_security.py`.

The short version:

- Detection is deterministic; the AI is never the source of truth
- Every endpoint but sign-in and health requires a token, enforced by a
  dependency and verified by a test that walks the OpenAPI schema
- No string-built SQL anywhere; the hunt DSL validates before it builds
- Telemetry is untrusted data everywhere downstream — bounded on ingest,
  parameterised in queries, rendered as text, fenced before a model sees it
- Every response action is simulated, and a test greps the package to prove the
  code has no way to reach a real system
- The audit log is append-only: no endpoint updates or deletes an audit record

## Responsible use

SENTINEL-X simulates attacks against its own database. It contains no exploit
code, no malware, and nothing that touches a system it does not own.

Do not point it at telemetry you are not authorised to process. Do not use the
scenario generators as a template for activity against systems you do not own.
