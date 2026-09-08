# Attack scenarios

## What a simulation is

A scenario generates realistic security telemetry and writes it to the database.
That is the whole mechanism.

It does **not**: deploy malware, exploit a vulnerability, scan a network, touch
any external system, steal a credential, or modify any operating-system setting.
The simulator package contains no process-execution or network primitives at
all, and `tests/test_security.py` asserts it by grepping the package. The
guarantee is that the code has no way to reach a real system, not that it
promises not to.

Every generated record is flagged in the database, counted in `/system/info`,
and labelled `SIMULATED` in the interface.

---

## Reproducibility

Every scenario takes a seed. The same seed produces byte-identical telemetry, so
any result can be reproduced from this repository. The test suite asserts it,
and the evaluation harness depends on it: if a seeded run were not
deterministic, nothing measured from it would mean anything.

Re-running the same scenario in the same database correctly produces *fewer*
alerts the second time. That is deduplication suppressing a repeat detection on
the same entity inside the same window, not the simulator drifting. Isolated
replay is what the evaluation harness does.

---

## The catalogue

| Key | Name | ATT&CK techniques | Should trigger |
|---|---|---|---|
| `full_chain` | Full Attack Chain | T1110, T1110.001, T1078, T1087, T1087.001, T1082, … | BRUTE_FORCE_001, BRUTE_FORCE_003, CREDENTIAL_FILE_ACCESS_001, ACCOUNT_DISCOVERY_001, … |
| `brute_force` | SSH Brute Force | T1110, T1110.001, T1078 | BRUTE_FORCE_001, BRUTE_FORCE_003 |
| `password_spraying` | Password Spraying | T1110, T1110.003 | BRUTE_FORCE_002 |
| `credential_abuse` | Valid Account Abuse | T1078, T1552, T1552.004 | VALID_ACCOUNT_ABUSE_001, CREDENTIAL_FILE_ACCESS_001 |
| `account_discovery` | Account and Host Discovery | T1087, T1087.001, T1082, T1033, T1069 | ACCOUNT_DISCOVERY_001 |
| `privilege_escalation` | Privilege Escalation | T1548, T1548.001, T1548.003, T1068 | PRIVESC_SUID_ENUM_001, PRIVESC_SUDO_CHAIN_001 |
| `persistence` | Persistence Establishment | T1053, T1053.003, T1543, T1543.002, T1098, T1098.004 | PERSISTENCE_SCHEDULED_TASK_001, PERSISTENCE_BACKDOOR_ACCOUNT_001, PRIVESC_GROUP_CHANGE_001 |
| `lateral_movement` | Lateral Movement | T1021, T1021.004, T1078, T1105, T1570 | LATERAL_MOVEMENT_001, LATERAL_BREADTH_001, LATERAL_TOOL_TRANSFER_001 |
| `cloud_iam` | Cloud IAM Abuse | T1087, T1087.004, T1526, T1098, T1098.001, T1098.003 | CLOUD_DISCOVERY_001, CLOUD_IAM_PRIVESC_001, CLOUD_IAM_KEY_CHAIN_001, CLOUD_LOG_TAMPERING_001 |

The "should trigger" column is the scenario's own declaration, and the Simulator
page compares it against what actually fired. **A rule that was expected and
stayed silent is reported, not hidden** — that is a coverage gap, and the most
common cause is a rule that needs behavioural history the database does not have
yet.

---

## The full chain

Eight stages, each producing telemetry from the sources a real estate would
have, ending now so the incident is live when you open the console.

| Stage | Activity | Sources |
|---|---|---|
| 1. Reconnaissance | External connection attempts against exposed services | network flow |
| 2. Brute force | Repeated SSH authentication failures against one account | linux auth |
| 3. Initial access | A successful authentication after the failures | linux auth |
| 4. Discovery | Account, host and group enumeration | EDR process |
| 5. Privilege escalation | SUID enumeration, then a sudo chain | EDR process, linux auth |
| 6. Persistence | A cron entry, a service install, a backdoor account | file integrity, linux auth |
| 7. Lateral movement | SSH to further hosts, tool transfer | linux auth, network flow |
| 8. Cloud compromise | IAM enumeration, policy attachment, log tampering | cloud audit |

### The detail that makes it one incident

The cloud stage runs from **the same adversary source address** as the earlier
on-premises stages. That shared address is load-bearing: correlation joins
alerts that share an entity, and without it the cloud activity would form a
second, disconnected incident.

This is realistic — an attacker who has compromised a host uses stolen keys from
that host — and it is also a demonstration of the correlation rule doing what it
says. An earlier version of this scenario produced two incidents, and the fix
was to make the telemetry honest rather than to loosen the correlation rule.

---

## Running one

From the Simulator page, or:

```bash
curl -X POST localhost:8000/api/v1/simulations/run \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"scenario": "full_chain", "seed": 4242}'
```

The response reports what actually happened, including what did not:

```json
{
  "run": { "event_count": 62, "alert_count": 28, "seed": 4242, "stage_log": [...] },
  "pipeline": { "events_ingested": 62, "alerts_created": 28, "alerts_suppressed": 4,
                "ioc_matches": 3, "detection_ms": 210, "correlation_ms": 44 },
  "incidents": ["SX-2026-0003"],
  "expected_detections": [...],
  "actual_detections": [...],
  "detections_missing": [],
  "safety_notice": "..."
}
```

Running an analyst role is required. A viewer cannot start a simulation.

---

## Benign history

The seed script generates days of benign activity before any attack runs. This
is not padding.

The anomaly detector needs behavioural history to say anything. Below
`min_observations` it stays silent, which is correct — calling the first login
of a new account anomalous is a coin toss. Without benign history, the anomaly
rules never fire and the platform looks like it only does thresholds.

The benign generator also produces the activity that *resembles* attacks:
administrators enumerating hosts, backup accounts sweeping the estate at 02:00,
configuration management writing cron entries, users mistyping passwords. That
is what makes the false-positive numbers in `README.md` mean something.

---

## Adding a scenario

1. Subclass the simulator base in `app/simulators/`.
2. Declare a `ScenarioSpec`: name, description, techniques (IDs only — names
   come from the catalogue), expected telemetry, expected detections, and a
   safety notice.
3. Generate `TelemetryRecord`s using the seeded RNG. Use reserved and
   documentation address ranges; never a real address, hostname or credential.
4. Register it.
5. Add it to `tests/test_end_to_end.py` — the parameterised test asserts that
   every scenario produces telemetry **and** at least one detection. A scenario
   the rule set cannot see proves nothing.

If the new scenario should fire an existing rule and does not, that is a finding
worth reporting, not a reason to weaken the rule.
