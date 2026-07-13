# Microsoft Security Ramp — Sentinel / KQL / Defender XDR

Public work log of my hands-on ramp into the Microsoft security stack.
Every entry is work I personally performed in my own lab environment.

**Start date:** July 10, 2026 · **Sprint target:** July 21, 2026
**Environment:** Microsoft Sentinel workspace (`law-sentinel-lab`, East US),
onboarded to the unified Microsoft Defender portal.

## Sprint plan
| Day | Date | Focus |
|---|---|---|
| 1 | Jul 10 | Deploy workspace, connect data, author + fire first analytics rule |
| 2–3 | Jul 11–12 | KQL core: where, project, summarize, join (rebuilt cold daily) |
| 4 | Jul 13 | Sentinel operations: rules, incidents, connectors in depth |
| 5 | Jul 14 | Defender XDR: E5 trial, incident investigation, advanced hunting |
| 6 | Jul 15 | Rule tuning: exclusions, thresholds, documented before/after volumes |
| 7 | Jul 16 | Consolidation + mock interview |
| 8–11 | Jul 17–20 | Second tuning pass, repo polish, drills |

## Background
This ramp builds on detection work I already own in production: the GPS
anti-cheat pipeline in [HexCapture](https://github.com/TravisMcGray/territory-app) —
threshold-based detection logic, false-positive tuning against live telemetry,
raw-data preservation for audit.

## Day logs
- [Day 1 — Workspace, connector, first detection](logs/day-01.md)
<img width="1568" height="656" alt="Rule1" src="https://github.com/user-attachments/assets/a90f6cb9-53df-46a3-9cda-41a8d3b0a491" />


# Day 2 — July 11, 2026
<img width="902" height="642" alt="Day2-16incidents" src="https://github.com/user-attachments/assets/f99cc687-0318-4a4d-8af3-9856036180e2" />

## Pipe verification
- AzureActivity ingesting; SentinelHealth showing scheduled-rule-run heartbeats.
- Isolated prior no-data issue to first-ingestion latency (events delivered
  hours after generation). Confirmed by morning ingestion.

## Incident triage (live data)
- Rule "Lab - Azure resource write operations" fired ~20 incidents on own
  administrative activity (tag writes). IDs 3–26.
- Walked incidents to verdict: Benign — own account (tmcgray204),
  known home IP, MICROSOFT.RESOURCES/TAGS/WRITE, Administrative category.
- Dispositioned queue: Resolved + classified. Distinction applied:
  "Informational/expected" not "False positive" (detection worked; activity
  was benign — mislabeling as FP corrupts rule accuracy metrics).

## Rule tuning
- Before: `AzureActivity | where OperationNameValue has "write"` → 6 hits/24h,
  all generating incidents.
- Tuned: added `| where CallerIpAddress != "<home IP>"` exclusion.
- Validated by running the tuned query BY HAND rather than waiting for the
  rule cycle. Expected 0 residual; got 2.
- Investigated the 2: own alertRules/write activity from a DIFFERENT IP.
- Finding: IP-based exclusion is brittle — my address isn't static, so noise
  returns when IP changes. Stable identifier is Caller (account), not IP.
  Production-correct move is a surgical exclusion (service account + specific
  operation + specific resource), not a blanket IP or account filter.
- Decision: left IP exclusion in place for lab; documented the limitation.

## Ingestion delay (measured)
- Ran: AzureActivity | extend delay = ingestion_time() - TimeGenerated
       | summarize percentiles(delay, 95, 99)
- [insert the two numbers once run]

## Concepts locked
- UTC in logs; Eastern = UTC-4 summer / -5 winter.
- getschema to discover unfamiliar table columns.
- Queues filter by default — check exclusions before trusting empty results.
- Validate detection logic via manual query, not by waiting on schedule.

# Day 3 — KQL Correlation & Baselining

## Environment
Azure Data Explorer help cluster (public sample data, ~885M rows, RawSysLogs).
Practiced correlation and baselining on live data.

## Skills
- `summarize count() by` — collapsed 885M rows into per-type and per-hour summaries.
- JSON field extraction: `tostring(tags.host)` to pull values from JSON columns.
- `join kind=inner` — correlated two metric types on a shared hourly time key.
- Debugged a join returning excess rows: root cause was join key granularity
  (sub-second timestamps not bucketed). Fixed by binning to Hour and joining on Hour.
- Windowed filtering: `where timestamp between (X .. Y)`.
- Baselining: `datetime_part("hour", timestamp)` to find the average shape of a day.

## Investigation (full loop)
- Observed: one hour showed 62,700 requests vs ~451,000 for every other hour.
- Hypothesis: anomaly, or partial first hour of data collection.
- Baselined by hour-of-day across all days → every hour ~102,000, uniform.
- Verdict: BENIGN. The low count was a collection-start artifact (partial hour),
  not a security event. Confirmed no periodicity anomaly.

## Takeaways
- Query fields that exist — checked schema first; `sourceip` returned empty
  (field absent in this dataset), `host` returned data. Can't hunt a field that isn't there.
- Never call something an anomaly without baselining. Most spikes are artifacts
  or normal periodicity; the baseline query decides which.
- Table first, then operators: `RawSysLogs | where ... | summarize ... | join ...`


# Day 4 — Detection Logic & Live Investigation

## Multi-rule environment
Enabled additional analytic rule templates in the Sentinel lab to build a
realistic multi-rule environment (previously one custom rule).

## Detection logic literacy — read and dissected rules across all 3 schedule types
Practiced reading production rule templates and articulating, for each: what it
detects, its data dependency, its MITRE mapping, and why its schedule fits its threat.

- **Event-based (my custom rule):** every 5 min / 1-hr lookback. Detects individual
  write events — short window, high frequency because events happen constantly and
  need catching fast.
- **Behavioral anomaly ("Suspicious Resource deployment"):** every 1 day / 14-day
  lookback. Detects a *rare caller* creating resources (compromised-account abuse,
  T1496/Impact). Long baseline because "rare" can't be seen in a short window.
- **Catastrophic-NRT (AD FS / Golden SAML, T1578.003):** near-real-time, ~1 min,
  queries on ingestion time. Detects federation-trust tampering — NRT because
  forging identity tokens is catastrophic and fast; can't wait an hour.

Key principle learned: run frequency and lookback are driven by *what you're
detecting*, not preference. Event = short/frequent; anomaly = long baseline/infrequent;
catastrophic = NRT. Also: not every daily rule is baselining — some are daily as a
cost-vs-urgency tradeoff (expensive queries shouldn't run every 5 min for
non-catastrophic threats).

Data-dependency judgment applied: did NOT enable the AD FS / hybrid-identity rules
because I don't collect that telemetry — enabling detections whose data sources I
lack adds noise to the inventory without adding coverage.

## Live investigation — brute-force alert (worked end to end)
Investigated a "Unauthorized Cloud Region Access" brute-force alert against a login
endpoint.

- Read the alert, extracted key fields (source IP, target account, 403 responses).
- Built an escalation framework: did it succeed? volume? source reputation? target value?
- Pivoted to log search to check the source IP's full activity.
- **Critical lesson — never disposition on absent data:** my first search returned
  nothing due to a filter that didn't apply; I nearly called the alert benign. When
  I fixed the search, it revealed 50 attempts from one source in under an hour against
  one target — flipping the verdict from "benign" to a true-positive automated
  brute-force.
- **Second lesson — tie the success to the attacker:** searching logs for "success"
  alone returned 100+ successful events from *other* users; a success is only relevant
  if it's tied to the attacker's IP AND timeframe. The answer lives in the intersection
  of both conditions, not either alone.
- Verdict: TRUE POSITIVE, unsuccessful. Real automated brute-force, all attempts
  blocked, no access gained. Escalation note: block source IP, monitor target account,
  check for same pattern from other IPs.

## Disposition terminology reinforced
- False positive = detection was wrong (nothing happened).
- Benign positive = detection was right, activity real but harmless/expected.
- True positive = real malicious activity correctly detected (even if it failed).
  A blocked brute-force is a true positive (real hostile intent), NOT benign
  (which implies harmless/expected activity).
