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
