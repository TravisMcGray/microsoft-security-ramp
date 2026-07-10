# Day 1 — July 10, 2026

## Done today
- Created Azure Log Analytics workspace `law-sentinel-lab` (East US) and
  attached Microsoft Sentinel (resource `SecurityInsights(law-sentinel-lab)`).
- Workspace onboarded to the unified Microsoft Defender portal — same
  interface used for Defender XDR operations.
- Installed Content Hub solutions: **KQL Training** (Intro to KQL +
  Advanced KQL workbooks), **Azure Activity**.
- Configured the **Azure Activity data connector** via Azure Policy
  assignment scoped to my subscription — live telemetry from my own
  environment, no canned data.
- Authored my first scheduled analytics rule:
  `Lab - Azure resource write operations`
  - Query: `AzureActivity | where OperationNameValue has "write"`
  - Every 5 min, 1-hour lookback, threshold > 0, severity Low,
    MITRE tactic: Impact, incident creation on.
  - Intentionally broad — this rule exists to be tuned on Day 6.

## First incident
_(screenshot pending — rule armed, waiting on first firing)_

## Notes
- Sentinel Training Lab solution was retired from Content Hub (~2025);
  pivoted to generating my own telemetry instead. Better trade.

## KQL session 1 — demo Log Analytics workspace
Operators learned: search, where, take, project, count, sort by desc

Queries I can rebuild cold:
- SecurityEvent | where EventID == 4625 | take 20
- SecurityEvent | where EventID == 4625 | project TimeGenerated, Account, Computer
- SecurityEvent | sort by TimeGenerated desc | take 5
- SecurityEvent | where EventID == 4625 | count

What I actually learned:
- Every query starts from a source (table or search) — learned via error message
- take = arbitrary rows, NOT first or most recent; recency requires sort by TimeGenerated desc
- Zero results ≠ no data — check the time range picker first (invisible filter on every query)
- take is for eyeballing data; finding patterns requires grouping/counting (summarize, Day 2)
- 4625 rows are logged by the machine that was targeted; IpAddress/LogonType columns show origin

Stumbled on (honest list):
- Simple mode vs KQL mode in the Logs editor
- Forgot the `search` keyword — "Operator source expression should be table or column"
- 0-result count until I widened the time range
