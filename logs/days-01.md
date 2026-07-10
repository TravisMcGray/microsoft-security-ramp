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
