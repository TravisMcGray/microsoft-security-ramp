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
<img width="902" height="642" alt="Day2-16incidents" src="https://github.com/user-attachments/assets/f99cc687-0318-4a4d-8af3-9856036180e2" />
<img width="1568" height="656" alt="Rule1" src="https://github.com/user-attachments/assets/a90f6cb9-53df-46a3-9cda-41a8d3b0a491" />
