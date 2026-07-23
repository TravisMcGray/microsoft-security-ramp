# Microsoft Security Ramp: Sentinel, KQL, and Defender XDR

This repository documents my hands-on work as I build practical experience with Microsoft Sentinel, KQL, and Defender XDR.

Every completed activity documented here was performed in my own lab environment. Planned work is clearly identified and is not presented as completed experience.

**Start date:** July 10, 2026  
**Current training period:** July 10–22, 2026  
**Primary environment:** Microsoft Sentinel workspace (`law-sentinel-lab`) in East US, onboarded to the unified Microsoft Defender portal.

## Training Log

| Day | Date | Focus |
|---|---|---|
| 1 | July 10 | Deployed the workspace, connected a data source, and created and triggered my first analytics rule. |
| 2–3 | July 11–12 | Practiced core KQL operators, including `where`, `project`, `summarize`, and `join`. |
| 4 | July 13 | Studied Sentinel operations, including analytics rules, incidents, and data connectors. |
| 5 | July 14 | Reviewed Defender XDR incident investigation and Advanced Hunting concepts. |
| 6 | July 15 | Studied rule-tuning concepts, including exclusions, thresholds, and query validation. |
| 7–13 | July 16–22 | Spent at least six hours each day studying Detection Engineering 101, investigative reasoning, Windows telemetry, KQL, baselining, and process relationships. |

## Background

This training builds on detection logic I developed for [HexCapture](https://github.com/TravisMcGray/territory-app), including threshold-based GPS abuse detection, false-positive review, and preservation of raw data for later analysis.

That experience is separate from security operations. This repository documents my transition into Microsoft security tools and detection engineering.

## Day Logs

- [Day 1: Workspace, Connector, and First Detection](logs/day-01.md)

<img width="1568" height="656" alt="First Sentinel analytics rule" src="https://github.com/user-attachments/assets/a90f6cb9-53df-46a3-9cda-41a8d3b0a491" />

# Day 2: July 11, 2026

<img width="902" height="642" alt="Sentinel incident queue with 16 incidents" src="https://github.com/user-attachments/assets/f99cc687-0318-4a4d-8af3-9856036180e2" />

## Data Ingestion Verification

- Confirmed that `AzureActivity` was receiving data.
- Confirmed that `SentinelHealth` contained scheduled analytics-rule execution records.
- Investigated an earlier period with no visible data.
- Determined that the records arrived after a delay during the initial ingestion period.
- Confirmed ingestion the following morning.

## Incident Triage

The rule named `Lab - Azure resource write operations` generated approximately 20 incidents from my own administrative activity, including resource-tag changes.

I reviewed the incidents and identified the following context:

- The activity came from my own account.
- The source IP address matched my known home connection.
- The operation was `MICROSOFT.RESOURCES/TAGS/WRITE`.
- The activity was administrative and expected.

I resolved and classified the incidents based on that evidence.

I did not classify the activity as a false positive because the rule correctly detected the behavior it was designed to identify. The activity occurred, but it was expected and harmless in this lab environment. Treating every harmless alert as a false positive would make later evaluations of the rule less accurate.

## Initial Rule Tuning

The original query was:

```kql
AzureActivity
| where OperationNameValue has "write"

The query returned six records within a 24-hour period, and those records generated incidents.

I added the following exclusion:

| where CallerIpAddress != "<home IP>"

I manually ran the modified query instead of waiting for the next scheduled rule execution. I expected the exclusion to remove all activity from my own administration, but two records remained.

I investigated the remaining records and found that they were related to my own analytics-rule write activity from a different IP address.

This showed a weakness in the exclusion. An IP-based filter is unreliable when the IP address can change. A more stable approach would use specific identifying information, such as the account, operation, and affected resource, instead of excluding all activity from one IP address or account.

I left the IP exclusion in place for this lab and documented its limitation. I have not treated this as production-quality tuning or as proof of improved detection performance.

Ingestion-Delay Query

I prepared the following query to measure the difference between event time and ingestion time:

AzureActivity
| extend delay = ingestion_time() - TimeGenerated
| summarize percentiles(delay, 95, 99)

The final percentile values have not yet been added to this log.

Lessons from Day 2
Sentinel records use UTC.
Eastern Daylight Time is UTC-4, while Eastern Standard Time is UTC-5.
getschema can be used to inspect the available columns in an unfamiliar table.
An empty queue does not always mean that no incidents exist. Filters and exclusions must be checked.
Detection logic should be validated by running the query directly instead of relying only on the scheduled rule cycle.
An exclusion should use the most stable and specific identifier available.
Day 3: KQL Correlation and Baselining
Environment

I used the Azure Data Explorer help cluster and its public RawSysLogs sample data. The dataset contained approximately 885 million records at the time of the exercise.

This was public sample data, not telemetry from my own organization or lab VM.

KQL Practice

I practiced the following techniques:

Used summarize count() by to reduce a large dataset into grouped totals.
Used tostring(tags.host) to extract a value from a dynamic JSON field.
Used join kind=inner to correlate two metric types using a shared hourly time value.
Used bin() to place timestamps into consistent hourly intervals before joining datasets.
Used where timestamp between (X .. Y) to limit results to a defined time window.
Used datetime_part("hour", timestamp) to compare activity by hour of day.
Join Troubleshooting

My first join returned more records than expected because the timestamps were too precise. Events that belonged to the same general period still had different subsecond timestamps.

I corrected the problem by grouping the timestamps into one-hour intervals and joining the datasets on the resulting hourly value.

This exercise demonstrated that two tables can contain related activity without having timestamps that match exactly. The join key must be appropriate for the question being asked.

Baseline Investigation

One hour contained approximately 62,700 requests, while other hours in the selected view contained approximately 451,000.

I considered two possible explanations:

The lower count represented unusual behavior.
The first hour contained only a partial collection period.

I compared the activity by hour of day across the available dataset. The broader comparison showed a consistent hourly pattern of approximately 102,000 records per hour.

The available evidence supported the second explanation. The low count came from a partial collection window rather than a security event.

Lessons from Day 3
I must inspect the schema before relying on a field.
A query against sourceip returned no useful data because that field was not present in the selected dataset.
The host value was available and could be extracted from the tags field.
A high or low count should not be called anomalous until it has been compared with an appropriate baseline.
Partial time windows can create misleading totals.
The basic KQL flow is to select the table, filter the records, choose the necessary fields, summarize the results, and then correlate or expand the data when needed.
Day 4: Detection Logic and Live Investigation
Analytics Rule Review

I enabled additional analytics-rule templates in the Sentinel lab so I could compare different types of detection logic. Before this exercise, the environment contained one custom rule.

I reviewed each rule by asking:

What behavior is the rule designed to detect?
Which data source does it require?
How is it mapped to MITRE ATT&CK?
How often does it run?
How much historical data does it examine?
Why are its frequency and lookback period appropriate for the behavior?
Rule Types Reviewed
Event-Based Rule

My custom rule ran every five minutes with a one-hour lookback period. It was designed to identify individual resource-write operations.

A short execution interval was appropriate because the relevant events could occur at any time and did not require a long historical baseline.

Behavioral Rule

I reviewed the Suspicious Resource Deployment rule, which used a daily schedule and a 14-day lookback period.

The rule attempted to identify unusual resource deployment by a caller who had not commonly performed that activity. A longer lookback period was necessary because the rule needed historical activity to determine whether the caller was rare.

Near-Real-Time Rule

I reviewed an AD FS and Golden SAML detection that used near-real-time processing.

The behavior involved changes to federation trust and identity infrastructure. Because successful abuse could allow forged authentication, the rule was designed to detect the activity quickly rather than waiting for a longer scheduled interval.

Scheduling Lesson

The rule frequency and lookback period should be based on the behavior being detected.

Individual events may support a short lookback and frequent execution.
Behavioral detections may require a longer period of historical activity.
High-impact behavior may justify near-real-time detection.
Some rules run less frequently because of query cost or operational urgency, not because they are establishing a baseline.

I did not enable AD FS or hybrid-identity rules in my lab because I was not collecting the telemetry they required. Enabling a rule without its required data source would not provide meaningful coverage.

Brute-Force Investigation

I investigated an Unauthorized Cloud Region Access alert involving repeated requests to a login endpoint.

I began by reviewing:

The source IP address
The target account
The response codes
The number of attempts
The selected time window
Whether any attempt succeeded
Whether the target account had additional importance or exposure

I then searched the available logs for all activity associated with the source IP address.

My first search returned no results because I used a filter that did not apply correctly to the data. If I had stopped there, I could have incorrectly concluded that the alert was harmless.

After correcting the query, I found 50 attempts from one source IP address against one target in less than one hour.

I also searched for successful authentication activity. That query returned more than 100 successful events, but they belonged to other users and were not tied to the source IP address or time window under investigation.

This demonstrated that a successful login is only relevant to the investigation when it can be connected to the same source, target, and period as the suspected activity.

Based on the available evidence, I classified the activity as a true positive involving an unsuccessful automated brute-force attempt. The attempts were blocked, and I did not find evidence that the source gained access.

My proposed next steps were to block the source IP address, monitor the target account, and search for the same pattern from other IP addresses. These were investigation recommendations, not response actions I performed.

Classification Terms
True positive: The suspicious or malicious behavior occurred, and the detection identified it correctly.
False positive: The detection incorrectly identified activity as suspicious or malicious.
Benign true positive: The detected behavior occurred, but it was authorized, expected, or harmless in the relevant context.
Inconclusive: The available evidence is not sufficient to make a reliable determination.

A blocked brute-force attempt can still be a true positive. The malicious behavior occurred even though the attacker did not successfully gain access.

Detection Engineering 101: July 16–22, 2026

From July 16 through July 22, I spent at least six hours each day studying and practicing Detection Engineering 101. This totaled more than 42 hours of focused work.

My goal was to understand the complete path a detection engineer follows instead of memorizing isolated Microsoft products, tables, event IDs, or KQL syntax.

The workflow I focused on was:

Sources → Telemetry → Data Connectors → Microsoft Sentinel → Log Analytics Tables → Analytics Rules → Alerts → Incidents → Investigation with KQL → Detection Tuning Decision

Sources

Security activity begins with the environment being monitored. Sources can include:

Endpoints
Servers
Identity systems
Network devices
Cloud resources
Applications
Email systems
Users interacting with those systems

These sources perform actions and generate data.

Telemetry

Telemetry is the raw data produced by systems and activity.

Telemetry can show that an event occurred, but it does not automatically explain why it occurred or whether it was malicious. Telemetry alone is not an alert or an incident.

Data Connectors

Data connectors bring telemetry from supported sources into the Sentinel and Log Analytics environment.

If the required connector is missing, misconfigured, or not collecting the necessary data, the detection may not have the evidence it needs to work correctly.

Microsoft Sentinel

Microsoft Sentinel provides SIEM capabilities for collecting, analyzing, correlating, investigating, and responding to security activity.

Sentinel depends on the data being collected. It cannot reliably detect behavior that is not represented in the available telemetry.

Log Analytics Tables

Ingested records are stored in tables based on their source and schema.

Examples I have worked with include:

AzureActivity
SecurityEvent
SentinelHealth
RawSysLogs in the Azure Data Explorer help cluster

Each table contains different fields and represents a different type of activity. I must inspect the schema and understand the data source before writing a useful query.

Analytics Rules

Analytics rules evaluate telemetry using defined detection logic.

The rule describes the behavior or conditions Sentinel should look for. It can include:

Filters
Thresholds
Time windows
Entity mappings
Suppression settings
Exclusions
Scheduling and lookback periods

The rule should be understood before it is changed.

Alerts

An alert can be generated when telemetry matches the conditions defined in an analytics rule.

An alert means the rule found activity that matched its logic. It does not automatically prove that the activity was malicious.

Incidents

Related alerts can be grouped into an incident for investigation.

The incident provides a central place to review the associated alerts, entities, evidence, timeline, severity, status, and investigation notes.

Investigation with KQL

KQL allows me to ask specific questions about the available telemetry.

During an investigation, I can use KQL to:

Define the relevant time window
Identify affected users and devices
Review source IP addresses
Examine successful and failed authentication
Review processes and command lines
Examine parent-child process relationships
Group repeated activity
Reconstruct the sequence of events
Compare current activity with the available baseline

The purpose of the query is not to confirm my first assumption. It is to determine what the evidence supports.

Detection Tuning

Detection tuning should occur after the investigation, not before it.

Before changing a rule, I should determine:

What the rule was designed to detect
Why the rule fired
Whether the detected behavior actually occurred
Whether the activity was malicious, expected, or still unclear
Whether the required telemetry was present
Whether the rule logic was too broad or too narrow
Whether the proposed change would reduce important coverage

Possible changes may include:

Adjusting a threshold
Changing the lookback period
Changing the execution frequency
Narrowing an entity scope
Adding a specific exclusion
Correcting the query logic
Improving entity mapping
Fixing the underlying telemetry collection

Lower alert volume does not automatically mean that a detection improved. A rule that produces fewer alerts may also be missing the behavior it was designed to detect.

Investigation Process
Understand what the detection was designed to identify.
Determine why the rule fired.
Define the relevant user, device, IP address, process, time window, and data sources.
Reconstruct what occurred before, during, and after the detected activity.
Examine the relevant accounts, processes, command lines, IP addresses, logon types, and parent-child relationships.
Compare the activity with the known environment and available baseline.
Determine whether the evidence supports a true positive, false positive, benign true positive, or inconclusive result.
Evaluate whether the detection worked as intended.
Change the detection only when the evidence supports the change.
Document the evidence, conclusion, reasoning, limitations, and remaining questions.
Principles Established
Investigation comes before tuning.
Evidence drives the decision.
An alert is a detection signal, not a verdict.
Missing or incorrect telemetry can cause a detection gap.
The analytics rule is not automatically the source of a missed detection.
Lower alert volume does not automatically mean better detection quality.
A parent process identifies which process initiated a child process. It does not establish intent by itself.
Legitimate tools, including PowerShell, can be used for authorized administration or malicious activity.
The surrounding evidence and operational context determine what the activity means.
A baseline must be specific to the environment being investigated.
A single-VM baseline cannot be treated as an enterprise baseline.
Facts must be separated from assumptions and unresolved questions.
Current Experience Boundary

This training strengthened my understanding of the detection engineering workflow and gave me hands-on practice using Sentinel and KQL in lab environments.

It does not represent production Microsoft Sentinel or Defender XDR experience, validated enterprise detection tuning, or independent ownership of complex security incidents.
