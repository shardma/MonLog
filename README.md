# MonLog

A lightweight cybersecurity logging project focused on Windows endpoint telemetry,
sysmon logs, Python-based parsing, and MITRE ATT&CK mapping

## Goals

- Collect Windows security telemetry with Sysmon
- Parse the exported logs with Python
- Detect suspicious activity
- Map said detections to MITRE ATT&CK techniques
- Document findings

## Tools

- Sysmon
- Python
- Powershell

## Planned Detections

- Encoded Powershell execution
- Powershell downloading remote content
- Suspicious parent-child process relationships
- New local user creation
- Scheduled task persistence
- Failed login spikes