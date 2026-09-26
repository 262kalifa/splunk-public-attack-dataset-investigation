# Windows Sysmon Threat Investigation & Detection Engineering in Splunk

## Overview

This project documents a structured investigation of a public Windows Sysmon attack-simulation dataset in Splunk.

The analysis progressed from broad telemetry review to suspicious PowerShell activity, Windows service creation, registry modification, file creation, SYSTEM-level process execution, MITRE ATT&CK mapping, and development of a reusable Splunk detection.

The primary finding was activity consistent with a controlled simulation of **MITRE ATT&CK T1574.009 – Path Interception by Unquoted Path**.

## Project Highlights

- Investigated **10,290 Sysmon events** in Splunk.
- Analyzed repeated PowerShell `EncodedCommand` execution.
- Reconstructed process and service activity across multiple Sysmon event types.
- Identified an unquoted Windows service path.
- Confirmed `C:\Program.exe` execution by `services.exe` as `NT AUTHORITY\SYSTEM`.
- Correlated the activity with Atomic Red Team `T1574.009` references.
- Built a reusable SPL detection for suspicious service-launched executables.
- Produced an investigation report, evidence set, ATT&CK mapping, and detection query library.

## Tools and Technologies

- Splunk Enterprise
- Windows Sysmon
- SPL
- PowerShell
- Windows process and registry telemetry
- MITRE ATT&CK
- Atomic Red Team public attack data

## Dataset

**Source:** Splunk Attack Data – First Time Windows Service

The imported dataset contained **10,290 Sysmon events**.

```text
Index:      attack_data
Sourcetype: XmlWinEventLog
Host:       win-dc-533.attackrange.local
```

The raw public dataset is intentionally excluded from this repository. The repository contains the investigation artifacts, queries, evidence, and reports produced from the analysis.

## Investigation Workflow

```text
Dataset validation
        ↓
Sysmon event review
        ↓
Process creation analysis
        ↓
Encoded PowerShell investigation
        ↓
Payload extraction and decoding
        ↓
Process-chain reconstruction
        ↓
Windows service and registry analysis
        ↓
C:\Program.exe creation and execution
        ↓
Consolidated activity timeline
        ↓
MITRE ATT&CK mapping
        ↓
Reusable Splunk detection
```

## Primary Finding

A Windows service named `Example Service` was configured with:

```text
C:\Program Files\windows_service.exe
```

The path contained a space and was not quoted.

Sysmon later recorded:

```text
Parent Process: services.exe
Process:        program.exe
Image:          C:\Program.exe
Command Line:   C:\Program Files\windows_service.exe
User:           NT AUTHORITY\SYSTEM
```

The mismatch between the configured service command line and the executable that actually ran is consistent with **path interception through an unquoted service path**.

The dataset also contained an Atomic Red Team reference to:

```text
C:\AtomicRedTeam\atomics\T1574.009\
```

That context supports interpreting the behavior as controlled attack simulation rather than confirmed real-world malware.

## Supporting Investigation Findings

### Encoded PowerShell

Repeated PowerShell processes used `EncodedCommand`. Selected Base64 content was extracted and decoded during analysis.

Encoded PowerShell was treated as a security-relevant indicator, not as proof of malicious activity by itself.

### Service and Registry Activity

Registry telemetry identified the `Example Service` `ImagePath`, and service-control activity showed creation, startup, stop, and deletion of the service.

### File and Process Evidence

The investigation correlated:

- creation of `C:\Program.exe`
- service startup
- execution by `services.exe`
- SYSTEM execution context
- subsequent service cleanup

This provided stronger evidence than relying on a single process event.

## MITRE ATT&CK Mapping

| Observed Behavior | ATT&CK Technique |
|---|---|
| Unquoted service path resulted in `C:\Program.exe` execution | **T1574.009 – Path Interception by Unquoted Path** |
| PowerShell with `EncodedCommand` | **T1059.001 – PowerShell** |
| `cmd.exe` command execution | **T1059.003 – Windows Command Shell** |
| Windows service creation and execution | **T1543.003 – Windows Service** |
| `whoami.exe` execution | **T1033 – System Owner/User Discovery** |

The detailed mapping is available in [reports/18_mitre_attack_mapping.md](./reports/18_mitre_attack_mapping.md).

## Detection Engineering

After the investigation, a reusable Splunk detection was created for suspicious executables launched by `services.exe` directly from the root of a drive.

The detection is designed around behavior rather than hard-coding only `C:\Program.exe`.

In this dataset, it identified:

```text
services.exe → C:\Program.exe
User: NT AUTHORITY\SYSTEM
```

Detection query:

[19_unquoted_service_path_detection.spl](./splunk_queries/19_unquoted_service_path_detection.spl)

The detection is a lab rule and would require tuning and validation before production use.

## Selected Evidence

Key screenshots include:

- [Suspicious encoded PowerShell](./screenshots/05_suspicious_powershell_encoded_commands.png)
- [Decoded PowerShell wrapper](./screenshots/07_decoded_powershell_wrapper_command.png)
- [Service ImagePath registry changes](./screenshots/13b_service_imagepath_registry_changes.png)
- [Windows service investigation summary](./screenshots/14_windows_service_exe_investigation_summary.png)
- [Program.exe service execution](./screenshots/15_program_exe_service_execution.png)
- [Final activity timeline](./screenshots/17_final_attack_timeline.png)
- [Unquoted service-path detection](./screenshots/19_unquoted_service_path_detection.png)

## Reports

- [Full investigation report](./investigation_report.md)
- [MITRE ATT&CK mapping](./reports/18_mitre_attack_mapping.md)
- [PDF investigation report](./reports/Windows_Sysmon_Threat_Investigation_Report.pdf)

## Repository Structure

```text
splunk-public-attack-dataset-investigation/
├── README.md
├── investigation_report.md
├── .gitignore
├── reports/
│   ├── 18_mitre_attack_mapping.md
│   └── Windows_Sysmon_Threat_Investigation_Report.pdf
├── screenshots/
│   └── investigation evidence
└── splunk_queries/
    └── reusable investigation and detection SPL
```

## Skills Demonstrated

- Splunk investigation workflow
- Windows Sysmon analysis
- SPL development and field extraction
- PowerShell investigation
- Base64 decoding
- process-chain analysis
- Windows service analysis
- registry telemetry analysis
- timeline reconstruction
- MITRE ATT&CK mapping
- detection engineering
- evidence-based technical reporting

## Analyst Takeaway

This project reinforced the importance of moving from **single suspicious events to correlated evidence**.

The strongest conclusion did not come from encoded PowerShell or a single service event. It came from correlating process, file, registry, service-control, and execution-context evidence into one defensible timeline.

## Status

**Completed.** Investigation artifacts, ATT&CK mapping, supporting evidence, reusable SPL queries, and the detection rule are documented in this repository.
