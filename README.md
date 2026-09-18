# Intermediate SOC Investigation Using Public Attack Data in Splunk

This project documents an intermediate SOC investigation using a public Windows Sysmon attack dataset in Splunk.

The investigation progressed from broad event review to suspicious PowerShell analysis, Windows service investigation, SYSTEM-level process execution, MITRE ATT&CK mapping, and detection engineering.

## Project Summary

The investigation identified activity consistent with a controlled simulation of **MITRE ATT&CK T1574.009 – Path Interception by Unquoted Path**.

Key evidence included:

- repeated PowerShell `EncodedCommand` execution;
- remote shell and command-shell activity;
- creation of a Windows service named `Example Service`;
- an unquoted service path: `C:\Program Files\windows_service.exe`;
- creation of `C:\Program.exe`;
- execution of `C:\Program.exe` by `services.exe`;
- execution under `NT AUTHORITY\SYSTEM`;
- Atomic Red Team references to `T1574.009`;
- a Splunk detection rule for similar service-path behavior.

## Tools and Technologies

- Splunk Enterprise
- Windows Sysmon
- SPL
- PowerShell
- Windows Registry analysis
- MITRE ATT&CK
- Atomic Red Team attack data

## Dataset

Source: Splunk Attack Data – First Time Windows Service

The imported dataset contained **10,290 Sysmon events** and was stored in the Splunk index:

```text
attack_data
```

Sourcetype:

```text
XmlWinEventLog
```

Investigated host:

```text
win-dc-533.attackrange.local
```

## Investigation Flow

```text
Dataset validation
        ↓
Process creation review
        ↓
Suspicious PowerShell EncodedCommand activity
        ↓
Encoded payload extraction and decoding
        ↓
Process-chain investigation
        ↓
Windows service registry analysis
        ↓
Example Service investigation
        ↓
C:\Program.exe creation
        ↓
SYSTEM-level execution through services.exe
        ↓
Final activity timeline
        ↓
MITRE ATT&CK mapping
        ↓
Reusable Splunk detection
```

## Key Finding

The strongest evidence showed:

```text
Parent Process: services.exe
Process:        program.exe
Image:          C:\Program.exe
Command Line:   C:\Program Files\windows_service.exe
User:           NT AUTHORITY\SYSTEM
```

This mismatch between the configured service command line and the actual process image is consistent with simulated **unquoted service-path / path-interception behavior**.

The dataset also contained the following Atomic Red Team reference:

```text
C:\AtomicRedTeam\atomics\T1574.009\
```

This supports the conclusion that the activity was attack-simulation activity rather than confirmed real-world malware.

## MITRE ATT&CK Mapping

| Observed Behavior | ATT&CK Technique |
|---|---|
| Unquoted path led to `C:\Program.exe` execution | T1574.009 – Path Interception by Unquoted Path |
| PowerShell with `EncodedCommand` | T1059.001 – PowerShell |
| `cmd.exe` command execution | T1059.003 – Windows Command Shell |
| Windows service creation and execution | T1543.003 – Windows Service |
| `whoami.exe` user discovery | T1033 – System Owner/User Discovery |

## Detection Engineering

A reusable Splunk detection was created to identify suspicious executables launched by `services.exe` directly from the root of a drive.

The detection successfully identified:

```text
services.exe -> C:\Program.exe
User: NT AUTHORITY\SYSTEM
Severity: High
```

The detection query is available at:

```text
splunk_queries/19_unquoted_service_path_detection.spl
```

## Repository Structure

```text
splunk-public-attack-dataset-investigation/
├── README.md
├── investigation_report.md
├── Project_4_SOC_Investigation_Report_Final.pdf
├── reports/
│   └── 18_mitre_attack_mapping.md
├── screenshots/
│   ├── 01_attack_data_import_confirmed.png
│   ├── 02_sysmon_event_codes_summary.png
│   ├── 03_process_creation_events.png
│   ├── ...
│   ├── 17_final_attack_timeline.png
│   └── 19_unquoted_service_path_detection.png
├── splunk_queries/
│   ├── 01_existing_logs.spl
│   ├── ...
│   └── 19_unquoted_service_path_detection.spl
└── dataset/
```

> The dataset folder can be excluded from GitHub if the raw log file is large or if you prefer to link to the public source instead.

## Main Evidence

Important screenshots include:

- `05_suspicious_powershell_encoded_commands.png`
- `07_decoded_powershell_wrapper_command.png`
- `13b_service_imagepath_registry_changes.png`
- `14_windows_service_exe_investigation_summary.png`
- `15_program_exe_service_execution.png`
- `17_final_attack_timeline.png`
- `19_unquoted_service_path_detection.png`

## Report

The full investigation report is available in:

```text
investigation_report.md
```

and:

```text
Project_4_SOC_Investigation_Report_Final.pdf
```

## Skills Demonstrated

- Splunk investigation workflow
- Sysmon log analysis
- SPL field extraction
- Process-chain analysis
- PowerShell investigation
- Base64 decoding
- Windows service analysis
- Registry analysis
- Timeline reconstruction
- MITRE ATT&CK mapping
- SOC documentation
- Detection engineering

## Conclusion

This project demonstrates the progression from identifying suspicious activity to validating evidence, reconstructing the attack sequence, mapping the behavior to MITRE ATT&CK, and developing a reusable Splunk detection.

The project is based on a public attack-simulation dataset and should be interpreted as a defensive investigation lab rather than a real-world incident response case.
