# MITRE ATT&CK Mapping

The investigation identified several behaviors that map to MITRE ATT&CK techniques.

| Observed Activity | MITRE ATT&CK Technique |
|---|---|
| Unquoted service path resulted in `C:\Program.exe` execution | T1574.009 – Path Interception by Unquoted Path |
| PowerShell executed with `EncodedCommand` | T1059.001 – PowerShell |
| `cmd.exe` was used for copy and service commands | T1059.003 – Windows Command Shell |
| `sc.exe` created and started `Example Service` | T1543.003 – Windows Service |
| `whoami.exe` was executed | T1033 – System Owner/User Discovery |

## Primary Finding

The primary technique identified was **T1574.009 – Path Interception by Unquoted Path**.

The service `Example Service` was configured with the unquoted path:

`C:\Program Files\windows_service.exe`

The investigation later confirmed that:

- `C:\Program.exe` was created;
- the service was started;
- `services.exe` launched `C:\Program.exe`;
- the process executed under `NT AUTHORITY\SYSTEM`.

This provides strong evidence of simulated unquoted service-path exploitation.

## Supporting Techniques

Additional activity observed during the investigation included:

- PowerShell execution with `EncodedCommand`;
- Windows Command Shell activity;
- Windows service creation and execution;
- user discovery using `whoami.exe`.

Because the dataset contained Atomic Red Team references, the activity is assessed as attack-simulation activity rather than confirmed real-world malware.
