# Detection Rules Catalog

SOC-Lite implements 14 behavioral and signature detection rules covering key stages of the MITRE ATT&CK framework.

| ID | Name | Severity | MITRE Tactic / Technique | Target Events | Detection Logic |
|---|---|---|---|---|---|
| **SOC-001** | Brute-force logon failures | High | Credential Access / [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Security 4625 | ≥ 5 failed logons for same source IP in 60s. Falls back to target user + host for local brute force. |
| **SOC-002** | Successful logon after failures | Critical | Credential Access / [T1110](https://attack.mitre.org/techniques/T1110/) | Security 4624 | Successful logon (4624) by an IP or user that had ≥ 5 failures within prior 5 minutes. |
| **SOC-003** | Local user account created | Medium / High | Persistence / [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Security 4720 | Event 4720. High if created by non-standard admin or account ends with `$` (hidden/service account). |
| **SOC-004** | User added to privileged group | High | Privilege Escalation / [T1098](https://attack.mitre.org/techniques/T1098/) | Security 4728, 4732, 4756 | Added to group with SID `S-1-5-32-544` or matching Administrators/Domain Admins. |
| **SOC-005** | Audit log cleared | Critical | Defense Evasion / [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | Security 1102, System 104 | Intentional clearing of Windows Security or System audit logs. |
| **SOC-006** | New service installed | Medium / High | Persistence / [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | System 7045, Security 4697 | Service registration. High if path is in `\Temp\`, `\AppData\`, `\Users\Public\`, or invokes cmd/powershell. |
| **SOC-007** | Encoded / obfuscated PowerShell | High | Execution / [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Security 4688, Sysmon 1 | PowerShell executed with `-EncodedCommand` base64 payload or hidden execution cradle. Decodes preview in alert. |
| **SOC-008** | LOLBin abuse for download/proxy | High | Defense Evasion / [T1218](https://attack.mitre.org/techniques/T1218/) | Security 4688, Sysmon 1 | Suspicious flags on certutil, bitsadmin, mshta, regsvr32, rundll32, curl/wget. |
| **SOC-009** | Scheduled task created | Medium / High | Persistence / [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Security 4698, schtasks /create | Scheduled task registered. High if task command invokes cmd/powershell/wscript. |
| **SOC-010** | LSASS memory access | Critical | Credential Access / [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | Sysmon 10 | Target image is `lsass.exe` with access mask `0x1010, 0x1410, 0x1438, 0x143a, 0x1fffff` from non-allowlisted binary. |
| **SOC-011** | Account lockout | Medium | Credential Access / [T1110](https://attack.mitre.org/techniques/T1110/) | Security 4740 | Windows account lockout event following threshold password failures. |
| **SOC-012** | Defender protection disabled | High | Defense Evasion / [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Defender 5001/5010/5012, 4688 | Real-time protection disabled via Defender event or `Set-MpPreference` / `sc stop WinDefend`. |
| **SOC-013** | Suspicious parent-child process | High | Execution / [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Security 4688, Sysmon 1 | Office suite process (Word, Excel, Outlook) spawning shell or script interpreters (cmd, powershell, wscript). |
| **SOC-014** | Rapid new-account + admin add chain | Critical | Persistence / [T1136.001](https://attack.mitre.org/techniques/T1136/001/) + [T1098](https://attack.mitre.org/techniques/T1098/) | Security 4720 + 4732 | Correlated: New user created (4720) and elevated to Administrators within 10 minutes. |
