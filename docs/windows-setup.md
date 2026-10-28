# Windows VM Prerequisites & Setup Guide

To enable the Windows Event Logs required for the full SOC-Lite detection catalog, run an elevated PowerShell session (**Run as Administrator**) on your Windows 10/11 or Server VM:

### 1. Enable Advanced Audit Policies
```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Account Lockout" /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable   # scheduled tasks (4698)
auditpol /set /subcategory:"Security System Extension" /success:enable                    # service install (4697)
auditpol /set /subcategory:"Special Logon" /success:enable
```

### 2. Enable Command Line in Process Creation (4688)
```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

### 3. Enable PowerShell Script Block Logging (4104)
```powershell
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
```

### 4. Install & Configure Sysmon
Download Microsoft Sysinternals Sysmon:
```powershell
# Using community recommended config:
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```
Verify:
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 3
```

### 5. Expand Security Log Size
Prevent log turnover during high-volume testing:
```powershell
wevtutil sl Security /ms:268435456
```
