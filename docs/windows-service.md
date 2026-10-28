# Running SOC-Lite Agent as a Windows Background Service

To run the SOC-Lite collector continuously in production or dedicated lab setups without keeping a console open:

## Option A: Using NSSM (Non-Sucking Service Manager)

1. Download `nssm` from `https://nssm.cc/download`.
2. Extract `nssm.exe` to a directory (e.g. `C:\tools\nssm.exe`).
3. In an Administrator PowerShell terminal, install the service:
```powershell
nssm install SocLiteAgent "C:\path\to\python.exe" "-m agent.collector --config C:\path\to\config.yaml"
nssm set SocLiteAgent AppDirectory "C:\path\to\soc-lite"
nssm set SocLiteAgent Description "SOC-Lite Windows Event Log Shipper"
nssm start SocLiteAgent
```
4. Verify service status:
```powershell
Get-Service SocLiteAgent
```

## Option B: Using Windows Task Scheduler

1. Create a Scheduled Task running as `NT AUTHORITY\SYSTEM` with highest privileges:
```powershell
$action = New-ScheduledTaskAction -Execute "C:\path\to\python.exe" -Argument "-m agent.collector --config C:\path\to\config.yaml" -WorkingDirectory "C:\path\to\soc-lite"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "SocLiteCollector" -Action $action -Trigger $trigger -Principal $principal
```
2. Start the task immediately:
```powershell
Start-ScheduledTask -TaskName "SocLiteCollector"
```
