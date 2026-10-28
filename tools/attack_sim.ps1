<#
.SYNOPSIS
    SOC-Lite Harmless Detection Simulation Script (LAB USE ONLY)
.DESCRIPTION
    Triggers Windows audit events to validate SOC-Lite detection rules:
    - 4625 Failed Logon Burst (SOC-001)
    - 4720 / 4732 User Creation & Admin Group Add (SOC-003, SOC-004, SOC-014)
    - Encoded PowerShell (SOC-007)
    - Service Creation (SOC-006)
    - Scheduled Task Creation (SOC-009)
#>

Write-Host "==========================================================" -ForegroundColor Red
Write-Host "                *** SOC-LITE TESTING ***                  " -ForegroundColor Yellow
Write-Host "               LAB AND EVALUATION USE ONLY                " -ForegroundColor Red
Write-Host "==========================================================" -ForegroundColor Red
Write-Host "This script executes safe, benign commands designed to generate"
Write-Host "Windows Event Log entries matching SOC-Lite detection rules."
Write-Host ""

$confirm = Read-Host "Are you running this inside a TEST / LAB environment? (y/N)"
if ($confirm -ne 'y' -and $confirm -ne 'Y') {
    Write-Host "Simulation aborted by user." -ForegroundColor Gray
    exit 0
}

Write-Host "`n[1/5] Simulating Failed Logon Burst (SOC-001)..." -ForegroundColor Cyan
1..8 | ForEach-Object {
    net use \\127.0.0.1\IPC$ /user:soc_sim_dummy_user WrongPassword123! 2>$null
    Start-Sleep -Milliseconds 200
}

Write-Host "[2/5] Simulating User Creation & Admin Group Addition (SOC-003, SOC-004, SOC-014)..." -ForegroundColor Cyan
net user soc_test_user 'Pass#1234_LabTest!' /add 2>$null
net localgroup Administrators soc_test_user /add 2>$null
Start-Sleep -Seconds 2
Write-Host "  -> Cleaning up test user account..." -ForegroundColor DarkGray
net localgroup Administrators soc_test_user /delete 2>$null
net user soc_test_user /delete 2>$null

Write-Host "[3/5] Simulating Encoded PowerShell Command (SOC-007)..." -ForegroundColor Cyan
$testPayload = 'Write-Output "SOC-Lite harmless encoded test"'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($testPayload)
$encoded = [System.Convert]::ToBase64String($bytes)
powershell.exe -NoProfile -NonInteractive -EncodedCommand $encoded

Write-Host "[4/5] Simulating Service Installation (SOC-006)..." -ForegroundColor Cyan
sc.exe create SocLiteLabSvc binPath= "C:\Windows\System32\cmd.exe /c echo soc_test" 2>$null
Start-Sleep -Seconds 1
sc.exe delete SocLiteLabSvc 2>$null

Write-Host "[5/5] Simulating Scheduled Task Creation (SOC-009)..." -ForegroundColor Cyan
schtasks.exe /create /tn "SocLiteLabTask" /tr "cmd.exe /c echo test" /sc once /st 23:59 /f 2>$null
Start-Sleep -Seconds 1
schtasks.exe /delete /tn "SocLiteLabTask" /f 2>$null

Write-Host "`nSimulation complete. Check your SOC-Lite live dashboard at http://127.0.0.1:8000" -ForegroundColor Green
