# Installs Sift on Windows and (optionally) registers it to start at logon.
# Run from the folder containing sift.exe:
#   powershell -ExecutionPolicy Bypass -File .\install.ps1
param(
    [string]$InstallDir = "$env:LOCALAPPDATA\Sift",
    [switch]$NoAutostart
)
$ErrorActionPreference = "Stop"

$exe = Join-Path $PSScriptRoot "sift.exe"
if (-not (Test-Path $exe)) { throw "sift.exe not found next to this script." }

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item $exe $InstallDir -Force

$envFile = Join-Path $InstallDir "sift.env"
if (-not (Test-Path $envFile)) {
    Copy-Item (Join-Path $PSScriptRoot "sift.env.example") $envFile
    Write-Host "Created $envFile - fill in your settings and Jev key."
}

# Lock the config down to the current user only (it holds secrets).
icacls $envFile /inheritance:r /grant:r "$($env:USERNAME):(R,W)" | Out-Null

if (-not $NoAutostart) {
    $action  = New-ScheduledTaskAction -Execute (Join-Path $InstallDir "sift.exe") -WorkingDirectory $InstallDir
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    $settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5) -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask -TaskName "Sift Mail Triage" -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
    Write-Host "Registered scheduled task 'Sift Mail Triage' (starts at logon)."
}

Write-Host ""
Write-Host "Installed to $InstallDir"
Write-Host "Next: edit sift.env, then test with:  cd `"$InstallDir`"; .\sift.exe"
