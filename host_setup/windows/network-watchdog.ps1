<#
.SYNOPSIS
  Network connectivity watchdog for the Windows Scope 2 VM.

.DESCRIPTION
  Why this exists: the VM lives on a bridged adapter on a Mac host. When the
  Mac sleeps, the bridge can lose its link binding and the VM ends up running
  with no network — the Velociraptor agent stops checking in. This watchdog
  pings the gateway every 30s and restarts the active network adapter after
  3 consecutive failures.

  Single self-installing script. Run once as Administrator:
      powershell.exe -ExecutionPolicy Bypass -File network-watchdog.ps1
  …and it copies itself to C:\ProgramData\ForensicAI\, registers a scheduled
  task that runs at startup as SYSTEM, then starts the task immediately.

  When invoked by the scheduled task (-Mode Run), it enters the watchdog loop.

.PARAMETER Mode
  Install (default) — self-install as a scheduled task.
  Run               — execute the watchdog loop (used by the scheduled task).
#>
param(
    [ValidateSet('Install','Run')]
    [string]$Mode = 'Install',

    [string]$Gateway = '192.168.1.1',
    [int]$IntervalSeconds = 30,
    [int]$FailThreshold = 3,
    [int]$RecoveryCooldownSeconds = 15
)

$ErrorActionPreference = 'Continue'
$TaskName = 'ForensicAI Network Watchdog'
$InstallDir = 'C:\ProgramData\ForensicAI'
$InstalledScript = Join-Path $InstallDir 'network-watchdog.ps1'
$EventSource = 'NetworkWatchdog'

function Initialize-EventSource {
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
            New-EventLog -LogName Application -Source $EventSource -ErrorAction Stop
        }
    } catch {
        # New-EventLog requires admin; if scheduled task ever runs without admin
        # we silently fall back to no-op logging.
    }
}

function Write-WatchdogLog {
    param([string]$Message, [string]$EntryType = 'Information', [int]$EventId = 1000)
    try {
        Write-EventLog -LogName Application -Source $EventSource -EntryType $EntryType -EventId $EventId -Message $Message -ErrorAction Stop
    } catch {
        # event source not registered — fall back to stdout (visible if user
        # manually runs `-Mode Run` from a console)
        Write-Host "[$EntryType] $Message"
    }
}

function Invoke-Install {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Install must run as Administrator.'
    }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item -Path $PSCommandPath -Destination $InstalledScript -Force
    Initialize-EventSource

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -File `"$InstalledScript`" -Mode Run -Gateway $Gateway -IntervalSeconds $IntervalSeconds -FailThreshold $FailThreshold"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -StartWhenAvailable `
        -RestartCount 999 `
        -RestartInterval (New-TimeSpan -Minutes 1)

    Register-ScheduledTask -TaskName $TaskName `
        -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
        -Description "Pings $Gateway every ${IntervalSeconds}s. Restarts network adapter after $FailThreshold consecutive failures." `
        -Force | Out-Null

    Start-ScheduledTask -TaskName $TaskName
    Write-Host "watchdog installed to $InstalledScript"
    Write-Host "scheduled task '$TaskName' registered and started"
    Write-Host "verify with: Get-ScheduledTask -TaskName '$TaskName'"
    Write-Host "logs:        Get-EventLog -LogName Application -Source $EventSource -Newest 20"
}

function Invoke-WatchdogLoop {
    Initialize-EventSource
    Write-WatchdogLog "started — gateway=$Gateway interval=${IntervalSeconds}s threshold=$FailThreshold"

    $failures = 0
    while ($true) {
        $ok = Test-Connection -ComputerName $Gateway -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($ok) {
            if ($failures -gt 0) {
                Write-WatchdogLog "gateway $Gateway reachable again after $failures failure(s); resetting"
            }
            $failures = 0
        } else {
            $failures++
            Write-WatchdogLog "gateway $Gateway unreachable (failure $failures/$FailThreshold)" 'Warning' 1001
            if ($failures -ge $FailThreshold) {
                Write-WatchdogLog 'restarting active network adapter(s)' 'Warning' 1002
                try {
                    Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } |
                        Restart-NetAdapter -Confirm:$false -ErrorAction Stop
                    Write-WatchdogLog 'adapter restart succeeded' 'Information' 1003
                } catch {
                    Write-WatchdogLog "adapter restart failed: $_" 'Error' 1004
                }
                $failures = 0
                Start-Sleep -Seconds $RecoveryCooldownSeconds
            }
        }
        Start-Sleep -Seconds $IntervalSeconds
    }
}

switch ($Mode) {
    'Install' { Invoke-Install }
    'Run'     { Invoke-WatchdogLoop }
}
