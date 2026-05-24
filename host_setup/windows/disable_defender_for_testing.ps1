# Temporarily disable Windows Defender real-time + behaviour monitoring so
# the v0 atomic tests (T1003.001 LSASS dump in particular) can execute.
# Re-enable with enable_defender.ps1 after the harness run.
#
# PREREQ: Tamper Protection must be disabled FIRST via Windows Security UI:
#   Settings -> Privacy & Security -> Windows Security -> Virus & threat
#   protection -> Manage settings -> Tamper Protection: Off
# Without that, Set-MpPreference silently no-ops (status returns success but
# the flags don't change).
#
# Run as Administrator. Idempotent.

$ErrorActionPreference = 'Stop'

Write-Host '[defender] disabling realtime + behavior monitoring...'
Set-MpPreference -DisableRealtimeMonitoring  $true
Set-MpPreference -DisableBehaviorMonitoring  $true
Set-MpPreference -DisableIOAVProtection      $true
Set-MpPreference -DisableScriptScanning      $true

Write-Host '[defender] adding path exclusion for C:\AtomicRedTeam...'
Add-MpPreference -ExclusionPath 'C:\AtomicRedTeam' -ErrorAction SilentlyContinue

$prefs = Get-MpPreference
[ordered]@{
    RealtimeMonitoring  = -not $prefs.DisableRealtimeMonitoring
    BehaviorMonitoring  = -not $prefs.DisableBehaviorMonitoring
    IOAVProtection      = -not $prefs.DisableIOAVProtection
    ScriptScanning      = -not $prefs.DisableScriptScanning
    ExclusionPathsCount = $prefs.ExclusionPath.Count
} | ConvertTo-Json

Write-Host ''
Write-Host '[defender] If any of the *Monitoring fields above are still True,'
Write-Host '[defender] Tamper Protection is still on — disable it via the'
Write-Host '[defender] Windows Security UI and re-run this script.'
