# Re-enable Windows Defender after a harness run. Inverse of
# disable_defender_for_testing.ps1.

$ErrorActionPreference = 'Stop'

Set-MpPreference -DisableRealtimeMonitoring  $false
Set-MpPreference -DisableBehaviorMonitoring  $false
Set-MpPreference -DisableIOAVProtection      $false
Set-MpPreference -DisableScriptScanning      $false

$prefs = Get-MpPreference
[ordered]@{
    RealtimeMonitoring = -not $prefs.DisableRealtimeMonitoring
    BehaviorMonitoring = -not $prefs.DisableBehaviorMonitoring
    IOAVProtection     = -not $prefs.DisableIOAVProtection
    ScriptScanning     = -not $prefs.DisableScriptScanning
} | ConvertTo-Json
