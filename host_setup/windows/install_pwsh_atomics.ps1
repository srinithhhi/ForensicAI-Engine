# Phase 2 prep — install PowerShell 7, Invoke-AtomicRedTeam module, atomics
# folder. Idempotent: safe to re-run.
#
# Invoke via SSH (from Mac):
#   ssh -i ~/.ssh/forensicai_key admin@<scope2_ip> \
#       'powershell -ExecutionPolicy Bypass -File C:\Temp\install_pwsh_atomics.ps1'

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host '=== Stage 1: PowerShell 7 ==='
$pwshExe = 'C:\Program Files\PowerShell\7\pwsh.exe'
if (-not (Test-Path $pwshExe)) {
    Write-Host 'Installing pwsh 7 via winget (this may take 3-8 min)...'
    winget install --id Microsoft.PowerShell --silent --scope machine `
        --accept-package-agreements --accept-source-agreements
} else {
    Write-Host 'pwsh 7 already installed.'
}
if (-not (Test-Path $pwshExe)) {
    throw 'pwsh 7 install failed — winget did not place pwsh.exe at expected path.'
}
$ver = & $pwshExe -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'
Write-Host "pwsh 7 version: $($ver.Trim())"

Write-Host ''
Write-Host '=== Stage 2: Invoke-AtomicRedTeam module (inside pwsh 7) ==='
& $pwshExe -NoProfile -Command @'
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if ((Get-PSRepository -Name PSGallery).InstallationPolicy -ne 'Trusted') {
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
}
if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
    Install-PackageProvider -Name NuGet -Force -Scope AllUsers | Out-Null
}
if (-not (Get-Module -ListAvailable -Name invoke-atomicredteam)) {
    Install-Module -Name invoke-atomicredteam -Scope AllUsers -Force -AllowClobber
    Write-Host '  module installed.'
} else {
    Write-Host '  module already installed.'
}
'@

Write-Host ''
Write-Host '=== Stage 3: Atomics folder ==='
$atomicsPath = 'C:\AtomicRedTeam\atomics'
if (-not (Test-Path $atomicsPath)) {
    & $pwshExe -NoProfile -Command @"
`$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Import-Module invoke-atomicredteam -Force
Install-AtomicsFolder -InstallPath '$atomicsPath' -Force
"@
} else {
    Write-Host 'Atomics folder already exists.'
}
$techniqueCount = (Get-ChildItem $atomicsPath -Directory -Filter 'T*' -ErrorAction SilentlyContinue | Measure-Object).Count
Write-Host "  atomics technique folders: $techniqueCount"

Write-Host ''
Write-Host '=== DONE ==='
[ordered]@{
    pwsh7 = (Test-Path $pwshExe)
    module = ([bool](& $pwshExe -NoProfile -Command "Get-Module -ListAvailable -Name invoke-atomicredteam"))
    atomics_path = $atomicsPath
    atomics_exists = (Test-Path $atomicsPath)
    technique_count = $techniqueCount
} | ConvertTo-Json
