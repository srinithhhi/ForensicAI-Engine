# Windows VM setup (Scope 2)

One-time configuration steps for the Windows 10 VM that hosts ForensicAI-Engine's
Scope 2 acquirer and simulation runner.

## Prerequisites (manual, one-time)

These steps require interactive console access (VMware UI or RDP). They cannot
be automated because they're guarded by Windows Security UI.

1. **Velociraptor agent** — installed and registered (`C.e68c726ce1daa77e`).
2. **Sysmon** + SwiftOnSecurity config — running as `Sysmon64`.
3. **Tamper Protection: OFF** — Windows Security → Virus & threat protection →
   Manage settings → Tamper Protection: Off. Required for the Defender disable
   script below to actually take effect (otherwise Defender silently ignores
   `Set-MpPreference` even from an elevated session).

## Automated setup

### 1. OpenSSH server + authorized key

Run once via Velociraptor (see the OpenSSH install in the project commit log
or save the relevant Velociraptor PowerShell artifact). After this:

```bash
ssh -i ~/.ssh/forensicai_key admin@<SCOPE2_IP>
```

succeeds and SCOPE2_IP/SCOPE2_CLIENT_ID are in `config/.env`.

### 2. PowerShell 7 + Invoke-AtomicRedTeam module + atomics

```powershell
# Inside a PowerShell session ON the Windows VM (admin):
# (this script is at host_setup/windows/install_pwsh_atomics.ps1; scp it over
#  to C:\Temp\install_pwsh_atomics.ps1 then run it.)
Set-ExecutionPolicy -Scope Process Bypass -Force
& C:\Temp\install_pwsh_atomics.ps1
```

End state:
- `C:\Program Files\PowerShell\7\pwsh.exe` exists, `pwsh -v` returns 7.x
- `invoke-atomicredteam` module installed AllUsers (visible from pwsh 7)
- `C:\AtomicRedTeam\atomics` populated with the technique YAMLs

### 3. Defender — disable before harness runs

```powershell
& C:\Temp\disable_defender_for_testing.ps1
```

Run `enable_defender.ps1` after the harness completes. **Tamper Protection must
be off** (prerequisite #3) or `Set-MpPreference` silently does nothing.

## File map

| Script | Purpose | Run once / each time? |
|---|---|---|
| `install_pwsh_atomics.ps1` | pwsh 7 + Invoke-AtomicTest module + atomics | once |
| `disable_defender_for_testing.ps1` | Bypass Defender for the harness window | before each harness run |
| `enable_defender.ps1` | Restore Defender | after each harness run |

## Harness invocation

After all setup above, from the Mac:

```bash
python tests/run_attack_and_acquire_windows.py
```

Runs the v0 6-pack (T1136.001#4, T1547.001#1, T1543.003#2, T1053.005#1,
T1105#10, T1003.001#2), acquires the bundle, cleans up.
