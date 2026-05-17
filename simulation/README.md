# simulation/ — Adversary emulation (dev-only)

Drives Atomic Red Team techniques against the Scope 1 Ubuntu VM over SSH and
writes a manifest that shares `incident_id` with the acquisition bundle.

**Not invoked by the orchestrator.** Only the dev harness
`tests/run_attack_and_acquire.py` calls this module.

## One-time setup on the Ubuntu VM (192.168.1.10)

### 1. Install PowerShell Core

```bash
sudo snap install powershell --classic
# verify
pwsh -Command '$PSVersionTable.PSVersion'
```

### 2. Install the invoke-atomicredteam module

```bash
pwsh -Command "Install-Module -Name invoke-atomicredteam -Scope CurrentUser -Force"
# verify
pwsh -Command "Get-Module -ListAvailable invoke-atomicredteam"
```

### 3. Verify atomics path

The runner expects atomics at `/home/admin/atomic-red-team/atomics` (per
`CONTEXT.md`). Override with `ATOMICS_PATH` in `config/.env` if different.

```bash
ls /home/admin/atomic-red-team/atomics | head
```

### 4. SSH key + sudo

Confirm `SCOPE1_USER` can SSH from the Mac with `SCOPE1_SSH_KEY` (no password).
Some atomics require `sudo`; configure `NOPASSWD` for the specific binaries
each technique invokes (do **not** grant blanket NOPASSWD).

## Configuration

`config/.env` keys read by this module:

- `SCOPE1_IP` — VM IP
- `SCOPE1_USER` — SSH user
- `SCOPE1_SSH_KEY` — path to private key
- `ATOMICS_PATH` — atomics folder on the VM (optional, defaults to `/home/admin/atomic-red-team/atomics`)

## Verifying

```bash
python -m simulation.ssh_client --ping
# Expected: kernel string from `uname -a` on the VM

python -c "from simulation import AtomicRedTeamRunner; \
           AtomicRedTeamRunner().simulate('SIM-TEST-001', ['T1053.003'])"
# Inspect: data/simulations/SIM-TEST-001/simulation_manifest.json
```

## Safety

Each `Invoke-AtomicTest` invocation is followed by an `Invoke-AtomicTest
-Cleanup` call on the same technique. Cleanup runs even if the test failed —
residual VM state would taint downstream acquisitions. Do not run this against
production hosts.
