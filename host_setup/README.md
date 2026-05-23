# Host-side setup scripts

Lab-VM helpers that don't belong in the acquisition / simulation modules
because they run **inside** the target VM, not against it.

## Ubuntu Scope 1 (`ubuntu/`)

`network-watchdog.sh` + `network-watchdog.service` — pings `192.168.1.1`
every 30 s. After 3 consecutive failures, runs `netplan apply` to re-attach
the bridged NIC after Mac host sleep events.

**Install:**

```bash
scp -i ~/.ssh/forensicai_key \
    host_setup/ubuntu/network-watchdog.sh \
    host_setup/ubuntu/network-watchdog.service \
    admin@192.168.1.10:/tmp/

ssh -i ~/.ssh/forensicai_key admin@192.168.1.10 '
    sudo install -m 755 /tmp/network-watchdog.sh /usr/local/sbin/network-watchdog.sh
    sudo install -m 644 /tmp/network-watchdog.service /etc/systemd/system/network-watchdog.service
    sudo systemctl daemon-reload
    sudo systemctl enable --now network-watchdog.service
'
```

**Verify:** `sudo systemctl status network-watchdog` on the VM.
**Logs:** `sudo journalctl -u network-watchdog -f`.

## Windows Scope 2 (`windows/`)

`network-watchdog.ps1` — single self-installing PowerShell. Same logic via
Scheduled Task running at startup as SYSTEM. Recovery action is
`Restart-NetAdapter` on every Up adapter.

**Install** (RDP to the VM, open PowerShell **as Administrator**):

```powershell
# Copy network-watchdog.ps1 to the VM (shared folder, paste, or download)
powershell.exe -ExecutionPolicy Bypass -File C:\path\to\network-watchdog.ps1
```

The script copies itself to `C:\ProgramData\ForensicAI\`, registers a
Scheduled Task `ForensicAI Network Watchdog`, and starts it immediately.

**Verify:**
```powershell
Get-ScheduledTask -TaskName 'ForensicAI Network Watchdog'
Get-EventLog -LogName Application -Source NetworkWatchdog -Newest 20
```

## Why these belong outside `acquisition/`

These keep the lab VMs healthy enough to *be acquired*. They are
infrastructure for the test environment, not part of the forensic pipeline.
If a future deployment runs on always-on VMs (or production endpoints with
their own redundancy), the watchdogs would not be installed.
