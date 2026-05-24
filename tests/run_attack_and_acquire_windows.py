"""Dev harness — Scope 2 (Windows): chain Atomic simulation + VMware acquisition.

Mirror of `tests/run_attack_and_acquire.py` for Windows. Sequence:

    1. WindowsAtomicRunner.simulate(... auto_cleanup=False)   — fire attacks
    2. VMwareAcquirer.acquire(incident_id)                    — capture evidence
    3. WindowsAtomicRunner.cleanup(simulation_manifest)       — restore VM

Cleanup runs in try/finally so the VM is never left dirty even on crash.

**Defender caveat.** Several v0 atomics (LSASS dump in particular) will be
blocked by Windows Defender real-time monitoring unless it's temporarily
disabled. Run host_setup/windows/disable_defender_for_testing.ps1 on the VM
BEFORE invoking this harness, and re-enable afterward.

Usage:
    python tests/run_attack_and_acquire_windows.py                  # default v0 6-pack
    python tests/run_attack_and_acquire_windows.py T1547.001#1      # ad-hoc subset
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from acquisition.vmware_acquirer import VMwareAcquirer  # noqa: E402
from simulation.windows_runner import WindowsAtomicRunner  # noqa: E402

# v0 attack set — verified Windows-applicable Atomic Red Team tests as of
# 2026-05-24. Coverage map and rationale: see Phase 2 planning notes.
DEFAULT_V0_TECHNIQUES = [
    "T1136.001#4",   # create local user via cmd
    "T1547.001#1",   # registry Run key persistence
    "T1543.003#2",   # Windows service via sc.exe
    "T1053.005#1",   # scheduled task via schtasks
    "T1105#10",      # PowerShell Invoke-WebRequest download
    "T1003.001#2",   # LSASS dump via comsvcs.dll
]


def make_incident_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"INC-WIN-{ts}"


def run(specs: list[str]) -> str:
    incident_id = make_incident_id()
    print(f"[harness-win] incident_id = {incident_id}")

    runner = WindowsAtomicRunner()
    print(f"[harness-win] firing {specs} on Windows VM (cleanup deferred)")
    sim_manifest = runner.simulate(incident_id, specs, auto_cleanup=False)
    failed_sims = [r for r in sim_manifest.runs if not r.success]
    print(
        f"[harness-win]   simulation wrote {len(sim_manifest.runs)} runs "
        f"({len(failed_sims)} failed) to data/simulations/{incident_id}/"
    )
    for r in failed_sims:
        print(f"  SIM-FAIL {r.technique_id}#{r.test_number}: exit={r.exit_code}")

    try:
        print("[harness-win] acquiring evidence via Velociraptor")
        acq_manifest = VMwareAcquirer().acquire(incident_id)
        failed_acq = [s for s in acq_manifest.steps if s.status != "success"]
        print(
            f"[harness-win]   acquisition wrote {len(acq_manifest.steps)} steps "
            f"({len(failed_acq)} failed) to data/raw/{incident_id}/"
        )
        for s in failed_acq:
            print(f"  ACQ-FAIL {s.name}: {s.error}")
    finally:
        print("[harness-win] restoring VM state (cleanup)")
        runner.cleanup(sim_manifest)
        print("[harness-win]   cleanup complete")

    return incident_id


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "techniques",
        nargs="*",
        help=(
            "MITRE ATT&CK technique specs, e.g. T1547.001 or T1547.001#1. "
            "If omitted, runs the v0 default 6-pack."
        ),
    )
    args = parser.parse_args()
    specs = args.techniques or DEFAULT_V0_TECHNIQUES
    run(specs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
