"""Dev harness — chains adversary simulation with bare-metal acquisition.

Manual invocation only. The two modules meet here and nowhere else.

Sequence:
    1. simulate(... auto_cleanup=False)   — fire attacks, leave evidence
    2. acquire(incident_id)               — capture evidence
    3. cleanup(simulation_manifest)       — restore VM state (always runs)

Even if acquisition crashes, cleanup runs via try/finally so the VM is
never left in a dirty state.

Technique specs accept "T1053.003" (test 1) or "T1053.003#2" (explicit
test number). Use whichever test of the technique actually leaves the
evidence you want the acquirer to catch.

Usage:
    python tests/run_attack_and_acquire.py T1053.003#2
    python tests/run_attack_and_acquire.py T1053.003#2 T1078.003 T1105
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Sleep-prevention is handled externally by wrapping the invocation in
# `caffeinate` (or equivalent). An earlier version self-execed caffeinate
# from inside main(); that turned out to be unreliable when launched as a
# background task — the PID supervisor desynced after execvp. Keep the
# harness Python pure; wrap at the shell level instead. See
# host_setup/README.md for the recommended invocation.

from acquisition.bare_metal_acquirer import BareMetalAcquirer  # noqa: E402
from simulation.atomic_runner import AtomicRedTeamRunner  # noqa: E402


def make_incident_id(specs: list[str]) -> str:
    # Format: INC-YYYYMMDD-HHMMSS  (UTC, no timezone marker for brevity).
    # We intentionally do NOT encode the technique list in the directory
    # name — that lives in simulation_manifest.json where it belongs.
    # Keeps incident_id short and consistent length regardless of how many
    # techniques fired.
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"INC-{ts}"


def run(specs: list[str]) -> str:
    incident_id = make_incident_id(specs)
    print(f"[harness] incident_id = {incident_id}")

    runner = AtomicRedTeamRunner()
    print(f"[harness] firing {specs} on the VM (cleanup deferred)")
    sim_manifest = runner.simulate(incident_id, specs, auto_cleanup=False)
    print(f"[harness]   simulation written to data/simulations/{incident_id}/")

    try:
        print("[harness] acquiring evidence via Velociraptor")
        acq_manifest = BareMetalAcquirer().acquire(incident_id)
        failed = [s for s in acq_manifest.steps if s.status != "success"]
        print(
            f"[harness]   acquisition wrote {len(acq_manifest.steps)} steps "
            f"({len(failed)} failed) to data/raw/{incident_id}/"
        )
    finally:
        print("[harness] restoring VM state (cleanup)")
        runner.cleanup(sim_manifest)
        print("[harness]   cleanup complete")

    return incident_id


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "techniques",
        nargs="+",
        help="MITRE ATT&CK technique specs, e.g. T1053.003 or T1053.003#2",
    )
    args = parser.parse_args()
    run(args.techniques)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
