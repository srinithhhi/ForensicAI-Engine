"""Dev harness — chains adversary simulation with bare-metal acquisition.

Manual invocation only. The two modules meet here and nowhere else.

Usage:
    python tests/run_attack_and_acquire.py T1053.003
    python tests/run_attack_and_acquire.py T1078.003 T1059.004
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from acquisition.bare_metal_acquirer import BareMetalAcquirer  # noqa: E402
from simulation.atomic_runner import AtomicRedTeamRunner  # noqa: E402


def make_incident_id(techniques: list[str]) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    tag = "_".join(t.replace(".", "-") for t in techniques)
    return f"SIM-{ts}-{tag}"


def run(techniques: list[str]) -> str:
    incident_id = make_incident_id(techniques)
    print(f"[harness] incident_id = {incident_id}")

    print(f"[harness] firing {techniques} on the VM")
    AtomicRedTeamRunner().simulate(incident_id, techniques)
    print(f"[harness] simulation written to data/simulations/{incident_id}/")

    print("[harness] acquiring evidence via Velociraptor")
    manifest = BareMetalAcquirer().acquire(incident_id)
    failed = [s for s in manifest.steps if s.status != "success"]
    print(
        f"[harness] acquisition wrote {len(manifest.steps)} steps "
        f"({len(failed)} failed) to data/raw/{incident_id}/"
    )

    return incident_id


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "techniques",
        nargs="+",
        help="MITRE ATT&CK technique IDs, e.g. T1053.003",
    )
    args = parser.parse_args()
    run(args.techniques)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
