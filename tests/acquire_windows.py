"""Dev harness — Windows acquisition only (no simulation yet).

Mirror of `tests/run_attack_and_acquire.py` for Scope 2, minus the simulator
half. Phase 2 will add a Windows AtomicRedTeam runner once OpenSSH is set up
on the VM; until then this script lets you fire a clean baseline acquisition
or an acquisition after manual evidence has been planted.

Usage:
    python tests/acquire_windows.py            # auto-generates INC-YYYYMMDD-HHMMSS
    python tests/acquire_windows.py --incident FULL-WIN-001
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from acquisition.vmware_acquirer import VMwareAcquirer  # noqa: E402


def make_incident_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"INC-WIN-{ts}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--incident",
        default=None,
        help="Incident ID (default: auto-generated INC-WIN-YYYYMMDD-HHMMSS)",
    )
    args = parser.parse_args()

    incident_id = args.incident or make_incident_id()
    print(f"[acquire-windows] incident_id = {incident_id}")
    print("[acquire-windows] starting VMwareAcquirer chain")

    manifest = VMwareAcquirer().acquire(incident_id)
    failed = [s for s in manifest.steps if s.status != "success"]
    print(
        f"[acquire-windows] wrote {len(manifest.steps)} steps "
        f"({len(failed)} failed) to data/raw/{incident_id}/"
    )
    for s in failed:
        print(f"  FAIL {s.name}: {s.error}")

    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
