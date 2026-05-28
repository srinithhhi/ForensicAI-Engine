"""Block until the NEXT new Windows bundle (WB-NN) appears in v0_state.json,
then exit. Each invocation waits for exactly one new completion.

Paired with the assistant's wake-on-completion loop: assistant runs this in
background, the harness notifies when the script exits, assistant inspects
the newly-completed slot, then re-invokes this script for the next one.

CLI:
    python tests/wait_next_wb.py                # block until next WB-* completes
    python tests/wait_next_wb.py --max-wait 7200  # exit non-zero after 2h timeout
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
STATE_PATH = REPO_ROOT / "data" / "experiments" / "v0_state.json"
POLL_SEC = 20


def _completed_matching(prefix: str) -> dict[str, dict]:
    if not STATE_PATH.exists():
        return {}
    with STATE_PATH.open() as f:
        state = json.load(f)
    return {k: v for k, v in state.get("completed", {}).items() if k.startswith(prefix)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--max-wait", type=int, default=7200,
        help="max seconds to wait before giving up (default 2h)"
    )
    parser.add_argument(
        "--prefix", default="",
        help="watch only slots starting with this prefix (default '' = any slot, e.g. 'WB-' or 'LB-' or '')",
    )
    args = parser.parse_args()

    baseline = _completed_matching(args.prefix)
    label = f"{args.prefix}*" if args.prefix else "any"
    print(f"baseline {label} completed: {sorted(baseline.keys())}", flush=True)
    print(f"waiting up to {args.max_wait}s for the next new {label} completion...", flush=True)

    deadline = time.monotonic() + args.max_wait
    while time.monotonic() < deadline:
        current = _completed_matching(args.prefix)
        new_slots = sorted(set(current.keys()) - set(baseline.keys()))
        if new_slots:
            for slot in new_slots:
                info = current[slot]
                print(f"NEW: {slot} {info['incident_id']} (duration {info.get('duration_sec', 0)/60:.1f} min)", flush=True)
            return 0
        time.sleep(POLL_SEC)
    print(f"timeout after {args.max_wait}s — no new completion", file=sys.stderr)
    return 124


if __name__ == "__main__":
    raise SystemExit(main())
