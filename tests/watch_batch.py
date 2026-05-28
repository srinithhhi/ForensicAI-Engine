"""Background watcher: detects new bundle completions and writes per-slot
inspection reports.

Run in one terminal while `python tests/run_batch.py` runs in another. Each
new completion in `data/experiments/v0_state.json` triggers:
  1. A markdown inspection report written to
     `data/experiments/inspections/<slot>.md`
  2. A one-line status print to stdout (so progress is visible in the
     watcher's terminal too)
  3. A line appended to `data/experiments/watch.log`

The inspection report compares the bundle's emitted feature signature
against the expected signature for its configured techniques (verdict =
PASS/FAIL). Used by the assistant to give immediate analytical summaries
without re-deriving the feature panel manually.

Exits when all 30 slots have inspection reports, or on Ctrl-C.

CLI:
    python tests/watch_batch.py                       # poll every 30s
    python tests/watch_batch.py --interval 60         # custom interval
    python tests/watch_batch.py --rebuild             # regenerate ALL reports
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
STATE_PATH = REPO_ROOT / "data" / "experiments" / "v0_state.json"
CONFIG_PATH = REPO_ROOT / "data" / "experiments" / "v0_training_set.yaml"
INSPECTIONS_DIR = REPO_ROOT / "data" / "experiments" / "inspections"
WATCH_LOG = REPO_ROOT / "data" / "experiments" / "watch.log"
POLL_INTERVAL_SEC_DEFAULT = 30

# Map of technique → list of (feature, threshold) tuples that should fire
# when the technique runs. Used to compute the verdict for each bundle.
# Predicate is the integer threshold the feature must meet or exceed.
TECHNIQUE_EXPECT: dict[str, list[tuple[str, int]]] = {
    # Linux v0
    "T1053.003": [("cron_entries_added", 1)],
    "T1078.003": [("new_user_creations", 1)],
    "T1543.002": [("service_installs", 1)],
    "T1098.004": [("ssh_keys_added", 1)],
    "T1105":     [("tmp_file_creations", 2)],          # framework log + downloaded payload
    "T1548.001": [("recent_suid_creations", 1)],
    # Windows v0
    "T1136.001": [("new_user_creations", 1)],
    "T1547.001": [("registry_run_key_changes", 1)],
    "T1543.003": [("service_installs", 1)],
    "T1053.005": [("new_persistence_entries", 1)],     # heuristic; scheduled task
    "T1003.001": [("sysmon_high_severity_count", 1)],  # Sysmon EID 10 ProcessAccess
}

ATTACK_FEATURES = [
    "cron_entries_added", "service_installs", "new_user_creations",
    "ssh_keys_added", "tmp_file_creations", "recent_suid_creations",
    "registry_run_key_changes", "startup_items_added",
    "sysmon_high_severity_count", "new_persistence_entries",
]

AMBIENT_FEATURES = [
    "log_lines_total", "auth_success_count", "recently_modified_count",
    "process_count", "yara_proc_hits", "file_integrity_changes",
    "system_file_modifications", "unique_remote_ips", "ioc_hash_matches",
]

PERSISTENCE_PATH_HINTS = (
    "/etc/cron", "/etc/systemd/system", "/etc/passwd", "/etc/shadow",
    "/etc/group", "/.ssh/", "/etc/sudoers", "/var/spool/cron",
    "/tmp/", "/var/tmp/", "/dev/shm/",
    "C:\\Windows\\System32\\Tasks", "C:\\Users",
)


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def _to_epoch_ms(iso_str: str | None) -> int:
    if not iso_str:
        return 0
    if iso_str.endswith("Z"):
        iso_str = iso_str[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(iso_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except ValueError:
        return 0


def _evaluate(label_techs: list[str], features: dict[str, Any]) -> tuple[bool, str]:
    """Returns (passed, explanation)."""
    if not label_techs:
        nonzero = [(k, features.get(k, 0)) for k in ATTACK_FEATURES if features.get(k, 0) != 0]
        if nonzero:
            details = ", ".join(f"{k}={v}" for k, v in nonzero)
            return (False, f"benign baseline has non-zero attack features: {details}")
        return (True, "benign discipline maintained (all attack features = 0)")

    misses = []
    fires = []
    for t in label_techs:
        expects = TECHNIQUE_EXPECT.get(t, [])
        if not expects:
            misses.append(f"{t}: no expectation registered")
            continue
        for feat, threshold in expects:
            v = features.get(feat, 0)
            if v >= threshold:
                fires.append(f"{t}→{feat}={v}")
            else:
                misses.append(f"{t} expected {feat}>={threshold}, got {v}")
    if misses:
        return (False, "missing: " + "; ".join(misses) +
                (" | firing: " + "; ".join(fires) if fires else ""))
    return (True, "expected: " + "; ".join(fires))


def _in_window_paths(processed_dir: Path, sim_start_ms: int) -> list[str]:
    events_path = processed_dir / "events.ndjson"
    if not events_path.exists() or sim_start_ms == 0:
        return []
    out: list[str] = []
    with events_path.open() as f:
        for line in f:
            e = json.loads(line)
            if e["class_uid"] != 1001:
                continue
            if e["unmapped"].get("source_step") != "recently_modified":
                continue
            if e.get("time", 0) < sim_start_ms:
                continue
            path = ((e.get("actor") or {}).get("process") or {}).get("file", {}).get("path") or ""
            if any(p in path for p in PERSISTENCE_PATH_HINTS):
                out.append(path)
    return out


def _inspect(slot: str, info: dict, config: dict) -> str:
    """Build the markdown inspection report for one completed slot."""
    iid = info["incident_id"]
    duration_min = info.get("duration_sec", 0) / 60
    labeled_path = REPO_ROOT / "data" / "labeled" / f"{iid}.json"
    if not labeled_path.exists():
        return f"# {slot} — ERROR\n\nlabeled JSON not found at {labeled_path}\n"

    v = json.load(labeled_path.open())
    feats = v["features"]
    label = v["label"]

    bundle_spec = next((b for b in config["bundles"] if b["slot"] == slot), {})
    expected_techs = bundle_spec.get("techniques", [])

    sim_path = REPO_ROOT / "data" / "simulations" / iid / "simulation_manifest.json"
    sim_start_ms = 0
    if sim_path.exists():
        sim = json.load(sim_path.open())
        sim_start_ms = _to_epoch_ms(sim.get("started_at"))

    in_window = _in_window_paths(REPO_ROOT / "data" / "processed" / iid, sim_start_ms)
    passed, explanation = _evaluate(label["technique_ids"], feats)

    lines: list[str] = []
    lines.append(f"# {slot} — {iid}")
    lines.append("")
    lines.append(f"- **scope**: {v['scope']}")
    lines.append(f"- **duration**: {duration_min:.1f} min")
    lines.append(f"- **expected techniques** (from config): {expected_techs or '(benign baseline)'}")
    lines.append(f"- **labeled techniques**: {label['technique_ids']}  is_benign={label['is_benign']}")
    lines.append(f"- **verdict**: {'✓ PASS' if passed else '✗ FAIL'}")
    lines.append(f"- **explanation**: {explanation}")
    lines.append("")
    lines.append("## attack features")
    lines.append("```")
    for k in ATTACK_FEATURES:
        v_ = feats.get(k, 0)
        marker = "  ← fires" if v_ > 0 else ""
        lines.append(f"  {k:<32} = {v_}{marker}")
    lines.append("```")
    lines.append("")
    lines.append("## ambient features")
    lines.append("```")
    for k in AMBIENT_FEATURES:
        lines.append(f"  {k:<32} = {feats.get(k, 0)}")
    lines.append("```")
    lines.append("")
    if in_window:
        lines.append(f"## in-window attack-evidence paths ({len(in_window)})")
        lines.append("```")
        for p in in_window:
            lines.append(f"  {p}")
        lines.append("```")
    else:
        lines.append("## in-window attack-evidence paths")
        lines.append("")
        lines.append("(none — expected for benign baselines)")
    lines.append("")
    return "\n".join(lines) + "\n"


def _emit(slot: str, info: dict, config: dict) -> None:
    """Write the report and log a one-line status."""
    INSPECTIONS_DIR.mkdir(parents=True, exist_ok=True)
    report = _inspect(slot, info, config)
    report_path = INSPECTIONS_DIR / f"{slot}.md"
    report_path.write_text(report)
    # First two lines: title and verdict (extracted from the report)
    first = report.split("\n", 1)[0]
    verdict_line = next((l for l in report.split("\n") if l.startswith("- **verdict**")), "")
    verdict = verdict_line.split(":", 1)[1].strip() if verdict_line else "?"
    print(f"[{_ts()}] {first}  →  {verdict}", flush=True)
    WATCH_LOG.parent.mkdir(parents=True, exist_ok=True)
    with WATCH_LOG.open("a") as f:
        f.write(f"[{datetime.now(timezone.utc).isoformat(timespec='seconds')}] {slot} {verdict}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interval", type=int, default=POLL_INTERVAL_SEC_DEFAULT,
                        help=f"polling interval in seconds (default {POLL_INTERVAL_SEC_DEFAULT})")
    parser.add_argument("--rebuild", action="store_true",
                        help="ignore existing reports and rebuild for all completed slots")
    args = parser.parse_args()

    INSPECTIONS_DIR.mkdir(parents=True, exist_ok=True)
    if not CONFIG_PATH.exists():
        print(f"config not found at {CONFIG_PATH}", file=sys.stderr)
        return 2
    with CONFIG_PATH.open() as f:
        config = yaml.safe_load(f)
    total_slots = len(config["bundles"])

    seen = set() if args.rebuild else {p.stem for p in INSPECTIONS_DIR.glob("*.md")}
    print(f"[watch] polling {STATE_PATH} every {args.interval}s", flush=True)
    print(f"[watch] reports → {INSPECTIONS_DIR}", flush=True)
    print(f"[watch] startup: {len(seen)} of {total_slots} slot(s) have existing reports", flush=True)

    while True:
        try:
            if not STATE_PATH.exists():
                time.sleep(args.interval)
                continue
            state = json.load(STATE_PATH.open())
            completed = state.get("completed", {})
            new_slots = sorted(set(completed.keys()) - seen,
                               key=lambda s: completed[s].get("completed_at", ""))
            for slot in new_slots:
                _emit(slot, completed[slot], config)
                seen.add(slot)
            if len(seen) >= total_slots:
                print(f"[watch] all {len(seen)} slots have reports — exiting", flush=True)
                return 0
            time.sleep(args.interval)
        except KeyboardInterrupt:
            print(f"[watch] interrupted; {len(seen)} slots inspected", file=sys.stderr)
            return 130


if __name__ == "__main__":
    raise SystemExit(main())
