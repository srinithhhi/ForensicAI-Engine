"""OCSF mapper driver.

Reads `data/raw/{incident_id}/manifest.json`, dispatches each successful step
to its registered mapper, validates every emitted event, and writes
`data/processed/{incident_id}/events.ndjson` sorted by time.

Invalid events are routed to `dead_letter.ndjson` rather than crashing the run
— mappers under active development should not block end-to-end verification of
mappers that are already correct.

CLI:
    python -m parsing.run_mappers data/raw/INC-20260523-134301
    python -m parsing.run_mappers data/raw/INC-X --out data/processed/INC-X

Exit codes:
    0  every step had a registered mapper AND dead-letter ratio < 1%
    1  one or more steps lacked a registered mapper (unknown artifact)
    2  dead-letter ratio exceeded 1% — mapper bug, investigate
    3  malformed manifest or missing input bundle
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Callable, Iterable, Iterator

from parsing.ocsf_base import (
    MapperContext,
    read_artifact_rows,
    to_epoch_millis,
    validate_event,
)
from parsing.ocsf_mappers import (
    linux_aide,
    linux_auth_keys,
    linux_bash_history,
    linux_cron,
    linux_journald,
    linux_netstat_enriched,
    linux_osquery,
    linux_plaso_timeline,
    linux_pslist,
    linux_recently_modified,
    linux_suid,
    linux_systemd,
    linux_yara_glob,
    linux_yara_proc,
    windows_amcache,
    windows_evtx_router,
    windows_local_users,
    windows_netstat,
    windows_osquery,
    windows_powershell_history,
    windows_prefetch,
    windows_pslist,
    windows_recently_modified,
    windows_services,
    windows_startup_items,
    windows_yara_glob,
    windows_yara_proc,
)

# Maps Velociraptor artifact name → mapper function. Dispatch is by artifact
# (not by step name) because step names collide across scopes — "processes"
# means Linux.Sys.Pslist on Scope 1 and Windows.System.Pslist on Scope 2.
# Artifact names are unique per data shape.
#
# Edge case: `Windows.EventLogs.Evtx` is invoked three times by the Windows
# acquirer with different Channel filters (event_security, event_system,
# sysmon). `windows_evtx_router` handles all three by reading the Channel
# field on each row.
#
# Unregistered artifacts cause the driver to exit 1 with the list of
# unmapped steps (no silent skips).
MapperFn = Callable[[Iterable[dict], MapperContext], Iterator[dict]]

MAPPER_REGISTRY: dict[str, MapperFn] = {
    # Linux (Scope 1) — 14 mappers
    "Linux.Forensics.Journal": linux_journald.map_rows,
    "Linux.Sys.Pslist": linux_pslist.map_rows,
    "Linux.Network.NetstatEnriched": linux_netstat_enriched.map_rows,
    "Linux.Sys.Crontab": linux_cron.map_rows,
    "Linux.Sys.Services": linux_systemd.map_rows,
    "Linux.Sys.BashHistory": linux_bash_history.map_rows,
    "Linux.Ssh.AuthorizedKeys": linux_auth_keys.map_rows,
    "Linux.Sys.SUID": linux_suid.map_rows,
    "Linux.Search.FileFinder": linux_recently_modified.map_rows,
    "Linux.Detection.Yara.Process": linux_yara_proc.map_rows,
    "Linux.Detection.Yara.Glob": linux_yara_glob.map_rows,
    "Custom.Linux.Sys.AIDE": linux_aide.map_rows,
    "Custom.Linux.Sys.Osquery": linux_osquery.map_rows,
    "Custom.Linux.Forensics.PlasoTimeline": linux_plaso_timeline.map_rows,
    # Windows (Scope 2) — session 3.4 (router covers 3 sub-channels)
    "Windows.EventLogs.Evtx": windows_evtx_router.map_rows,
    # Windows (Scope 2) — session 3.5
    "Windows.System.Pslist": windows_pslist.map_rows,
    "Windows.Network.Netstat": windows_netstat.map_rows,
    "Windows.System.Services": windows_services.map_rows,
    "Windows.Sys.StartupItems": windows_startup_items.map_rows,
    "Windows.Sys.Users": windows_local_users.map_rows,
    "Windows.OSQuery.Generic": windows_osquery.map_rows,
    "Windows.System.Powershell.PSReadline": windows_powershell_history.map_rows,
    "Windows.Forensics.Prefetch": windows_prefetch.map_rows,
    "Windows.Forensics.Amcache": windows_amcache.map_rows,
    "Windows.Search.FileFinder": windows_recently_modified.map_rows,
    "Windows.Detection.Yara.Process": windows_yara_proc.map_rows,
    "Windows.Detection.Yara.Glob": windows_yara_glob.map_rows,
}

DEAD_LETTER_THRESHOLD = 0.01  # 1%


def _process_step(
    step: dict,
    bundle_dir: Path,
    scope: str,
    incident_id: str,
) -> tuple[list[dict], list[dict]]:
    """Run one manifest step through its mapper.

    Returns (valid_events, dead_letter_events). dead_letter_events are dicts
    with `{"event": <invalid event>, "errors": [...]}`.
    """
    artifact = step["artifact"]
    mapper = MAPPER_REGISTRY[artifact]
    # Fallback time for snapshot artifacts (systemd, bash_history, auth_keys,
    # etc.) that have no per-row timestamp. Defaults to 0 if started_at is
    # missing — caller can spot 0-time events as a debugging signal.
    try:
        acquisition_time_ms = to_epoch_millis(step.get("started_at"))
    except ValueError:
        acquisition_time_ms = 0
    context = MapperContext(
        scope=scope,
        incident_id=incident_id,
        source_step=step["name"],
        source_artifact=artifact,
        acquisition_time_ms=acquisition_time_ms,
    )
    rows = list(read_artifact_rows(bundle_dir, step["path"]))
    valid: list[dict] = []
    dead: list[dict] = []
    for event in mapper(rows, context):
        errors = validate_event(event)
        if errors:
            dead.append({"event": event, "errors": errors})
        else:
            valid.append(event)
    return valid, dead


def run(bundle_dir: Path, out_dir: Path) -> int:
    manifest_path = bundle_dir / "manifest.json"
    if not manifest_path.exists():
        print(f"manifest not found: {manifest_path}", file=sys.stderr)
        return 3
    with manifest_path.open() as f:
        manifest = json.load(f)

    incident_id = manifest["incident_id"]
    scope = manifest["scope"]

    out_dir.mkdir(parents=True, exist_ok=True)
    events_path = out_dir / "events.ndjson"
    dead_letter_path = out_dir / "dead_letter.ndjson"

    all_events: list[dict] = []
    all_dead: list[dict] = []
    unmapped_artifacts: list[str] = []

    for step in manifest["steps"]:
        if step.get("status") != "success":
            # Skip failed acquisition steps — there's no artifact to map.
            continue
        artifact = step["artifact"]
        if artifact not in MAPPER_REGISTRY:
            unmapped_artifacts.append(f"{step['name']} ({artifact})")
            continue
        print(f"[map] {step['name']} ({artifact}) ...", flush=True)
        valid, dead = _process_step(step, bundle_dir, scope, incident_id)
        print(
            f"       → {len(valid)} valid, {len(dead)} dead-letter",
            flush=True,
        )
        all_events.extend(valid)
        all_dead.extend(dead)

    # Sort by time. Events with time=0 (unparseable timestamp) sort to the
    # top so they're easy to spot during debugging.
    all_events.sort(key=lambda e: e["time"])

    with events_path.open("w") as f:
        for event in all_events:
            f.write(json.dumps(event, sort_keys=True) + "\n")
    print(f"[write] {events_path}: {len(all_events)} events", flush=True)

    if all_dead:
        with dead_letter_path.open("w") as f:
            for entry in all_dead:
                f.write(json.dumps(entry, sort_keys=True) + "\n")
        print(
            f"[write] {dead_letter_path}: {len(all_dead)} dead-letter entries",
            flush=True,
        )

    if unmapped_artifacts:
        print(
            "[warn] unmapped artifacts (will be skipped):",
            file=sys.stderr,
        )
        for u in unmapped_artifacts:
            print(f"       - {u}", file=sys.stderr)

    total = len(all_events) + len(all_dead)
    dead_ratio = len(all_dead) / total if total else 0.0

    if unmapped_artifacts:
        # Soft warning until all 29 mappers exist — exit code distinguishes
        # "no mapper" (1) from "mapper bug" (2).
        return 1
    if dead_ratio > DEAD_LETTER_THRESHOLD:
        print(
            f"[fail] dead-letter ratio {dead_ratio:.2%} exceeds "
            f"{DEAD_LETTER_THRESHOLD:.0%} threshold",
            file=sys.stderr,
        )
        return 2
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "bundle_dir",
        type=Path,
        help="Path to data/raw/{incident_id} bundle directory",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output directory. Defaults to data/processed/{incident_id}.",
    )
    args = parser.parse_args()

    bundle_dir = args.bundle_dir.resolve()
    if not bundle_dir.is_dir():
        print(f"bundle dir not found: {bundle_dir}", file=sys.stderr)
        return 3
    out_dir = (
        args.out.resolve()
        if args.out
        else bundle_dir.parent.parent / "processed" / bundle_dir.name
    )
    return run(bundle_dir, out_dir)


if __name__ == "__main__":
    raise SystemExit(main())
