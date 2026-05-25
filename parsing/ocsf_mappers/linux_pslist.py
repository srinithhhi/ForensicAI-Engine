"""Linux.Sys.Pslist → OCSF Process Activity (class_uid 1007).

Velociraptor's Pslist gives a snapshot of every process alive at collection
time. We emit one event per process with activity_id=1 (Launch) — strictly
this is a "process observed running" snapshot, not a launch event, but
Phase 4 feature aggregation only cares about process counts and exe paths,
not the precise activity type.
"""

from __future__ import annotations

from typing import Iterable, Iterator

from parsing.ocsf_base import MapperContext, normalise_hash, ocsf_event, to_epoch_millis


def map_rows(rows: Iterable[dict], context: MapperContext) -> Iterator[dict]:
    for row in rows:
        pid_raw = row.get("Pid")
        try:
            pid = int(pid_raw) if pid_raw is not None else None
        except (TypeError, ValueError):
            pid = None
        ppid_raw = row.get("Ppid")
        try:
            ppid = int(ppid_raw) if ppid_raw is not None else None
        except (TypeError, ValueError):
            ppid = None

        created = row.get("CreatedTime")
        try:
            time_ms = to_epoch_millis(created) if created else context.acquisition_time_ms
        except ValueError:
            time_ms = context.acquisition_time_ms

        actor = {
            "user": {"name": row.get("Username"), "uid": None},
            "process": {
                "pid": pid,
                "name": row.get("Name"),
                "cmd_line": row.get("CommandLine"),
                "file": {
                    "path": row.get("Exe"),
                    "fingerprints": normalise_hash(row.get("Hash")),
                },
            },
        }

        yield ocsf_event(
            class_uid=1007,
            activity_id=1,  # Launch (observed-running)
            time_ms=time_ms,
            raw_row=row,
            context=context,
            severity_id=1,
            actor=actor,
            unmapped_extra={"event_id": ppid},  # store ppid for parent-chain features
        )
