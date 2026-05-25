"""Windows.Forensics.Prefetch → OCSF Process Activity (class_uid 1007).

Prefetch is execution evidence: Windows keeps a `.pf` file per executable
it has launched, with up to 8 LastRunTimes timestamps and a total RunCount.
We emit ONE event per LastRunTime so Phase 4 can correctly count launches
and detect bursts of new-executable activity.
"""

from __future__ import annotations

from typing import Iterable, Iterator

from parsing.ocsf_base import MapperContext, ocsf_event, to_epoch_millis


def map_rows(rows: Iterable[dict], context: MapperContext) -> Iterator[dict]:
    for row in rows:
        last_runs = row.get("LastRunTimes") or []
        executable = row.get("Executable") or row.get("ExecutableDosPath")
        full_path = row.get("Binary") or row.get("ExecutablePath")

        actor_template = {
            "process": {
                "pid": None,
                "name": executable,
                "cmd_line": None,
                "file": {"path": full_path, "fingerprints": []},
            },
        }
        message = f"prefetch: {executable} (run_count={row.get('RunCount')})"

        # If LastRunTimes is empty, emit one event at acquisition time so the
        # binary still appears in the log volume.
        if not last_runs:
            yield ocsf_event(
                class_uid=1007,
                activity_id=1,
                time_ms=context.acquisition_time_ms,
                raw_row=row,
                context=context,
                severity_id=1,
                actor=actor_template,
                message=message,
            )
            continue

        for run_time in last_runs:
            try:
                time_ms = to_epoch_millis(run_time)
            except ValueError:
                time_ms = context.acquisition_time_ms
            yield ocsf_event(
                class_uid=1007,
                activity_id=1,
                time_ms=time_ms,
                raw_row=row,
                context=context,
                severity_id=1,
                actor=actor_template,
                message=message,
            )
