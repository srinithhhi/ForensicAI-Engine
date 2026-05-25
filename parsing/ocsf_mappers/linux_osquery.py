"""Custom.Linux.Sys.Osquery → OCSF Process Activity (class_uid 1007).

Our osquery custom artifact runs `SELECT * FROM processes` (Linux), so each
row is a process snapshot. Output overlaps Linux.Sys.Pslist — but events are
tagged with `unmapped.source_step="osquery"` so Phase 4 can dedupe if needed
or treat osquery as an independent corroborating source.

The osquery row schema differs from Velociraptor's Pslist (lowercase keys,
no Hash dict, `start_time` as Unix epoch seconds string).
"""

from __future__ import annotations

from typing import Iterable, Iterator

from parsing.ocsf_base import MapperContext, ocsf_event, to_epoch_millis


def map_rows(rows: Iterable[dict], context: MapperContext) -> Iterator[dict]:
    for row in rows:
        # Only the "processes" table is mapped — other osquery tables (if we
        # add them later) would need their own dispatch.
        if row.get("osquery_table") and row["osquery_table"] != "processes":
            continue

        pid_raw = row.get("pid")
        try:
            pid = int(pid_raw) if pid_raw is not None else None
        except (TypeError, ValueError):
            pid = None

        start_raw = row.get("start_time")
        try:
            time_ms = (
                to_epoch_millis(int(start_raw))
                if start_raw not in (None, "", "-1", "0")
                else context.acquisition_time_ms
            )
        except (ValueError, TypeError):
            time_ms = context.acquisition_time_ms

        actor = {
            "user": {"name": None, "uid": str(row["uid"]) if row.get("uid") not in (None, "") else None},
            "process": {
                "pid": pid,
                "name": row.get("name"),
                "cmd_line": row.get("cmdline"),
                "file": {"path": row.get("path"), "fingerprints": []},
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
        )
