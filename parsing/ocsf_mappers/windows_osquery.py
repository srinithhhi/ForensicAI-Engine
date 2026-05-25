"""Windows.OSQuery.Generic → OCSF Process Activity (class_uid 1007).

Windows osquery returns one row per running process. All numeric fields are
string-typed with `"-1"` sentinel for unknown — convert carefully.
"""

from __future__ import annotations

from typing import Iterable, Iterator

from parsing.ocsf_base import MapperContext, ocsf_event, to_epoch_millis


def _maybe_int(s: str | int | None) -> int | None:
    if s in (None, "", "-1"):
        return None
    try:
        v = int(s)
        return v if v >= 0 else None
    except (TypeError, ValueError):
        return None


def map_rows(rows: Iterable[dict], context: MapperContext) -> Iterator[dict]:
    for row in rows:
        pid = _maybe_int(row.get("pid"))
        start_raw = row.get("start_time")
        if start_raw in (None, "", "-1", "0"):
            time_ms = context.acquisition_time_ms
        else:
            try:
                time_ms = to_epoch_millis(int(start_raw))
            except (ValueError, TypeError):
                time_ms = context.acquisition_time_ms

        is_elevated = (row.get("is_elevated_token") or "") == "1"

        actor = {
            "user": {"name": None, "uid": str(_maybe_int(row.get("uid"))) if _maybe_int(row.get("uid")) is not None else None},
            "process": {
                "pid": pid,
                "name": row.get("name") or None,
                "cmd_line": row.get("cmdline") or None,
                "file": {"path": row.get("path") or None, "fingerprints": []},
            },
        }

        yield ocsf_event(
            class_uid=1007,
            activity_id=1,
            time_ms=time_ms,
            raw_row=row,
            context=context,
            severity_id=1,
            actor=actor,
            unmapped_extra={"is_privileged": is_elevated},
        )
