"""Windows.System.Services → OCSF System Activity (class_uid 6004).

One event per service unit at collection time. Severity escalated when:
- ServiceType is kernel/file_system driver (3)
- StartMode is "Auto" AND PathName isn't under C:\\Windows (2)
- State is "Stopped" but StartMode is "Auto" (3 — broken auto-start)
"""

from __future__ import annotations

from typing import Iterable, Iterator

from parsing.ocsf_base import MapperContext, ocsf_event, to_epoch_millis


def _path_under_windows(path: str | None) -> bool:
    if not path:
        return False
    p = path.lower().strip().lstrip('"')
    return p.startswith(("c:\\windows\\", "c:/windows/", "%systemroot%"))


def map_rows(rows: Iterable[dict], context: MapperContext) -> Iterator[dict]:
    for row in rows:
        created = row.get("Created")
        try:
            time_ms = to_epoch_millis(created) if created else context.acquisition_time_ms
        except ValueError:
            time_ms = context.acquisition_time_ms

        start_mode = row.get("StartMode") or ""
        state = row.get("State") or ""
        path_name = row.get("PathName") or row.get("AbsoluteExePath")
        service_type = row.get("ServiceType") or ""

        severity_id = 1
        if "driver" in service_type.lower() or "kernel" in service_type.lower():
            severity_id = 3
        elif start_mode == "Auto" and not _path_under_windows(path_name):
            severity_id = 2  # auto-start service outside Windows dir
        if state == "Stopped" and start_mode == "Auto":
            severity_id = max(severity_id, 3)

        actor = {
            "user": {"name": row.get("UserAccount"), "uid": None},
            "process": {
                "pid": row.get("Pid") if isinstance(row.get("Pid"), int) else None,
                "name": row.get("Name"),
                "cmd_line": path_name,
                "file": {"path": row.get("AbsoluteExePath"), "fingerprints": []},
            },
        }
        message = f"{row.get('Name')}: {start_mode}/{state} — {row.get('DisplayName', '')}"

        yield ocsf_event(
            class_uid=6004,
            activity_id=0,
            time_ms=time_ms,
            raw_row=row,
            context=context,
            severity_id=severity_id,
            actor=actor,
            message=message,
        )
