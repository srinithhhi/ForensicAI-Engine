"""Windows.System.Pslist → OCSF Process Activity (class_uid 1007)."""

from __future__ import annotations

from typing import Iterable, Iterator

from parsing.ocsf_base import MapperContext, normalise_hash, ocsf_event, to_epoch_millis


def map_rows(rows: Iterable[dict], context: MapperContext) -> Iterator[dict]:
    for row in rows:
        pid = row.get("Pid")
        ppid = row.get("Ppid")
        created = row.get("CreateTime")
        try:
            time_ms = to_epoch_millis(created) if created else context.acquisition_time_ms
        except ValueError:
            time_ms = context.acquisition_time_ms

        # TokenIsElevated is the Windows analogue of "running as root" — flag
        # it on unmapped.is_privileged so Phase 4 can count elevated procs.
        is_elevated = bool(row.get("TokenIsElevated"))

        actor = {
            "user": {"name": row.get("Username"), "uid": None},
            "process": {
                "pid": pid if isinstance(pid, int) else None,
                "name": row.get("Name"),
                "cmd_line": row.get("CommandLine"),
                "file": {
                    "path": row.get("Exe") or None,
                    "fingerprints": normalise_hash(row.get("Hash")),
                },
            },
        }

        # Severity: elevated process with non-system path is mildly notable.
        severity_id = 2 if is_elevated and row.get("Exe", "").startswith(("C:\\Users\\", "C:\\Temp\\")) else 1

        yield ocsf_event(
            class_uid=1007,
            activity_id=1,
            time_ms=time_ms,
            raw_row=row,
            context=context,
            severity_id=severity_id,
            actor=actor,
            unmapped_extra={
                "event_id": ppid if isinstance(ppid, int) else None,
                "is_privileged": is_elevated,
            },
        )
