"""Linux.Sys.SUID → OCSF File System Activity (class_uid 1001).

Velociraptor walks the filesystem for files with the SUID bit set and emits
one row per such file. Every event carries `unmapped.is_privileged=True` so
Phase 4 can count `suid_additions` (vs. a baseline) without re-parsing the
mode field.

Time source: file Mtime (when the SUID bit was last set / file last
modified). Falls back to acquisition time if Mtime is missing or unparseable.
"""

from __future__ import annotations

from typing import Iterable, Iterator

from parsing.ocsf_base import MapperContext, ocsf_event, to_epoch_millis


def map_rows(rows: Iterable[dict], context: MapperContext) -> Iterator[dict]:
    for row in rows:
        mtime = row.get("Mtime")
        try:
            time_ms = to_epoch_millis(mtime) if mtime else context.acquisition_time_ms
        except ValueError:
            time_ms = context.acquisition_time_ms

        actor = None
        owner = row.get("OwnerID")
        if owner is not None:
            actor = {"user": {"name": None, "uid": str(owner)}}

        # File path goes into actor.process.file.path even though SUID files
        # are not necessarily running. The plan's OCSF shape requires
        # file-as-target to live in actor.process.file for class 1001 — close
        # enough; Phase 4 reads OSPath from raw_data directly anyway.
        if actor is None:
            actor = {}
        actor["process"] = {
            "pid": None,
            "name": None,
            "cmd_line": None,
            "file": {
                "path": row.get("OSPath"),
                "fingerprints": [],
            },
        }

        yield ocsf_event(
            class_uid=1001,
            activity_id=6,  # Set Attributes — most appropriate for SUID-flagged file
            time_ms=time_ms,
            raw_row=row,
            context=context,
            severity_id=3,  # SUID files are inherently privilege-sensitive
            actor=actor,
            unmapped_extra={"is_privileged": True},
        )
