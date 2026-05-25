"""Windows.Forensics.Amcache → OCSF Process Activity (class_uid 1007).

Amcache.hve records every executable that has run on the system, including
file hash, size, and the InventoryApplicationFile timestamp (when the OS
first observed the binary). One event per row.
"""

from __future__ import annotations

from typing import Iterable, Iterator

from parsing.ocsf_base import MapperContext, ocsf_event, to_epoch_millis


def map_rows(rows: Iterable[dict], context: MapperContext) -> Iterator[dict]:
    for row in rows:
        ts = row.get("Timestamp")
        try:
            time_ms = to_epoch_millis(ts) if ts else context.acquisition_time_ms
        except ValueError:
            time_ms = context.acquisition_time_ms

        sha1 = row.get("SHA1")
        fingerprints = [{"algorithm_id": 2, "value": sha1.lower()}] if sha1 else []

        actor = {
            "process": {
                "pid": None,
                "name": row.get("Name"),
                "cmd_line": None,
                "file": {
                    "path": row.get("FullPath"),
                    "fingerprints": fingerprints,
                },
            },
        }
        message = f"amcache: {row.get('Name')} (product={row.get('ProductName')}, size={row.get('Size')})"

        yield ocsf_event(
            class_uid=1007,
            activity_id=1,
            time_ms=time_ms,
            raw_row=row,
            context=context,
            severity_id=1,
            actor=actor,
            message=message,
        )
