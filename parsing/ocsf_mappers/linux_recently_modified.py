"""Linux.Search.FileFinder → OCSF File System Activity (class_uid 1001).

Velociraptor's FileFinder runs glob+mtime queries (in our acquirer: files
modified in the last N minutes under /tmp, /var/tmp, /home, /root,
/etc/cron.*, etc.). Each row is one file whose mtime fell inside the query
window — emitted as activity_id=3 (Update).

Time source: MTime (when the file content was last modified).
"""

from __future__ import annotations

from typing import Iterable, Iterator

from parsing.ocsf_base import MapperContext, normalise_hash, ocsf_event, to_epoch_millis


def map_rows(rows: Iterable[dict], context: MapperContext) -> Iterator[dict]:
    for row in rows:
        mtime = row.get("MTime")
        try:
            time_ms = to_epoch_millis(mtime) if mtime else context.acquisition_time_ms
        except ValueError:
            time_ms = context.acquisition_time_ms

        actor = {
            "process": {
                "pid": None,
                "name": None,
                "cmd_line": None,
                "file": {
                    "path": row.get("OSPath"),
                    "fingerprints": normalise_hash(row.get("Hash")),
                },
            },
        }

        yield ocsf_event(
            class_uid=1001,
            activity_id=3,  # Update
            time_ms=time_ms,
            raw_row=row,
            context=context,
            severity_id=2,
            actor=actor,
        )
