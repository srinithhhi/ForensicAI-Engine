"""Windows.Sys.Users → OCSF Authentication (class_uid 3002).

Enumerates local users (account context, not events). We emit one event per
user with activity_id=99 (Other) at low severity; Phase 4 can count
`new_user_creations` by diffing against an expected baseline.
"""

from __future__ import annotations

from typing import Iterable, Iterator

from parsing.ocsf_base import MapperContext, ocsf_event, to_epoch_millis


def map_rows(rows: Iterable[dict], context: MapperContext) -> Iterator[dict]:
    for row in rows:
        # Mtime on the ProfileList registry key roughly tracks account creation.
        mtime = row.get("Mtime")
        try:
            time_ms = to_epoch_millis(mtime) if mtime else context.acquisition_time_ms
        except ValueError:
            time_ms = context.acquisition_time_ms

        sid = row.get("UUID")
        actor = {
            "user": {
                "name": row.get("Name"),
                "uid": sid,
            },
        }
        message = f"local account: {row.get('Name')} (SID {sid}) — home={row.get('Directory')}"

        yield ocsf_event(
            class_uid=3002,
            activity_id=99,
            time_ms=time_ms,
            raw_row=row,
            context=context,
            severity_id=2,
            status_id=1,
            actor=actor,
            message=message,
        )
