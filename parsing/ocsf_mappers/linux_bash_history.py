"""Linux.Sys.BashHistory → OCSF System Activity (class_uid 6004).

Velociraptor reads ~/.bash_history files and emits one row per line. The
artifact does NOT carry per-command timestamps (bash only writes them if
HISTTIMEFORMAT is set) — we tag every event with the acquisition time.

The owning user is parsed from the OSPath (`/home/<user>/.bash_history` or
`/root/.bash_history`).
"""

from __future__ import annotations

from typing import Iterable, Iterator

from parsing.ocsf_base import MapperContext, ocsf_event


def _user_from_path(path: str | None) -> str | None:
    if not path:
        return None
    # /home/<user>/.bash_history → <user> ;  /root/.bash_history → root
    parts = path.split("/")
    if len(parts) >= 3 and parts[1] == "home":
        return parts[2]
    if len(parts) >= 2 and parts[1] == "root":
        return "root"
    return None


def map_rows(rows: Iterable[dict], context: MapperContext) -> Iterator[dict]:
    for row in rows:
        line = row.get("Line")
        if not line or not line.strip():
            continue
        ospath = row.get("OSPath")
        user = _user_from_path(ospath)

        actor = {"user": {"name": user, "uid": None}} if user else None

        yield ocsf_event(
            class_uid=6004,
            activity_id=0,
            time_ms=context.acquisition_time_ms,
            raw_row=row,
            context=context,
            severity_id=1,
            actor=actor,
            message=line,
        )
