"""Linux.Network.NetstatEnriched → OCSF Network Activity (class_uid 4001).

Velociraptor's NetstatEnriched returns one row per open socket with the
owning process tree (CallChain) and detailed ProcInfo. We emit one event per
socket: src_endpoint = local side, dst_endpoint = remote side.
"""

from __future__ import annotations

from typing import Iterable, Iterator

from parsing.ocsf_base import MapperContext, ocsf_event, to_epoch_millis


def map_rows(rows: Iterable[dict], context: MapperContext) -> Iterator[dict]:
    for row in rows:
        proc = row.get("ProcInfo") or {}
        create_time = proc.get("CreateTime") or proc.get("StartTime")
        try:
            time_ms = to_epoch_millis(create_time) if create_time else context.acquisition_time_ms
        except ValueError:
            time_ms = context.acquisition_time_ms

        pid_raw = row.get("Pid")
        try:
            pid = int(pid_raw) if pid_raw is not None else None
        except (TypeError, ValueError):
            pid = None

        actor = {
            "user": {"name": proc.get("Username"), "uid": None},
            "process": {
                "pid": pid,
                "name": proc.get("Name"),
                "cmd_line": proc.get("CommandLine"),
            },
        }

        src_endpoint = {"hostname": None, "ip": row.get("Laddr"), "port": row.get("Lport")}
        dst_endpoint = {"hostname": None, "ip": row.get("Raddr"), "port": row.get("Rport")}

        status_raw = row.get("Status") or ""
        # Map TCP states to OCSF activity. 6=Traffic for established,
        # 7=Listen for LISTEN. Everything else falls through as Traffic.
        if status_raw.upper() == "LISTEN":
            activity_id = 7
        else:
            activity_id = 6

        yield ocsf_event(
            class_uid=4001,
            activity_id=activity_id,
            time_ms=time_ms,
            raw_row=row,
            context=context,
            severity_id=1,
            actor=actor,
            src_endpoint=src_endpoint,
            dst_endpoint=dst_endpoint,
        )
