"""Windows.Network.Netstat → OCSF Network Activity (class_uid 4001).

Note: Velociraptor flattens the local/remote address pairs into dot-keyed
top-level fields (`Laddr.IP`, `Laddr.Port`, `Raddr.IP`, `Raddr.Port`)
rather than nested objects — be careful when reading.
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

        pid = row.get("Pid")
        actor = {
            "process": {
                "pid": pid if isinstance(pid, int) else None,
                "name": row.get("Name"),
                "cmd_line": None,
                "file": {"path": None, "fingerprints": []},
            },
        }

        src_endpoint = {
            "hostname": None,
            "ip": row.get("Laddr.IP"),
            "port": row.get("Laddr.Port"),
        }
        dst_endpoint = {
            "hostname": None,
            "ip": row.get("Raddr.IP"),
            "port": row.get("Raddr.Port"),
        }

        activity_id = 7 if (row.get("Status") or "").upper() == "LISTEN" else 6
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
