"""Microsoft-Windows-Sysmon/Operational → OCSF events (multi-class).

Sysmon is the strongest behavioural signal source on Windows. Unlike the
other evtx mappers (single output class), Sysmon dispatches by EventID into
several OCSF classes:

| EventID | Sysmon name                | OCSF class | Activity | Notes |
|---------|----------------------------|------------|----------|-------|
| 1       | Process create             | 1007       | 1 Launch | Strongest signal — hash + cmdline + parent |
| 2       | File creation time changed | 1001       | 6 SetAttr | Timestomping signal |
| 3       | Network connection         | 4001       | 6 Traffic | src/dst IP+port |
| 5       | Process terminated         | 1007       | 2 Terminate | |
| 6       | Driver loaded              | 6004       | 0        | Driver-load — rare; investigate hash |
| 7       | Image loaded (DLL)         | 1001       | 14 Open  | DLL-load; volume varies wildly |
| 8       | CreateRemoteThread         | 2004       | 1 Create | High-signal malware indicator |
| 10      | ProcessAccess              | 2004       | 1 Create | Credential dump signal (T1003) |
| 11      | File create                | 1001       | 1 Create | High volume; filter by path in Phase 4 |
| 12      | Registry object create/del | 1001       | 1/4      | Registry-as-file |
| 13      | Registry value set         | 1001       | 3 Update | Run-key persistence (T1547.001) |
| 15      | FileCreateStreamHash       | 1001       | 1 Create | Alternate data stream — suspicious |
| 22      | DNS query                  | 4001       | 6 Traffic | dst_endpoint = resolved host |
| other   | misc / config              | 6004       | 0        | low-signal noise |

Severity is escalated for EventIDs that correspond to known ATT&CK techniques
in our v0 attack set (1=Info, 2=Low, 3=Medium, 4=High).
"""

from __future__ import annotations

from typing import Iterable, Iterator

from parsing.ocsf_base import MapperContext, ocsf_event
from parsing.ocsf_mappers._evtx_shared import extract

# EventID → (class_uid, activity_id, severity_id, label).
SYSMON_DISPATCH: dict[int, tuple[int, int, int, str]] = {
    1: (1007, 1, 2, "process_create"),
    2: (1001, 6, 3, "file_creation_time_changed"),
    3: (4001, 6, 2, "network_connection"),
    5: (1007, 2, 1, "process_terminate"),
    6: (6004, 0, 3, "driver_load"),
    7: (1001, 14, 1, "image_load"),
    8: (2004, 1, 4, "create_remote_thread"),
    10: (2004, 1, 4, "process_access"),
    11: (1001, 1, 2, "file_create"),
    12: (1001, 1, 2, "registry_object_create_delete"),
    13: (1001, 3, 3, "registry_value_set"),
    15: (1001, 1, 3, "file_create_stream_hash"),
    16: (6004, 0, 1, "sysmon_config_changed"),
    22: (4001, 6, 2, "dns_query"),
    255: (6004, 0, 2, "sysmon_error"),
}


def _hashes_from_field(field: str | None) -> list[dict]:
    """Parse Sysmon's `Hashes` field — comma-separated `ALGO=HEX` pairs.

    Example: `MD5=ABC...,SHA256=DEF...,IMPHASH=...`. Returns OCSF
    fingerprints array; unknown algorithms (IMPHASH) are silently dropped.
    """
    if not field:
        return []
    algo_map = {"MD5": 1, "SHA1": 2, "SHA256": 3, "SHA512": 4}
    out: list[dict] = []
    for part in field.split(","):
        if "=" not in part:
            continue
        algo, value = part.split("=", 1)
        algo_id = algo_map.get(algo.strip().upper())
        if algo_id is None:
            continue
        out.append({"algorithm_id": algo_id, "value": value.strip().lower()})
    return out


def map_rows(rows: Iterable[dict], context: MapperContext) -> Iterator[dict]:
    for row in rows:
        e = extract(row, context)
        class_uid, activity_id, severity_id, label = SYSMON_DISPATCH.get(
            e.event_id or -1, (6004, 0, 1, "sysmon_other")
        )

        ed = e.event_data
        src_endpoint: dict | None = None
        dst_endpoint: dict | None = None
        actor: dict = {}

        # Common: user fields.
        user_name = ed.get("User") or ed.get("SourceUser")
        if user_name and user_name not in ("-", ""):
            actor["user"] = {"name": user_name, "uid": None}

        # Process-context fields (used by classes 1007, 1001, 2004, 4001).
        proc_pid = ed.get("ProcessId") or ed.get("SourceProcessId")
        try:
            proc_pid = int(proc_pid) if proc_pid is not None else None
        except (TypeError, ValueError):
            proc_pid = None
        actor["process"] = {
            "pid": proc_pid,
            "name": ed.get("Image") or ed.get("SourceImage"),
            "cmd_line": ed.get("CommandLine"),
            "file": {
                "path": ed.get("Image") or ed.get("TargetFilename"),
                "fingerprints": _hashes_from_field(ed.get("Hashes")),
            },
        }

        # Class-specific overrides for network events (3, 22).
        if class_uid == 4001:
            if e.event_id == 3:
                src_endpoint = {
                    "hostname": e.computer,
                    "ip": ed.get("SourceIp"),
                    "port": ed.get("SourcePort"),
                }
                dst_endpoint = {
                    "hostname": ed.get("DestinationHostname"),
                    "ip": ed.get("DestinationIp"),
                    "port": ed.get("DestinationPort"),
                }
            elif e.event_id == 22:
                src_endpoint = {"hostname": e.computer, "ip": None}
                dst_endpoint = {
                    "hostname": ed.get("QueryName"),
                    "ip": None,
                    "port": None,
                }
        else:
            if e.computer:
                src_endpoint = {"hostname": e.computer}

        # First line of Sysmon's message field is "EventTitle:" — useful for
        # quick human-readable triage.
        message_lines = row.get("Message", "").split("\n", 1)
        message = message_lines[0] if message_lines and message_lines[0] else None

        yield ocsf_event(
            class_uid=class_uid,
            activity_id=activity_id,
            time_ms=e.time_ms,
            raw_row=e.raw_row,
            context=context,
            severity_id=severity_id,
            actor=actor,
            src_endpoint=src_endpoint,
            dst_endpoint=dst_endpoint,
            message=message,
            unmapped_extra={"event_id": e.event_id},
        )
