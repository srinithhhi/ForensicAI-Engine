"""Windows System.evtx → OCSF System Activity (class_uid 6004).

The System channel is mostly Service Control Manager and boot/shutdown
events. We emit one event per row, with EventID-based severity escalation
for the persistence-relevant cases (service installs especially).
"""

from __future__ import annotations

from typing import Iterable, Iterator

from parsing.ocsf_base import MapperContext, ocsf_event
from parsing.ocsf_mappers._evtx_shared import extract

# EventID → (severity_id, label).
SYS_DISPATCH: dict[int, tuple[int, str]] = {
    6005: (2, "event_log_started"),
    6006: (2, "event_log_stopped"),
    6008: (3, "unexpected_shutdown"),
    7000: (3, "service_failed_to_start"),
    7034: (3, "service_terminated_unexpectedly"),
    7036: (1, "service_state_changed"),
    7040: (2, "service_start_type_changed"),
    7045: (4, "service_installed"),  # New service install → high signal for T1543.003
    1074: (2, "reboot_initiated"),
}


def map_rows(rows: Iterable[dict], context: MapperContext) -> Iterator[dict]:
    for row in rows:
        e = extract(row, context)
        severity_id, label = SYS_DISPATCH.get(e.event_id or -1, (1, "unknown"))

        ed = e.event_data
        # Service install (7045) carries ServiceName, ImagePath, ServiceType.
        service_name = ed.get("ServiceName") or ed.get("param1")

        src_endpoint = {"hostname": e.computer} if e.computer else None
        first_line = row.get("Message", "").split("\n", 1)[0] if row.get("Message") else None

        yield ocsf_event(
            class_uid=6004,
            activity_id=0,
            time_ms=e.time_ms,
            raw_row=e.raw_row,
            context=context,
            severity_id=severity_id,
            src_endpoint=src_endpoint,
            message=(first_line or service_name or None),
            unmapped_extra={"event_id": e.event_id},
        )
