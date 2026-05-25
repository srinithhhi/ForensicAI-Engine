"""Shared row-extraction helpers for Windows EVTX-shaped artifacts.

Velociraptor's evtx parser emits a consistent row shape across all event
channels (Security, System, Application, Sysmon, etc.):

    {
      "EventID": 4624,                              # top-level scalar
      "TimeCreated": "2026-05-13T07:15:03Z",         # top-level ISO string
      "EventData": {...},                            # event-specific payload
      "System": {
        "Computer": "WIN-...",
        "EventID": {"Value": 4624, ...},             # nested fallback
        "TimeCreated": {"SystemTime": <epoch>},
        ...
      },
      ...
    }

These helpers extract the common fields so per-channel mappers only have to
implement the dispatch table from EventID → (class_uid, activity_id, etc.).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from parsing.ocsf_base import MapperContext, to_epoch_millis


@dataclass(frozen=True)
class EvtxRow:
    event_id: int | None
    time_ms: int
    computer: str | None
    event_data: dict
    raw_row: dict


def extract(row: dict, context: MapperContext) -> EvtxRow:
    """Pull (EventID, TimeCreated, Computer, EventData) out of an evtx row.

    Falls back to nested System.* fields if the top-level shortcut fields are
    missing. Returns time=context.acquisition_time_ms on unparseable timestamps
    rather than 0 — every evtx row has a Time and a zero would skew Phase 4
    log-window features.
    """
    system = row.get("System") or {}

    # EventID — prefer top-level scalar, fall back to System.EventID.Value.
    eid_raw = row.get("EventID")
    if not isinstance(eid_raw, int):
        nested = system.get("EventID")
        if isinstance(nested, dict):
            eid_raw = nested.get("Value")
        elif isinstance(nested, int):
            eid_raw = nested
    event_id = eid_raw if isinstance(eid_raw, int) else None

    # Time — prefer top-level TimeCreated string, fall back to nested SystemTime.
    time_val: Any = row.get("TimeCreated")
    if not time_val:
        nested_time = system.get("TimeCreated")
        if isinstance(nested_time, dict):
            time_val = nested_time.get("SystemTime")
    try:
        time_ms = to_epoch_millis(time_val) if time_val else context.acquisition_time_ms
    except ValueError:
        time_ms = context.acquisition_time_ms

    return EvtxRow(
        event_id=event_id,
        time_ms=time_ms,
        computer=system.get("Computer"),
        event_data=row.get("EventData") or {},
        raw_row=row,
    )
