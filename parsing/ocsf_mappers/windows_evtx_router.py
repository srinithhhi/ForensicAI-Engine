"""Channel-based router for `Windows.EventLogs.Evtx`.

The Windows acquirer calls `Windows.EventLogs.Evtx` three times — once with
`Security.evtx`, once with `System.evtx`, once with
`Microsoft-Windows-Sysmon/Operational.evtx` — under different step names
(event_security, event_system, sysmon). They all produce the same artifact
name in the manifest, so the registry-by-artifact dispatch in
`run_mappers.py` can't tell them apart.

This router solves it the most robust way: by reading the `Channel` field
embedded in each row (Velociraptor stamps it from the source evtx). Rows
without a recognised Channel are skipped (zero events emitted) rather than
forced through an arbitrary mapper.
"""

from __future__ import annotations

from typing import Iterable, Iterator

from parsing.ocsf_base import MapperContext
from parsing.ocsf_mappers import (
    windows_evtx_security,
    windows_evtx_system,
    windows_sysmon,
)

_CHANNEL_DISPATCH = {
    "Security": windows_evtx_security.map_rows,
    "System": windows_evtx_system.map_rows,
    "Microsoft-Windows-Sysmon/Operational": windows_sysmon.map_rows,
}


def map_rows(rows: Iterable[dict], context: MapperContext) -> Iterator[dict]:
    # Group rows by Channel so each sub-mapper sees a homogeneous stream.
    # Loading everything into memory matches the rest of the pipeline (we
    # already buffer in run_mappers for the time-sort); the largest channel
    # buffer is ~35 MB on the current bundles, comfortably small.
    buckets: dict[str, list[dict]] = {}
    for row in rows:
        channel = row.get("Channel")
        if channel not in _CHANNEL_DISPATCH:
            continue
        buckets.setdefault(channel, []).append(row)
    for channel, chan_rows in buckets.items():
        yield from _CHANNEL_DISPATCH[channel](chan_rows, context)
