"""Linux.Sys.Services → OCSF System Activity (class_uid 6004).

Velociraptor's Services artifact returns one row per systemd unit, listing
its Active/Load/Sub state at collection time. We emit one event per unit so
Phase 4 can count `service_installs` (delta against a baseline) and surface
new persistence units.
"""

from __future__ import annotations

from typing import Iterable, Iterator

from parsing.ocsf_base import MapperContext, ocsf_event


def map_rows(rows: Iterable[dict], context: MapperContext) -> Iterator[dict]:
    for row in rows:
        unit = row.get("Unit")
        active = row.get("Active")
        # Failed/inactive units flagged at Medium severity so they surface in
        # downstream aggregates; active/loaded units stay informational.
        severity = 3 if active in ("failed", "inactive") else 1
        message = f"{unit}: {row.get('Load')}/{active}/{row.get('Sub')} — {row.get('Description', '')}"

        yield ocsf_event(
            class_uid=6004,
            activity_id=0,
            time_ms=context.acquisition_time_ms,
            raw_row=row,
            context=context,
            severity_id=severity,
            message=message,
        )
