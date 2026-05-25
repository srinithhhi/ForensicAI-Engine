"""Windows.Sys.StartupItems → OCSF System Activity (class_uid 6004).

Enumerates Run/RunOnce key entries and Startup folder shortcuts. Every
enabled entry is severity Medium (3) — this is the persistence-relevant
artifact for T1547.001 (Registry Run Keys) and T1547.009 (Shortcut
Modification).
"""

from __future__ import annotations

from typing import Iterable, Iterator

from parsing.ocsf_base import MapperContext, ocsf_event


def map_rows(rows: Iterable[dict], context: MapperContext) -> Iterator[dict]:
    for row in rows:
        enabled = (row.get("Enabled") or "").lower() == "enabled"
        severity_id = 3 if enabled else 2
        ospath = row.get("OSPath") or ""
        details = row.get("Details") or ""
        message = f"{row.get('Name')}: {details}  [{ospath}]"

        yield ocsf_event(
            class_uid=6004,
            activity_id=0,
            time_ms=context.acquisition_time_ms,
            raw_row=row,
            context=context,
            severity_id=severity_id,
            message=message,
            unmapped_extra={"is_privileged": enabled},
        )
