"""Linux.Sys.Crontab → OCSF System Activity (class_uid 6004).

Velociraptor's Crontab returns one row per cron entry across user crontabs
and /etc/cron.{d,daily,hourly,monthly,weekly}. Most healthy hosts have zero
custom cron entries — empty input yields zero events (and that's valid).

When present, each row describes a scheduled command — we emit a generic
system activity event with the command stored in `message` so Phase 4
persistence-feature aggregation can count `cron_entries_added`.
"""

from __future__ import annotations

from typing import Iterable, Iterator

from parsing.ocsf_base import MapperContext, ocsf_event


def map_rows(rows: Iterable[dict], context: MapperContext) -> Iterator[dict]:
    for row in rows:
        # Schemas vary by source; common keys are Command, Schedule, User,
        # OSPath. We pass the row through verbatim in raw_data and emit a
        # message summarising the schedule + command for human readability.
        command = row.get("Command") or row.get("CommandLine") or ""
        schedule = row.get("Schedule") or ""
        user = row.get("User") or row.get("Username")
        msg = f"{schedule} {command}".strip()

        actor = {"user": {"name": user, "uid": None}} if user else None

        yield ocsf_event(
            class_uid=6004,
            activity_id=0,
            time_ms=context.acquisition_time_ms,
            raw_row=row,
            context=context,
            severity_id=2,  # cron entries are notable for persistence
            actor=actor,
            message=msg or None,
        )
