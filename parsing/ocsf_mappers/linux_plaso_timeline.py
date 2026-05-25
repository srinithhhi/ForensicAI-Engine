"""Custom.Linux.Forensics.PlasoTimeline → OCSF events.

Plaso runs forensic timeline extraction across the bundled forensic targets
(wtmp, syslog rotations, dpkg/apt logs, etc.) and emits a single row whose
`raw_csv` field is a multi-line CSV of timeline events.

We parse that CSV and emit one OCSF event per row. Most plaso events come
from utmp / wtmp / syslog / dpkg sources — we route them to:
- 3002 Authentication when source is UTMP (login/logout/boot)
- 6004 System Activity for everything else (the bulk: package installs,
  log content modifications, file metadata changes)

Timestamps in the CSV use `MM/DD/YYYY,HH:MM:SS,timezone` — we parse with
`datetime.strptime` and stamp epoch millis.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from typing import Iterable, Iterator

from parsing.ocsf_base import MapperContext, ocsf_event

# Plaso "source" column values that map to Authentication (3002).
# UTMP entries are "User: X PID: Y Status: ..." — login/logout/boot/shutdown.
_AUTH_SOURCETYPES = {"UTMP session"}


def _parse_plaso_time(date: str, time_str: str, tz: str) -> int:
    """Return epoch millis from plaso's MM/DD/YYYY,HH:MM:SS,TZ triple.

    Plaso only ever emits UTC in our custom artifact (the artifact passes
    `--timezone UTC`), but we honour `tz` defensively. Unknown tz → assume UTC.
    """
    try:
        dt = datetime.strptime(f"{date} {time_str}", "%m/%d/%Y %H:%M:%S")
    except ValueError:
        return 0
    # Treat anything other than literal "UTC" as still-UTC. Plaso never emits
    # offsets we can't handle, but if it did we'd lose <= a few hours of skew.
    dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def map_rows(rows: Iterable[dict], context: MapperContext) -> Iterator[dict]:
    for row in rows:
        raw_csv = row.get("raw_csv") or ""
        if not raw_csv.strip():
            continue
        reader = csv.DictReader(io.StringIO(raw_csv))
        for entry in reader:
            sourcetype = entry.get("sourcetype") or ""
            time_ms = _parse_plaso_time(
                entry.get("date", ""),
                entry.get("time", ""),
                entry.get("timezone", "UTC"),
            )
            if time_ms == 0:
                time_ms = context.acquisition_time_ms

            user = entry.get("user") or None
            if user == "-":
                user = None
            host = entry.get("host") or None
            description = (entry.get("desc") or "")[:500]

            actor = {"user": {"name": user, "uid": None}} if user else None
            src_endpoint = {"hostname": host} if host else None

            if sourcetype in _AUTH_SOURCETYPES:
                class_uid = 3002
                activity_id = 1  # Logon (UTMP sessions broadly = logon/logoff)
                severity_id = 2
            else:
                class_uid = 6004
                activity_id = 0
                severity_id = 1

            yield ocsf_event(
                class_uid=class_uid,
                activity_id=activity_id,
                time_ms=time_ms,
                raw_row=entry,
                context=context,
                severity_id=severity_id,
                actor=actor,
                src_endpoint=src_endpoint,
                message=description or None,
            )
