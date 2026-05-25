"""Windows.System.Powershell.PSReadline → OCSF System Activity (class_uid 6004).

PSReadline keeps per-user PowerShell command history in
`%APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt`.
We emit one event per line (skipping blank lines). Time source is the file's
Mtime — PSReadline does not write per-line timestamps.

PowerShell commands are a strong attack signal — even informational events
here can carry T1059.001 / T1027 / T1140 indicators in the command text.
"""

from __future__ import annotations

from typing import Iterable, Iterator

from parsing.ocsf_base import MapperContext, ocsf_event, to_epoch_millis


def map_rows(rows: Iterable[dict], context: MapperContext) -> Iterator[dict]:
    for row in rows:
        line = row.get("Line")
        if not line or not line.strip():
            continue
        stat = row.get("Stat") or {}
        mtime = stat.get("Mtime")
        try:
            time_ms = to_epoch_millis(mtime) if mtime else context.acquisition_time_ms
        except ValueError:
            time_ms = context.acquisition_time_ms

        actor = {
            "user": {"name": row.get("Username"), "uid": None},
        }

        # Heuristic: lines containing the obvious obfuscation/encoded-command
        # markers get bumped to Medium severity so Phase 4 can count them.
        lower = line.lower()
        severity_id = 2  # bash_history baseline
        if "-encodedcommand" in lower or "frombase64string" in lower or "iex (new-object" in lower:
            severity_id = 4

        yield ocsf_event(
            class_uid=6004,
            activity_id=0,
            time_ms=time_ms,
            raw_row=row,
            context=context,
            severity_id=severity_id,
            actor=actor,
            message=line,
        )
