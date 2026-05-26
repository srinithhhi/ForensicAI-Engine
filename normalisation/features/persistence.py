"""Persistence features.

Five counts that combine to form the most direct attack-signal feature group.
`new_persistence_entries` is the sum — kept as a separate feature so the
model has both an aggregate and its parts.

Source dispatching:
- cron_entries_added       → 6004 events, source_step=cron
- service_installs         → 6004 events with EventID 7045 (Windows service
                              install) OR source_step=systemd severity>=3
- startup_items_added      → 6004 events from source_step=startup_items
                              with severity_id>=3 (enabled startup entries)
- registry_run_key_changes → 1001 events with event_id=13 (Sysmon Registry
                              value set) OR source_step=startup_items
"""

from __future__ import annotations

_RUN_KEY_SUBSTRINGS = ("\\Run\\", "\\RunOnce\\", "\\StartupApproved\\", "\\Run/", "\\RunOnce/")


def _path_of(event: dict) -> str:
    actor = event.get("actor") or {}
    proc = actor.get("process") or {}
    f = proc.get("file") or {}
    return f.get("path") or ""


def compute(events: list[dict]) -> dict:
    cron_count = sum(1 for e in events if e["unmapped"].get("source_step") == "cron")

    service_installs = 0
    for e in events:
        if e["unmapped"].get("event_id") == 7045:
            service_installs += 1
            continue
        if (
            e["unmapped"].get("source_step") == "systemd"
            and e.get("severity_id", 0) >= 3
        ):
            service_installs += 1

    startup_count = sum(
        1 for e in events
        if e["unmapped"].get("source_step") == "startup_items"
        and e.get("severity_id", 0) >= 3
    )

    registry_run_changes = 0
    for e in events:
        if e["class_uid"] != 1001:
            continue
        if e["unmapped"].get("event_id") != 13:
            continue
        # Sysmon EID 13 stores the target registry key in actor.process.file.path
        # or in the raw_row's TargetObject; we check the file path first.
        path = _path_of(e)
        if any(s in path for s in _RUN_KEY_SUBSTRINGS):
            registry_run_changes += 1
            continue
        # Fall back to scanning raw_data for TargetObject when path is empty.
        raw = e.get("raw_data") or ""
        if any(s.lower() in raw.lower() for s in _RUN_KEY_SUBSTRINGS):
            registry_run_changes += 1

    new_persistence_entries = cron_count + service_installs + startup_count

    return {
        "new_persistence_entries": new_persistence_entries,
        "registry_run_key_changes": registry_run_changes,
        "cron_entries_added": cron_count,
        "service_installs": service_installs,
        "startup_items_added": startup_count,
    }
