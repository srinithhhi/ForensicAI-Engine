"""File-system features (class_uid=1001).

Splits 1001 events by source_step to isolate AIDE diffs (file_integrity_changes)
from FileFinder mtime sweeps (recently_modified_count) from SUID-flagged
files (suid_additions). `system_file_modifications` counts ANY 1001 event
whose target path lives under a high-value system directory — this is the
cross-cutting "attacker touched something they shouldn't" signal.
"""

from __future__ import annotations

_SYSTEM_PREFIXES = (
    "/etc/", "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/var/spool/cron/",
    "/root/", "/boot/",
    "C:\\Windows\\", "C:/Windows/", "C:\\Program Files\\", "C:/Program Files/",
)


def _path_of(event: dict) -> str | None:
    return ((event.get("actor") or {}).get("process") or {}).get("file", {}).get("path")


def compute(events: list[dict]) -> dict:
    files = [e for e in events if e["class_uid"] == 1001]

    aide = sum(1 for e in files if e["unmapped"].get("source_step") == "aide_diff")
    recently = sum(1 for e in files if e["unmapped"].get("source_step") == "recently_modified")
    suid = sum(1 for e in files if e["unmapped"].get("is_privileged") is True)

    system_mods = 0
    for e in files:
        path = _path_of(e) or ""
        if path.startswith(_SYSTEM_PREFIXES):
            system_mods += 1

    return {
        "file_integrity_changes": aide,
        "suid_additions": suid,
        "recently_modified_count": recently,
        "system_file_modifications": system_mods,
    }
