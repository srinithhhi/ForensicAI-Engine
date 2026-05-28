"""File-system features (class_uid=1001).

Splits 1001 events by source_step to isolate AIDE diffs (file_integrity_changes)
from FileFinder mtime sweeps (recently_modified_count) from SUID-flagged
files (suid_additions). `system_file_modifications` counts ANY 1001 event
whose target path lives under a high-value system directory — this is the
cross-cutting "attacker touched something they shouldn't" signal.

`tmp_file_creations` is the drop-target signal for T1105-style ingress
tool transfer: distinct files in /tmp, /var/tmp, /dev/shm modified during
the simulation window. Gated by simulation_started_ms so background /tmp
churn between bundles doesn't bleed across.

`recent_suid_creations` catches T1548.001 (Setuid/Setgid). Velociraptor's
FileFinder preserves the file Mode in raw_data using Go's os.FileMode
encoding — bit 1<<23 is ModeSetuid. Stock SUID files (counted by the
static `suid_additions` from Linux.Sys.SUID) have an unchanging baseline
of ~24 on a clean Ubuntu, so dynamic SUID-bit setting is invisible at
that aggregate. This feature finds the actual attacker-installed SUID
file via per-event Mode inspection.
"""

from __future__ import annotations

import json

# Go's os.FileMode encoding constants — used by Velociraptor's FileFinder.
# See: https://pkg.go.dev/os#FileMode  ModeSetuid = 1 << 23.
_GO_MODE_SETUID = 1 << 23

_SYSTEM_PREFIXES = (
    "/etc/", "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/var/spool/cron/",
    "/root/", "/boot/",
    "C:\\Windows\\", "C:/Windows/", "C:\\Program Files\\", "C:/Program Files/",
)

# Paths an attacker drops payloads into. Linux uses /tmp/* and friends;
# Windows uses %TEMP% (which expands per-user under AppData\Local\Temp\),
# system temp (C:\Windows\Temp\), and the user Downloads folder. We match
# both forward- and back-slash variants because Velociraptor on Windows
# emits backslash paths but normalisation elsewhere may use slashes.
_TMP_PATH_SUBSTRINGS = (
    "/tmp/", "/var/tmp/", "/dev/shm/",            # Linux drop targets
    "\\AppData\\Local\\Temp\\",                    # Windows per-user %TEMP%
    "/AppData/Local/Temp/",
    "\\Windows\\Temp\\", "C:/Windows/Temp/",       # Windows system temp
    "\\Downloads\\", "/Downloads/",                # Windows browser downloads
)


def _path_of(event: dict) -> str | None:
    return ((event.get("actor") or {}).get("process") or {}).get("file", {}).get("path")


def compute(events: list[dict], *, simulation_started_ms: int | None = None) -> dict:
    files = [e for e in events if e["class_uid"] == 1001]

    aide = sum(1 for e in files if e["unmapped"].get("source_step") == "aide_diff")
    recently = sum(1 for e in files if e["unmapped"].get("source_step") == "recently_modified")
    suid = sum(1 for e in files if e["unmapped"].get("is_privileged") is True)

    system_mods = 0
    for e in files:
        path = _path_of(e) or ""
        if path.startswith(_SYSTEM_PREFIXES):
            system_mods += 1

    # tmp_file_creations: distinct files in tmp/var/tmp/dev/shm modified during
    # the simulation window. Distinct path dedupe so the same file touched
    # twice (mtime + ctime) only counts once.
    tmp_paths: set[str] = set()
    # recent_suid_creations: distinct files modified in window with SUID bit
    # set in their Velociraptor-reported Mode integer.
    suid_paths: set[str] = set()
    for e in files:
        if e["unmapped"].get("source_step") != "recently_modified":
            continue
        if simulation_started_ms is not None and e.get("time", 0) < simulation_started_ms:
            continue
        path = _path_of(e) or ""
        if not path:
            continue
        if any(s in path for s in _TMP_PATH_SUBSTRINGS):
            tmp_paths.add(path)
        # Parse raw_data for the Mode integer — only present on FileFinder rows.
        try:
            raw = json.loads(e.get("raw_data") or "{}")
        except json.JSONDecodeError:
            continue
        mode = raw.get("Mode")
        if isinstance(mode, int) and (mode & _GO_MODE_SETUID):
            suid_paths.add(path)

    return {
        "file_integrity_changes": aide,
        "suid_additions": suid,
        "recently_modified_count": recently,
        "system_file_modifications": system_mods,
        "tmp_file_creations": len(tmp_paths),
        "recent_suid_creations": len(suid_paths),
    }
