"""Persistence features.

Five counts that combine to form the most direct attack-signal feature group.
`new_persistence_entries` is the sum — kept as a separate feature so the
model has both an aggregate and its parts.

Source dispatching is fallback-style: each feature checks multiple sources
because Velociraptor's dedicated persistence artifacts (Linux.Sys.Crontab,
Linux.Sys.Services for service installs) are unreliable on 0.76.x. The
recently_modified FileFinder sweep with broadened globs catches anything
those artifacts miss — see `acquisition/bare_metal_acquirer.RECENTLY_MODIFIED_GLOB`.

| Feature                    | Sources (any match → +1)                            |
|----------------------------|------------------------------------------------------|
| cron_entries_added         | source_step=cron rows  OR  recently_modified events  |
|                            | with path under /etc/cron*/ or /var/spool/cron/      |
| service_installs           | Windows EID 7045  OR  source_step=systemd sev≥3      |
|                            | OR  recently_modified path under /etc/systemd/system |
|                            | or /usr/lib/systemd/system (filtered to `.service`)  |
| startup_items_added        | source_step=startup_items sev≥3 (Windows)            |
| registry_run_key_changes   | Sysmon EID 13 with Run-key substring in path/raw     |
"""

from __future__ import annotations

_RUN_KEY_SUBSTRINGS = (
    "\\Run\\", "\\RunOnce\\", "\\StartupApproved\\",
    "\\Run/", "\\RunOnce/",
)

# Path prefixes that, when seen in recently_modified file events, indicate
# a cron-mediated persistence entry was created or touched.
_CRON_PATH_PREFIXES = (
    "/etc/cron.d/",
    "/etc/cron.daily/",
    "/etc/cron.hourly/",
    "/etc/cron.weekly/",
    "/etc/cron.monthly/",
    "/var/spool/cron/",
)
# Exact files we don't count (root crontab itself is a single file but its
# *contents* change is interesting — leaving the file path counted is fine;
# the parent-prefix matchers above won't double-count it since /etc/crontab
# isn't under any of the dir prefixes).
_CRON_PATH_EXACT = ("/etc/crontab",)

_SYSTEMD_PATH_PREFIXES = (
    "/etc/systemd/system/",
    "/usr/lib/systemd/system/",
)

# Authorized-keys persistence (T1098.004). The atomic-installed key lives in
# either /root/.ssh/authorized_keys or /home/<user>/.ssh/authorized_keys. The
# recently_modified glob covers both. Match on substring (not prefix) so we
# catch authorized_keys2 / authorized_keys.tmp variants too.
_SSH_KEY_PATH_SUBSTRINGS = (
    "/.ssh/authorized_keys",
)

# Scheduled task persistence (T1053.005). Detected via Sysmon EID 11
# (FileCreate) whose TargetFilename lives under C:\Windows\System32\Tasks\.
# This is the persistence artifact path — schtasks.exe / Register-ScheduledTask
# both eventually cause svchost to write the task XML there.
_SCHED_TASK_PATH_SUBSTRINGS = (
    "\\Windows\\System32\\Tasks\\",
    "C:/Windows/System32/Tasks/",
)


def _path_of(event: dict) -> str:
    actor = event.get("actor") or {}
    proc = actor.get("process") or {}
    f = proc.get("file") or {}
    return f.get("path") or ""


def _is_recently_modified_file(event: dict, since_ms: int | None) -> bool:
    """True if this event came from the FileFinder recently_modified step
    AND its mtime is at or after the simulation start time (when provided).

    `since_ms` defaults to None which disables the time-window filter — used
    for real (unsimulated) incidents and tests. When set (always set by
    feature_extractor for simulated bundles), it excludes file mtimes from
    earlier bundles that the 24h MoreRecentThan acquisition window would
    otherwise surface (e.g. /etc/passwd mtimes left over from a prior
    bundle's T1078.003 atomic + its userdel cleanup).
    """
    if event["class_uid"] != 1001:
        return False
    if event["unmapped"].get("source_step") != "recently_modified":
        return False
    if since_ms is not None and event.get("time", 0) < since_ms:
        return False
    return True


def _cron_path_match(path: str) -> bool:
    return any(path.startswith(p) for p in _CRON_PATH_PREFIXES) or path in _CRON_PATH_EXACT


def _systemd_path_match(path: str) -> bool:
    if not any(path.startswith(p) for p in _SYSTEMD_PATH_PREFIXES):
        return False
    # Only count .service / .timer / .socket units — exclude .wants/, .d/
    # directory entries which are routine systemd refresh artifacts.
    return path.endswith((".service", ".timer", ".socket"))


def _ssh_keys_path_match(path: str) -> bool:
    return any(s in path for s in _SSH_KEY_PATH_SUBSTRINGS)


def compute(events: list[dict], *, simulation_started_ms: int | None = None) -> dict:
    cron_count = 0
    seen_cron_paths: set[str] = set()
    for e in events:
        # Dedicated source (currently broken — keeps the door open for when
        # Linux.Sys.Crontab is fixed in a later Velociraptor release).
        if e["unmapped"].get("source_step") == "cron":
            cron_count += 1
            continue
        # FileFinder evidence — gated by simulation_started_ms to exclude
        # carry-over mtimes from prior bundles.
        if _is_recently_modified_file(e, simulation_started_ms):
            path = _path_of(e)
            if path and _cron_path_match(path) and path not in seen_cron_paths:
                seen_cron_paths.add(path)
                cron_count += 1

    service_installs = 0
    seen_unit_paths: set[str] = set()
    for e in events:
        # EID 7045 / systemd-source-step paths are EVTX-time-based — without
        # window filter, every service install in System.evtx since boot
        # would count (huge inflation on Windows bundles).
        if e["unmapped"].get("event_id") == 7045:
            if simulation_started_ms is not None and e.get("time", 0) < simulation_started_ms:
                continue
            service_installs += 1
            continue
        if (
            e["unmapped"].get("source_step") == "systemd"
            and e.get("severity_id", 0) >= 3
        ):
            # Linux.Sys.Services is a snapshot — no time gating (it shows
            # what's loaded right now).
            service_installs += 1
            continue
        if _is_recently_modified_file(e, simulation_started_ms):
            path = _path_of(e)
            if path and _systemd_path_match(path) and path not in seen_unit_paths:
                seen_unit_paths.add(path)
                service_installs += 1

    startup_count = sum(
        1 for e in events
        if e["unmapped"].get("source_step") == "startup_items"
        and e.get("severity_id", 0) >= 3
    )

    ssh_keys_count = 0
    seen_ssh_paths: set[str] = set()
    for e in events:
        if not _is_recently_modified_file(e, simulation_started_ms):
            continue
        path = _path_of(e)
        if path and _ssh_keys_path_match(path) and path not in seen_ssh_paths:
            seen_ssh_paths.add(path)
            ssh_keys_count += 1

    # Scheduled-task persistence — Sysmon EID 11 with target under Tasks dir.
    # Read TargetFilename from raw_data (Velociraptor's EventData payload).
    sched_task_count = 0
    seen_task_paths: set[str] = set()
    import json as _json
    for e in events:
        if e["unmapped"].get("source_step") != "sysmon":
            continue
        if e["unmapped"].get("event_id") != 11:
            continue
        if simulation_started_ms is not None and e.get("time", 0) < simulation_started_ms:
            continue
        try:
            raw = _json.loads(e.get("raw_data") or "{}")
        except _json.JSONDecodeError:
            continue
        target = (raw.get("EventData") or {}).get("TargetFilename") or ""
        if any(s in target for s in _SCHED_TASK_PATH_SUBSTRINGS) and target not in seen_task_paths:
            seen_task_paths.add(target)
            sched_task_count += 1

    registry_run_changes = 0
    for e in events:
        if e["class_uid"] != 1001:
            continue
        if e["unmapped"].get("event_id") != 13:
            continue
        # Sysmon EID 13 is real-time event-logged — gate by sim window so we
        # don't count every Run-key write since the Sysmon log started.
        if simulation_started_ms is not None and e.get("time", 0) < simulation_started_ms:
            continue
        path = _path_of(e)
        if any(s in path for s in _RUN_KEY_SUBSTRINGS):
            registry_run_changes += 1
            continue
        raw = e.get("raw_data") or ""
        if any(s.lower() in raw.lower() for s in _RUN_KEY_SUBSTRINGS):
            registry_run_changes += 1

    new_persistence_entries = (
        cron_count + service_installs + startup_count
        + ssh_keys_count + sched_task_count + registry_run_changes
    )

    return {
        "new_persistence_entries": new_persistence_entries,
        "registry_run_key_changes": registry_run_changes,
        "cron_entries_added": cron_count,
        "service_installs": service_installs,
        "startup_items_added": startup_count,
        "ssh_keys_added": ssh_keys_count,
        "scheduled_task_creations": sched_task_count,
    }
