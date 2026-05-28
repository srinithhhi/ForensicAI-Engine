"""Detection features (class_uid=2004).

Two sources contribute to 2004 Detection Finding events:
- YARA hits — split into process scans (yara_proc step) and filesystem
  glob scans (yara_files step). YARA artifacts are SNAPSHOTS (they scan
  whatever processes/files exist at acquisition time), so no time gating
  is needed — count all of them.
- Sysmon EventID 8 (CreateRemoteThread) + EventID 10 (ProcessAccess) —
  the credential-dump and process-injection signals. These are real-time
  log events, so we MUST gate by simulation_started_ms — otherwise every
  Sysmon EID 8/10 ever logged would inflate the count (Windows lab VMs
  routinely have ~50 baseline EID 10 events from legitimate process
  inspection by AV/EDR/credentials APIs).
"""

from __future__ import annotations


def compute(events: list[dict], *, simulation_started_ms: int | None = None) -> dict:
    detections = [e for e in events if e["class_uid"] == 2004]

    proc_hits = sum(1 for e in detections if e["unmapped"].get("source_step") == "yara_proc")
    file_hits = sum(1 for e in detections if e["unmapped"].get("source_step") == "yara_files")

    # sysmon: gate by sim window since Sysmon events are time-stamped log
    # entries, not snapshots.
    sysmon_hits = 0
    for e in detections:
        if e["unmapped"].get("source_step") != "sysmon":
            continue
        if simulation_started_ms is not None and e.get("time", 0) < simulation_started_ms:
            continue
        sysmon_hits += 1

    rules = {e["unmapped"].get("yara_rule") for e in detections if e["unmapped"].get("yara_rule")}

    return {
        "yara_proc_hits": proc_hits,
        "yara_file_hits": file_hits,
        "unique_yara_rules_matched": len(rules),
        "sysmon_high_severity_count": sysmon_hits,
    }
