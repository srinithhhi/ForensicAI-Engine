"""Detection features (class_uid=2004).

Two sources contribute to 2004 Detection Finding events:
- YARA hits — split into process scans (yara_proc step) and filesystem
  glob scans (yara_files step) so the model can weight them differently.
- Sysmon EventID 8 (CreateRemoteThread) + EventID 10 (ProcessAccess) —
  the credential-dump and process-injection signals. Bundled into one
  `sysmon_high_severity_count` because they're rare on benign systems.
"""

from __future__ import annotations


def compute(events: list[dict]) -> dict:
    detections = [e for e in events if e["class_uid"] == 2004]

    proc_hits = sum(1 for e in detections if e["unmapped"].get("source_step") == "yara_proc")
    file_hits = sum(1 for e in detections if e["unmapped"].get("source_step") == "yara_files")
    sysmon_hits = sum(1 for e in detections if e["unmapped"].get("source_step") == "sysmon")

    rules = {e["unmapped"].get("yara_rule") for e in detections if e["unmapped"].get("yara_rule")}

    return {
        "yara_proc_hits": proc_hits,
        "yara_file_hits": file_hits,
        "unique_yara_rules_matched": len(rules),
        "sysmon_high_severity_count": sysmon_hits,
    }
