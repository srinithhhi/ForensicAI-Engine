"""Hand-crafted synthetic mid-scenarios for v0.3 training.

Each scenario is a plausible incident a SOC analyst might see — partial
attacks, noisy benign activity, stale traces, or recon-only kill-chain
phases. They occupy the middle of the feature space that the 39 lab
bundles leave empty (full-stack atomic-red-team attacks at one extreme,
fully-clean benign at the other).

Why this exists: v0.2 produces only score_10 ∈ {1, 10} because the
training data has no intermediate-signal examples. Adding ~16 plausible
mid-scenarios teaches the model to score real-world ambiguous incidents
smoothly, combined with sigmoid (not isotonic) calibration in train.py.

The Python module is the source-of-truth; `generate()` writes one JSON
per scenario to data/synthetic/ that validates against
schemas/feature_vector_v1.json.

Usage:
    python3 -m ai_triage.synthetic_scenarios
"""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = REPO_ROOT / "data" / "synthetic"

# ---------- baselines ------------------------------------------------------
# Every scenario starts from one of these and overrides specific features.
# The constants reflect a quiet 4-hour-window observation of a typical host:
# a few legitimate logins, a handful of routine processes, stock SUID files
# on Linux, minor DNS chatter on Windows.

_LINUX_BENIGN: dict = {
    "log_lines_total": 5000, "log_window_hours": 4.0, "event_class_diversity": 4,
    "auth_failure_count": 0, "auth_success_count": 2, "auth_failure_ratio": 0.0,
    "unique_src_ips": 1, "offhours_logins": 0, "new_user_creations": 0,
    "process_count": 10, "elevated_process_count": 1, "suspicious_proc_count": 0,
    "powershell_obfuscation_count": 0, "encoded_command_count": 0,
    "unique_remote_ips": 0, "listen_port_count": 5, "dns_query_count": 0,
    "connections_to_threat_intel_ip": 0,
    "file_integrity_changes": 0, "suid_additions": 24,  # stock Ubuntu SUID count
    "recently_modified_count": 50, "system_file_modifications": 0,
    "tmp_file_creations": 0, "recent_suid_creations": 0,
    "new_persistence_entries": 0, "registry_run_key_changes": 0,
    "cron_entries_added": 0, "service_installs": 0, "startup_items_added": 0,
    "ssh_keys_added": 0, "scheduled_task_creations": 0,
    "ioc_hash_matches": 0, "ioc_ip_matches": 0, "ioc_domain_matches": 0,
    "ioc_match_threat_levels_max": 0,
    "yara_proc_hits": 0, "yara_file_hits": 0, "unique_yara_rules_matched": 0,
    "sysmon_high_severity_count": 0,
}

_WINDOWS_BENIGN: dict = {
    "log_lines_total": 8000, "log_window_hours": 4.0, "event_class_diversity": 5,
    "auth_failure_count": 0, "auth_success_count": 3, "auth_failure_ratio": 0.0,
    "unique_src_ips": 1, "offhours_logins": 0, "new_user_creations": 0,
    "process_count": 15, "elevated_process_count": 2, "suspicious_proc_count": 0,
    "powershell_obfuscation_count": 0, "encoded_command_count": 0,
    "unique_remote_ips": 1, "listen_port_count": 8, "dns_query_count": 12,
    "connections_to_threat_intel_ip": 0,
    "file_integrity_changes": 0, "suid_additions": 0,
    "recently_modified_count": 80, "system_file_modifications": 0,
    "tmp_file_creations": 0, "recent_suid_creations": 0,
    "new_persistence_entries": 0, "registry_run_key_changes": 0,
    "cron_entries_added": 0, "service_installs": 0, "startup_items_added": 0,
    "ssh_keys_added": 0, "scheduled_task_creations": 0,
    "ioc_hash_matches": 0, "ioc_ip_matches": 0, "ioc_domain_matches": 0,
    "ioc_match_threat_levels_max": 0,
    "yara_proc_hits": 0, "yara_file_hits": 0, "unique_yara_rules_matched": 0,
    "sysmon_high_severity_count": 0,
}


def _vec(
    incident_id: str,
    scope: str,
    base: dict,
    overrides: dict,
    is_attack: bool,
    techniques: list[str],
) -> dict:
    feats = deepcopy(base)
    feats.update(overrides)
    return {
        "incident_id": incident_id,
        "scope": "bare_metal" if scope == "linux" else "vmware",
        "schema_version": "v1",
        "features": feats,
        "label": {
            "technique_ids": techniques,
            "is_benign": not is_attack,
        },
    }


# ---------- 16 scenarios ---------------------------------------------------
# Each entry: (incident_id, scope, base, overrides, is_attack, techniques, _description)
# `_description` is for human inspection only — not written to the JSON.

SCENARIOS: list[tuple[str, str, dict, dict, bool, list[str], str]] = [
    # ---- Partial attacks (is_attack=True, weak signal) ----
    (
        "SYNTH-PARTIAL-DISCOVERY-T1083", "linux", _LINUX_BENIGN,
        {"process_count": 18, "suspicious_proc_count": 1, "log_lines_total": 6500},
        True, ["T1083"],
        "find / + ls -laR for recon. No persistence, no drops. Target ~5.",
    ),
    (
        "SYNTH-PARTIAL-DOWNLOAD-NOEXEC", "linux", _LINUX_BENIGN,
        {"tmp_file_creations": 1, "unique_remote_ips": 3, "process_count": 14,
         "ioc_ip_matches": 1, "ioc_match_threat_levels_max": 2},
        True, ["T1105"],
        "wget'd a payload to /tmp, never executed it. Target ~6.",
    ),
    (
        "SYNTH-PARTIAL-LOGIN-NOFOLLOW", "linux", _LINUX_BENIGN,
        {"auth_success_count": 4, "offhours_logins": 1, "unique_src_ips": 2,
         "process_count": 11},
        True, ["T1078"],
        "Suspicious off-hours login from new IP, ran one cmd, logged off. Target ~4.",
    ),
    (
        "SYNTH-PARTIAL-PS-BLOCKED-AV", "windows", _WINDOWS_BENIGN,
        {"encoded_command_count": 1, "powershell_obfuscation_count": 1,
         "tmp_file_creations": 1, "yara_file_hits": 1, "unique_yara_rules_matched": 1,
         "process_count": 19, "unique_remote_ips": 2},
        True, ["T1059.001"],
        "PowerShell IEX-download blocked by AV before payload executed. Target ~7.",
    ),
    (
        "SYNTH-PARTIAL-FAILED-PERSIST", "linux", _LINUX_BENIGN,
        {"elevated_process_count": 2, "process_count": 13,
         "suspicious_proc_count": 1, "auth_failure_count": 1,
         "auth_failure_ratio": 0.33},
        True, ["T1543.002"],
        "Attempted systemd service install, denied (no root). Target ~4.",
    ),

    # ---- Noisy benign (is_attack=False, looks suspicious but isn't) ----
    (
        "SYNTH-BENIGN-DEV-WORKSTATION", "linux", _LINUX_BENIGN,
        {"tmp_file_creations": 8, "ssh_keys_added": 1, "new_persistence_entries": 1,
         "process_count": 35, "unique_remote_ips": 4, "log_lines_total": 15000,
         "log_window_hours": 8.0},
        False, [],
        "Developer compiling code, ssh keys added for staging deploy. Target ~5.",
    ),
    (
        "SYNTH-BENIGN-DBA-MAINTENANCE", "windows", _WINDOWS_BENIGN,
        {"suspicious_proc_count": 2, "process_count": 45,
         "elevated_process_count": 5, "tmp_file_creations": 2,
         "auth_success_count": 8, "log_lines_total": 12000},
        False, [],
        "DBA running backup scripts with certutil for hashing. Target ~4.",
    ),
    (
        "SYNTH-BENIGN-PATCH-WINDOW", "linux", _LINUX_BENIGN,
        {"offhours_logins": 1, "service_installs": 2, "new_persistence_entries": 2,
         "system_file_modifications": 5, "file_integrity_changes": 8,
         "elevated_process_count": 3, "process_count": 22,
         "auth_success_count": 1, "log_lines_total": 7500},
        False, [],
        "Off-hours legitimate patching: service restarts, /usr/lib mods. Target ~6.",
    ),
    (
        "SYNTH-BENIGN-CI-RUNNER", "windows", _WINDOWS_BENIGN,
        {"scheduled_task_creations": 1, "new_persistence_entries": 1,
         "tmp_file_creations": 12, "unique_remote_ips": 8, "process_count": 60,
         "dns_query_count": 45, "log_lines_total": 25000, "log_window_hours": 12.0},
        False, [],
        "CI/CD runner: scheduled tasks, build churn, lots of network. Target ~6.",
    ),

    # ---- Stale traces (is_attack=False, residue not active threat) ----
    (
        "SYNTH-STALE-OLD-SUID", "linux", _LINUX_BENIGN,
        {"suid_additions": 25, "process_count": 8,
         "log_lines_total": 4500},
        False, [],
        "SUID file from prior compromise, patched but file remains. Target ~3.",
    ),
    (
        "SYNTH-STALE-DORMANT-CRON", "linux", _LINUX_BENIGN,
        {"cron_entries_added": 1, "new_persistence_entries": 1,
         "process_count": 9, "log_lines_total": 4800},
        False, [],
        "Legacy cron entry from years ago, never triggered. Target ~4.",
    ),
    (
        "SYNTH-STALE-OLD-SSH-KEYS", "linux", _LINUX_BENIGN,
        {"log_lines_total": 3500, "log_window_hours": 3.5},
        False, [],
        "authorized_keys has departed-engineer entries, no recent auth. Target ~2.",
    ),

    # ---- Reconnaissance only (is_attack=True, kill-chain phase 1) ----
    (
        "SYNTH-RECON-NETWORK-SCAN", "linux", _LINUX_BENIGN,
        {"unique_remote_ips": 25, "process_count": 13, "listen_port_count": 8,
         "log_lines_total": 7000},
        True, ["T1046"],
        "Many short connections to varied IPs, no payload follow-on. Target ~5.",
    ),
    (
        "SYNTH-RECON-DNS-IOC-HITS", "windows", _WINDOWS_BENIGN,
        {"dns_query_count": 65, "ioc_domain_matches": 2,
         "ioc_match_threat_levels_max": 2, "unique_remote_ips": 0,
         "process_count": 18, "log_lines_total": 11000},
        True, ["T1071.004"],
        "DNS lookups to sinkholed suspicious domains, no actual connection. Target ~7.",
    ),
    (
        "SYNTH-RECON-PROC-DISCOVERY", "windows", _WINDOWS_BENIGN,
        {"process_count": 20, "log_lines_total": 9000},
        True, ["T1057"],
        "tasklist + Get-Process executions, then nothing. Target ~3.",
    ),
    (
        "SYNTH-RECON-PASSWORD-SPRAY", "linux", _LINUX_BENIGN,
        {"auth_failure_count": 8, "auth_failure_ratio": 1.0,
         "unique_src_ips": 1, "process_count": 11, "log_lines_total": 5500},
        True, ["T1110.003"],
        "5 failed logins at 3am from one IP, then stopped. Target ~5.",
    ),

    # ---- Extreme-benign anchors (score_10 = 1-3) ----
    # Calibrator needs these to learn "this is unambiguously benign" so
    # real benigns can drift back toward 1-2 from the current ~5.
    (
        "SYNTH-BENIGN-IDLE-HOST", "linux", _LINUX_BENIGN,
        {"process_count": 2, "elevated_process_count": 0, "listen_port_count": 1,
         "dns_query_count": 0, "unique_remote_ips": 0, "auth_success_count": 0,
         "log_lines_total": 800, "log_window_hours": 4.0,
         "event_class_diversity": 2},
        False, [],
        "Server in maintenance window, almost zero activity. Target ~1.",
    ),
    (
        "SYNTH-BENIGN-AIRGAP-QUIET", "linux", _LINUX_BENIGN,
        {"process_count": 3, "elevated_process_count": 0, "listen_port_count": 2,
         "dns_query_count": 0, "unique_remote_ips": 0, "auth_success_count": 0,
         "log_lines_total": 1200, "event_class_diversity": 2},
        False, [],
        "Air-gapped workstation, no network at all. Target ~1.",
    ),
    (
        "SYNTH-BENIGN-ROUTINE-IDLE", "windows", _WINDOWS_BENIGN,
        {"process_count": 4, "elevated_process_count": 0, "listen_port_count": 3,
         "dns_query_count": 3, "unique_remote_ips": 0, "auth_success_count": 0,
         "log_lines_total": 1500, "event_class_diversity": 3},
        False, [],
        "Office workstation overnight, screensaver-only. Target ~2.",
    ),

    # ---- Score_10 ≈ 3 anchors ----
    (
        "SYNTH-LOW-FORGOTTEN-TMP", "linux", _LINUX_BENIGN,
        {"tmp_file_creations": 1, "process_count": 5,
         "elevated_process_count": 0, "log_lines_total": 2200,
         "event_class_diversity": 3},
        False, [],
        "Single old tmp file from forgotten download, no other signal. Target ~3.",
    ),
    (
        "SYNTH-LOW-ROUTINE-CRON", "linux", _LINUX_BENIGN,
        {"cron_entries_added": 1, "new_persistence_entries": 1,
         "process_count": 6, "elevated_process_count": 0,
         "log_lines_total": 2500, "event_class_diversity": 3},
        False, [],
        "Expected logrotate cron entry, no execution in window. Target ~3.",
    ),

    # ---- Score_10 ≈ 6 anchors ----
    (
        "SYNTH-MED-SUSPICIOUS-ONESHOT", "windows", _WINDOWS_BENIGN,
        {"encoded_command_count": 1, "powershell_obfuscation_count": 1,
         "process_count": 18, "log_lines_total": 9000},
        True, ["T1059.001"],
        "One encoded PowerShell command, completed cleanly, no follow-on. Target ~6.",
    ),
    (
        "SYNTH-MED-SINGLE-IOC-HIT", "linux", _LINUX_BENIGN,
        {"unique_remote_ips": 4, "ioc_ip_matches": 1,
         "ioc_match_threat_levels_max": 3, "process_count": 12,
         "log_lines_total": 6000},
        True, ["T1071.001"],
        "Outbound connection to one low-threat MISP IP, no other signal. Target ~6.",
    ),
    (
        "SYNTH-MED-LATERAL-FAILED", "windows", _WINDOWS_BENIGN,
        {"auth_failure_count": 12, "auth_failure_ratio": 1.0,
         "unique_src_ips": 3, "process_count": 16, "log_lines_total": 8500},
        True, ["T1021"],
        "Multiple failed auths from internal IPs, no successful escalation. Target ~6.",
    ),

    # ---- Catastrophic-attack anchors (score_10 = 9-10) ----
    # Calibrator needs these to learn "this is unambiguously critical" so
    # real attacks can drift back toward 9-10 from the current ~7.
    (
        "SYNTH-CRITICAL-RANSOMWARE", "windows", _WINDOWS_BENIGN,
        {"file_integrity_changes": 200, "system_file_modifications": 50,
         "tmp_file_creations": 30, "recently_modified_count": 800,
         "yara_proc_hits": 5, "yara_file_hits": 15, "unique_yara_rules_matched": 4,
         "ioc_hash_matches": 3, "ioc_match_threat_levels_max": 1,
         "new_persistence_entries": 4, "scheduled_task_creations": 2,
         "registry_run_key_changes": 2, "service_installs": 1,
         "sysmon_high_severity_count": 3, "suspicious_proc_count": 8,
         "encoded_command_count": 5, "powershell_obfuscation_count": 4,
         "process_count": 60, "elevated_process_count": 12,
         "unique_remote_ips": 8, "log_lines_total": 45000,
         "log_window_hours": 6.0, "event_class_diversity": 6},
        True, ["T1486"],
        "Live ransomware: mass file mods + IOC + YARA + persistence. Target ~10.",
    ),
    (
        "SYNTH-CRITICAL-CONFIRMED-APT", "windows", _WINDOWS_BENIGN,
        {"ioc_hash_matches": 5, "ioc_ip_matches": 3, "ioc_domain_matches": 4,
         "ioc_match_threat_levels_max": 1,
         "yara_proc_hits": 8, "yara_file_hits": 10, "unique_yara_rules_matched": 6,
         "sysmon_high_severity_count": 4, "new_persistence_entries": 6,
         "scheduled_task_creations": 2, "registry_run_key_changes": 3,
         "service_installs": 1, "startup_items_added": 1,
         "encoded_command_count": 15, "powershell_obfuscation_count": 6,
         "suspicious_proc_count": 10, "process_count": 80,
         "elevated_process_count": 18, "tmp_file_creations": 12,
         "system_file_modifications": 25, "file_integrity_changes": 35,
         "unique_remote_ips": 15, "dns_query_count": 120,
         "log_lines_total": 60000, "log_window_hours": 8.0,
         "event_class_diversity": 6},
        True, ["T1003.001"],
        "Multi-IOC + multi-YARA + multi-persistence + LSASS dump. Target ~10.",
    ),

    # ---- Matched ambiguity pairs (score_10 ≈ 5) ----
    # Each pair has near-identical features with opposite labels. Forces RF
    # trees grown on different bootstraps to see conflicting majorities at
    # this feature region, so tree votes split ~50/50 and the calibrated
    # probability lands near 0.5. The slight feature noise (offhours=1 vs 1,
    # process_count=18 vs 17) prevents the trees from memorizing the pairs
    # as identical exceptions — they generalize to nearby feature space too.

    # PAIR 1 — off-hours sysadmin: legitimate maintenance or insider with creds?
    (
        "SYNTH-AMBIG-OFFHOURS-ADMIN-A", "linux", _LINUX_BENIGN,
        {"offhours_logins": 1, "auth_success_count": 3,
         "elevated_process_count": 4, "process_count": 18,
         "system_file_modifications": 3, "file_integrity_changes": 2,
         "log_lines_total": 6500},
        True, ["T1078"],
        "Off-hours admin login + sudo commands + system file edits. Insider? Target ~5.",
    ),
    (
        "SYNTH-AMBIG-OFFHOURS-ADMIN-B", "linux", _LINUX_BENIGN,
        {"offhours_logins": 1, "auth_success_count": 3,
         "elevated_process_count": 4, "process_count": 17,
         "system_file_modifications": 3, "file_integrity_changes": 2,
         "log_lines_total": 6300},
        False, [],
        "Off-hours admin login + sudo commands + system file edits. Legit ops. Target ~5.",
    ),

    # PAIR 2 — encoded PowerShell: legitimate Configuration Manager or attacker?
    (
        "SYNTH-AMBIG-ENCODED-PS-A", "windows", _WINDOWS_BENIGN,
        {"encoded_command_count": 2, "powershell_obfuscation_count": 1,
         "process_count": 22, "elevated_process_count": 3,
         "log_lines_total": 10000},
        True, ["T1059.001"],
        "Encoded PowerShell with obfuscation marker. Malicious. Target ~5.",
    ),
    (
        "SYNTH-AMBIG-ENCODED-PS-B", "windows", _WINDOWS_BENIGN,
        {"encoded_command_count": 2, "powershell_obfuscation_count": 1,
         "process_count": 21, "elevated_process_count": 3,
         "log_lines_total": 9800},
        False, [],
        "Encoded PowerShell from Configuration Manager / SCCM. Benign. Target ~5.",
    ),

    # (PAIRS 3 & 4 removed — too much middle-anchor weight collapsed the
    # extremes. The 2 surviving pairs above are enough to anchor ~5; the
    # rest is rebalanced via more extreme anchors below.)

    # ---- Additional deeply-benign anchors (score_10 = 1) ----
    (
        "SYNTH-BENIGN-DEEP-IDLE", "linux", _LINUX_BENIGN,
        {"process_count": 1, "elevated_process_count": 0, "listen_port_count": 1,
         "dns_query_count": 0, "unique_remote_ips": 0, "auth_success_count": 0,
         "log_lines_total": 400, "log_window_hours": 4.0,
         "event_class_diversity": 1},
        False, [],
        "Idle VM, only kernel heartbeats. Target ~1.",
    ),
    (
        "SYNTH-BENIGN-EMPTY-SERVER", "linux", _LINUX_BENIGN,
        {"process_count": 2, "elevated_process_count": 0, "listen_port_count": 2,
         "dns_query_count": 0, "unique_remote_ips": 0, "auth_success_count": 0,
         "log_lines_total": 600, "event_class_diversity": 2},
        False, [],
        "Empty server (post-reboot, no app started). Target ~1.",
    ),

    # ---- Additional catastrophic-attack anchors (score_10 = 10) ----
    (
        "SYNTH-CRITICAL-WORM", "windows", _WINDOWS_BENIGN,
        {"unique_remote_ips": 80, "dns_query_count": 200,
         "ioc_ip_matches": 8, "ioc_match_threat_levels_max": 1,
         "yara_proc_hits": 6, "yara_file_hits": 8, "unique_yara_rules_matched": 5,
         "sysmon_high_severity_count": 5, "process_count": 70,
         "elevated_process_count": 15, "suspicious_proc_count": 7,
         "tmp_file_creations": 20, "system_file_modifications": 30,
         "file_integrity_changes": 80, "new_persistence_entries": 5,
         "registry_run_key_changes": 3, "service_installs": 2,
         "encoded_command_count": 8, "powershell_obfuscation_count": 3,
         "log_lines_total": 55000, "log_window_hours": 4.0,
         "event_class_diversity": 6},
        True, ["T1210"],
        "Worm propagation: explosive network + persistence stack. Target ~10.",
    ),
    (
        "SYNTH-CRITICAL-EXFIL", "linux", _LINUX_BENIGN,
        {"unique_remote_ips": 25, "ioc_ip_matches": 4, "ioc_domain_matches": 3,
         "ioc_match_threat_levels_max": 1, "ioc_hash_matches": 2,
         "yara_proc_hits": 4, "yara_file_hits": 7, "unique_yara_rules_matched": 3,
         "tmp_file_creations": 50, "system_file_modifications": 15,
         "file_integrity_changes": 40, "new_persistence_entries": 3,
         "cron_entries_added": 2, "ssh_keys_added": 2,
         "process_count": 55, "elevated_process_count": 12,
         "suspicious_proc_count": 6, "recent_suid_creations": 2,
         "suid_additions": 26, "log_lines_total": 50000,
         "log_window_hours": 6.0, "event_class_diversity": 6},
        True, ["T1041"],
        "Data exfiltration: high outbound + staging + persistence. Target ~10.",
    ),
]


def generate() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    # Sweep stale SYNTH-*.json that aren't in the current scenario list, so
    # removing a scenario from SCENARIOS removes its file too.
    current_ids = {s[0] for s in SCENARIOS}
    for stale in OUT_DIR.glob("SYNTH-*.json"):
        if stale.stem not in current_ids:
            stale.unlink()
            print(f"removed stale {stale.relative_to(REPO_ROOT)}")
    for incident_id, scope, base, overrides, is_attack, techs, _desc in SCENARIOS:
        vec = _vec(incident_id, scope, base, overrides, is_attack, techs)
        out = OUT_DIR / f"{incident_id}.json"
        out.write_text(json.dumps(vec, sort_keys=True, indent=2))
        print(f"wrote {out.relative_to(REPO_ROOT)}")
    print(f"\n{len(SCENARIOS)} synthetic vectors written to {OUT_DIR.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    generate()
