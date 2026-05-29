"""Plain-English reasoning + feature-contribution ranking for the dashboard.

Two consumers:
  - feature_contributions(): the M2 feature bars. A feature's contribution is
    (value / dataset_max) * model_importance — i.e. "how unusually high is this
    incident's value, weighted by how much the model cares about the feature."
  - why_bullets(): the "why this score" panel. Hand-crafted rules map raw
    feature values to SOC-readable sentences, ordered by the driving feature's
    model importance so the highest-signal evidence floats to the top.

Both read model importances + dataset maxima computed once at startup (the
maxima come from the same labeled+synthetic population the model trained on).
Nothing here re-scores or contradicts the model — it only explains the vector
the model already scored.
"""
from __future__ import annotations

from typing import Callable, Optional

# Each rule: feature -> (threshold, template). The template receives the value.
# `template` returns the bullet text. Ordering across triggered rules is by the
# feature's model importance, not by this list order.
RuleFn = Callable[[float], str]
_RULES: dict[str, tuple[float, RuleFn]] = {
    "yara_proc_hits": (0, lambda n: f"YARA process detection — {int(n)} in-memory rule hits"),
    "yara_file_hits": (0, lambda n: f"YARA file detection — {int(n)} on-disk rule hits"),
    "unique_yara_rules_matched": (1, lambda n: f"{int(n)} distinct YARA rules matched"),
    "sysmon_high_severity_count": (0, lambda n: f"Sysmon credential-access / injection — {int(n)} high-severity events"),
    "ioc_hash_matches": (0, lambda n: f"{int(n)} process hashes matched MISP threat-intel IOCs"),
    "ioc_ip_matches": (0, lambda n: f"{int(n)} connections to MISP-flagged IP IOCs"),
    "ioc_domain_matches": (0, lambda n: f"{int(n)} lookups of MISP-flagged domain IOCs"),
    "connections_to_threat_intel_ip": (0, lambda n: f"{int(n)} sessions to known threat-intel infrastructure"),
    "new_persistence_entries": (0, lambda n: f"Persistence stack — {int(n)} new entries (cron / service / startup)"),
    "service_installs": (0, lambda n: f"{int(n)} new service installs (T1543)"),
    "scheduled_task_creations": (0, lambda n: f"{int(n)} scheduled tasks created (T1053)"),
    "registry_run_key_changes": (0, lambda n: f"{int(n)} Run-key registry changes (T1547.001)"),
    "startup_items_added": (0, lambda n: f"{int(n)} startup items added"),
    "cron_entries_added": (0, lambda n: f"{int(n)} cron entries added"),
    "ssh_keys_added": (0, lambda n: f"{int(n)} authorized_keys entries added (T1098.004)"),
    "new_user_creations": (0, lambda n: f"{int(n)} new user accounts created (T1136)"),
    "encoded_command_count": (0, lambda n: f"{int(n)} base64/encoded command invocations"),
    "powershell_obfuscation_count": (0, lambda n: f"{int(n)} obfuscated PowerShell invocations"),
    "tmp_file_creations": (0, lambda n: f"{int(n)} files staged in tmp directories"),
    "suid_additions": (0, lambda n: f"{int(n)} SUID binaries present (privilege-escalation surface)"),
    "recent_suid_creations": (0, lambda n: f"{int(n)} SUID binaries created in-window"),
    "elevated_process_count": (0, lambda n: f"{int(n)} elevated / privileged processes"),
    "suspicious_proc_count": (0, lambda n: f"{int(n)} processes flagged suspicious"),
    "offhours_logins": (0, lambda n: f"{int(n)} off-hours logins"),
    "auth_failure_count": (4, lambda n: f"{int(n)} authentication failures (possible spray / brute force)"),
    "unique_remote_ips": (20, lambda n: f"{int(n)} distinct remote IPs contacted"),
}


def feature_contributions(
    features: dict,
    importance: dict[str, float],
    dataset_max: dict[str, float],
    top_n: int = 10,
) -> list[dict]:
    """Rank features by (value/dataset_max) * importance. Highest first.

    Returns rows of {name, value, importance, contribution, fill_pct} where
    fill_pct is the contribution normalized to the top row (0-100) for bar
    widths. Features the model never weighs (importance 0) or absent from the
    vector are skipped.
    """
    rows: list[dict] = []
    for name, value in features.items():
        imp = importance.get(name, 0.0)
        if imp <= 0:
            continue
        dmax = dataset_max.get(name, 0.0) or 0.0
        norm = (value / dmax) if dmax > 0 else 0.0
        norm = min(norm, 1.0)  # clamp; an incident above the training max pins at 1
        contribution = norm * imp
        rows.append(
            {
                "name": name,
                "value": value,
                "importance": imp,
                "contribution": contribution,
            }
        )
    rows.sort(key=lambda r: r["contribution"], reverse=True)
    rows = rows[:top_n]
    top = rows[0]["contribution"] if rows and rows[0]["contribution"] > 0 else 0.0
    for r in rows:
        r["fill_pct"] = (r["contribution"] / top * 100.0) if top > 0 else 0.0
    return rows


def why_bullets(
    features: dict,
    importance: dict[str, float],
    max_bullets: int = 5,
) -> list[dict]:
    """Hand-crafted evidence bullets, ordered by driving-feature importance.

    Returns [{text, feature, value, importance}]. 3-5 highest-signal bullets.
    """
    triggered: list[dict] = []
    for feature, (threshold, template) in _RULES.items():
        value = features.get(feature)
        if value is None:
            continue
        if value > threshold:
            triggered.append(
                {
                    "text": template(value),
                    "feature": feature,
                    "value": value,
                    "importance": importance.get(feature, 0.0),
                }
            )
    triggered.sort(key=lambda b: b["importance"], reverse=True)
    return triggered[:max_bullets]
