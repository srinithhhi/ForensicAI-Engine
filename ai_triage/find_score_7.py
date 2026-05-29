"""Search for a feature vector that scores in the high band (score_10=7).

Strategy: start from a real attack vector (score=1.0), progressively zero
out features in importance order, and report which ablations land where on
the 1-10 scale. Reveals whether the isotonic-calibrated probabilities have
a usable middle range or jump straight from low to critical.

If a vector lands in [0.625, 0.775) → score_10=7, save it to
data/labeled/SMOKE-MILD-7.json so predict.py can score it.
"""
from __future__ import annotations

import copy
import json
from itertools import combinations

import joblib
import pandas as pd

from .data_loader import LABELED_DIR, REPO_ROOT
from .predict import risk_for, score_10_for

MODEL_PATH = REPO_ROOT / "ai_triage" / "model.pkl"
ATTACK_BASE = "INC-20260526-162052"  # T1053.003 cron - chosen as base attack

# Features ranked by RF importance (from v0.2 training). Ablate in order to
# strip away the strongest attack signals first.
ABLATION_ORDER = [
    "tmp_file_creations",
    "system_file_modifications",
    "yara_proc_hits",
    "process_count",
    "offhours_logins",
    "new_persistence_entries",
    "file_integrity_changes",
    "unique_remote_ips",
    "yara_file_hits",
    "encoded_command_count",
    "powershell_obfuscation_count",
    "suspicious_proc_count",
    "elevated_process_count",
    "cron_entries_added",
    "service_installs",
    "startup_items_added",
    "ssh_keys_added",
    "scheduled_task_creations",
    "registry_run_key_changes",
    "ioc_hash_matches",
    "sysmon_high_severity_count",
]


def _score(model, feature_cols, scope_encoder, base_vec: dict, overrides: dict) -> float:
    feat = dict(base_vec["features"])
    feat.update(overrides)
    feat["scope_enc"] = int(scope_encoder.transform([base_vec["scope"]])[0])
    X = pd.DataFrame([feat])[feature_cols].to_numpy()
    return float(model.predict_proba(X)[0, 1])


def main() -> None:
    bundle = joblib.load(MODEL_PATH)
    model = bundle["model"]
    feature_cols = bundle["feature_cols"]
    scope_encoder = bundle["scope_encoder"]

    base_path = LABELED_DIR / f"{ATTACK_BASE}.json"
    base_vec = json.loads(base_path.read_text())
    base_score = _score(model, feature_cols, scope_encoder, base_vec, {})
    print(f"base attack {ATTACK_BASE}: score={base_score:.4f} score_10={score_10_for(base_score)}")
    print()

    # Cumulative ablation: zero out features one at a time, top of importance
    # list first. Tracks how fast the score collapses.
    print(f"{'ablated':<35} {'score':>7} {'10':>3} {'risk':<9}")
    print("-" * 60)
    overrides: dict = {}
    rows = []
    for i, feat_name in enumerate(ABLATION_ORDER, 1):
        overrides[feat_name] = 0
        score = _score(model, feature_cols, scope_encoder, base_vec, overrides)
        s10 = score_10_for(score)
        rows.append((tuple(overrides.keys()), score, s10))
        label = f"+ zero {feat_name}"
        print(f"{label:<35} {score:>7.4f} {s10:>3} {risk_for(score):<9}")

    # Look for any ablation set landing in score_10=7 territory.
    in_band = [(keys, s, s10) for (keys, s, s10) in rows if s10 == 7]
    print()
    if in_band:
        keys, s, s10 = in_band[0]
        print(f"FOUND score_10=7 at score={s:.4f}, zeroing: {list(keys)}")
        synth_id = "SMOKE-MILD-7"
        synth = copy.deepcopy(base_vec)
        synth["incident_id"] = synth_id
        for k in keys:
            synth["features"][k] = 0
        # Mark as not-benign with empty techniques (synthetic, no real label).
        synth["label"] = {"technique_ids": [], "is_benign": False}
        out = LABELED_DIR / f"{synth_id}.json"
        out.write_text(json.dumps(synth, sort_keys=True, indent=2))
        print(f"wrote {out}")
        print(f"verify: python3 -m ai_triage.predict --incident {synth_id}")
    else:
        print("No ablation hit score_10=7.")
        print("Reachable score_10 values via cumulative ablation:")
        reachable = sorted({s10 for (_, _, s10) in rows})
        print(f"  {reachable}")
        print()
        print("This means the isotonic calibrator's step function skips over")
        print("the 7 band. Partial-feature ablation alone cannot land there.")
        print("Options: try combo-of-2 ablations, switch base bundle, or accept")
        print("that v0.2's calibration doesn't expose this band.")


if __name__ == "__main__":
    main()
