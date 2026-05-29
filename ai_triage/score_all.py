"""Score every v0_state.completed bundle and print the distribution.

Surfaces any naturally-occurring intermediate-score incidents so we can pick
demo bundles for each risk band without synthesizing.
"""
from __future__ import annotations

import json
from collections import Counter

import joblib
import pandas as pd

from .data_loader import LABELED_DIR, REPO_ROOT, SYNTHETIC_DIR, V0_STATE_PATH
from .predict import risk_for, score_10_for

MODEL_PATH = REPO_ROOT / "ai_triage" / "model.pkl"


def main() -> None:
    wanted = {
        e["incident_id"]
        for e in json.loads(V0_STATE_PATH.read_text())["completed"].values()
    }
    bundle = joblib.load(MODEL_PATH)
    model = bundle["model"]
    feature_cols = bundle["feature_cols"]
    scope_encoder = bundle["scope_encoder"]

    rows = []
    sources = (("real", LABELED_DIR, wanted), ("synthetic", SYNTHETIC_DIR, None))
    for source_tag, directory, filter_set in sources:
        if not directory.exists():
            continue
        for p in sorted(directory.glob("*.json")):
            v = json.loads(p.read_text())
            if filter_set is not None and v["incident_id"] not in filter_set:
                continue
            feat = dict(v["features"])
            feat["scope_enc"] = int(scope_encoder.transform([v["scope"]])[0])
            X = pd.DataFrame([feat])[feature_cols].to_numpy()
            score = float(model.predict_proba(X)[0, 1])
            rows.append({
                "incident_id": v["incident_id"],
                "source": source_tag,
                "score": round(score, 4),
                "score_10": score_10_for(score),
                "risk": risk_for(score),
                "is_benign": v["label"]["is_benign"],
                "techniques": ",".join(v["label"]["technique_ids"]) or "-",
            })

    rows.sort(key=lambda r: r["score"])

    print(f"{'incident_id':<34} {'src':<10} {'score':>7} {'10':>3} {'risk':<9} {'techniques'}")
    for r in rows:
        print(
            f"{r['incident_id']:<34} {r['source']:<10} {r['score']:>7.4f} {r['score_10']:>3} "
            f"{r['risk']:<9} {r['techniques']}"
        )

    counts = Counter(r["score_10"] for r in rows)
    print("\nscore_10 distribution:")
    for i in range(1, 11):
        bar = "#" * counts.get(i, 0)
        print(f"  {i:>2}: {counts.get(i, 0):>2}  {bar}")


if __name__ == "__main__":
    main()
