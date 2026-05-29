"""Predict risk for one labeled incident.

Usage:  python3 -m ai_triage.predict --incident INC-20260526-162052
Output: {"incident_id": "...", "risk": "...", "score": 0.xxxx, "model_version": "..."}
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import pandas as pd

from .data_loader import DEMO_DIR, REPO_ROOT, SYNTHETIC_DIR

MODEL_PATH = REPO_ROOT / "ai_triage" / "model.pkl"
LABELED_DIR = REPO_ROOT / "data" / "labeled"


def _find_vector(incident_id: str) -> Path:
    """Look in data/labeled/, data/synthetic/, then data/demo/."""
    for d in (LABELED_DIR, SYNTHETIC_DIR, DEMO_DIR):
        candidate = d / f"{incident_id}.json"
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        f"No labeled vector for {incident_id} in labeled/, synthetic/, or demo/"
    )

# Locked thresholds — must match docs/PHASE5_HANDOFF.md §3.
# Highest threshold first so the iteration short-circuits correctly.
THRESHOLDS = (
    (0.85, "critical"),
    (0.55, "high"),
    (0.25, "med"),
    (0.0, "low"),
)

# Band-aligned 1-10 score. Each risk band maps to a contiguous integer range
# with linear interpolation inside the band, so score_10 and risk always
# tell a consistent story (a "med" never shows up as 6+, a "high" never as 5-).
#   low      (p < 0.25)         -> 1-2
#   med      (0.25 <= p < 0.55) -> 3-5
#   high     (0.55 <= p < 0.85) -> 6-8
#   critical (p >= 0.85)        -> 9-10
_BAND_RANGES = (
    # (lower_p, upper_p, lower_int, upper_int)
    (0.00, 0.25, 1,  2),
    (0.25, 0.55, 3,  5),
    (0.55, 0.85, 6,  8),
    (0.85, 1.01, 9, 10),  # upper bound 1.01 so p=1.0 lands in this band
)


def risk_for(score: float) -> str:
    for threshold, label in THRESHOLDS:
        if score >= threshold:
            return label
    return "low"


def score_10_for(score: float) -> int:
    """Map a 0-1 probability to a 1-10 integer that respects risk bands."""
    p = max(0.0, min(1.0, score))
    for lo_p, hi_p, lo_i, hi_i in _BAND_RANGES:
        if lo_p <= p < hi_p:
            # Linear interpolate within the band, then round.
            interp = lo_i + (p - lo_p) / (hi_p - lo_p) * (hi_i - lo_i)
            return int(round(interp))
    return 10  # only reachable on p > 1.0 (shouldn't happen post-clamp)


def predict(incident_id: str) -> dict:
    bundle = joblib.load(MODEL_PATH)
    model = bundle["model"]
    feature_cols = bundle["feature_cols"]
    scope_encoder = bundle["scope_encoder"]

    vec = json.loads(_find_vector(incident_id).read_text())

    row = dict(vec["features"])
    row["scope_enc"] = int(scope_encoder.transform([vec["scope"]])[0])
    X = pd.DataFrame([row])[feature_cols].to_numpy()
    score = float(model.predict_proba(X)[0, 1])

    return {
        "incident_id": incident_id,
        "risk": risk_for(score),
        "score": round(score, 4),
        "score_10": score_10_for(score),
        "model_version": bundle["model_version"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--incident", required=True, help="e.g. INC-20260526-162052")
    args = parser.parse_args()
    print(json.dumps(predict(args.incident), indent=2))


if __name__ == "__main__":
    main()
