"""Train the v0 RandomForest classifier, calibrate, and persist via joblib.

Usage:  python3 -m ai_triage.train
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path

import joblib
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import LeaveOneOut, cross_val_predict
from sklearn.preprocessing import LabelEncoder

from .data_loader import REPO_ROOT, feature_columns, load_dataset

MODEL_VERSION = "rf-v0.3"
MODEL_PATH = REPO_ROOT / "ai_triage" / "model.pkl"


def _prepare(df):
    scope_encoder = LabelEncoder().fit(df["scope"])
    df = df.copy()
    df["scope_enc"] = scope_encoder.transform(df["scope"])
    cols = feature_columns(df)
    X = df[cols].to_numpy()
    y = df["is_attack"].astype(int).to_numpy()
    return X, y, cols, scope_encoder


def train() -> None:
    df = load_dataset(experiment_only=True, include_synthetic=True)
    n_real = int((df["source"] == "real").sum())
    n_syn = int((df["source"] == "synthetic").sum())
    print(f"training on {len(df)} vectors ({n_real} real + {n_syn} synthetic)")
    X, y, feature_cols, scope_encoder = _prepare(df)

    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=8,
        class_weight="balanced",
        random_state=42,
    )

    # Honest LOO-CV — refits the model n times, one held-out incident each.
    loo_proba = cross_val_predict(
        rf, X, y, cv=LeaveOneOut(), method="predict_proba"
    )
    loo_auc = roc_auc_score(y, loo_proba[:, 1])
    print(f"LOO-CV AUC (uncalibrated RF): {loo_auc:.3f}")

    # Fit a separate RF on the full data just to surface feature importance —
    # so we can see whether the dropped-ambient-features mitigation worked.
    rf_full = RandomForestClassifier(
        n_estimators=200, max_depth=8, class_weight="balanced", random_state=42,
    ).fit(X, y)
    ranked = sorted(zip(feature_cols, rf_full.feature_importances_), key=lambda kv: -kv[1])
    print("Top-10 feature importances (post-drop):")
    for name, imp in ranked[:10]:
        print(f"  {imp:.4f}  {name}")

    # Final calibrated estimator fit on the full training set.
    # Sigmoid (Platt) calibration — smooth parametric curve over [0,1],
    # produces continuous probabilities. Switched from isotonic (v0.2)
    # which was a step function on the bimodal training set and could
    # only emit ~6 distinct probabilities. Sigmoid plays well with the
    # mid-scenario synthetic vectors that anchor intermediate signal.
    calibrated = CalibratedClassifierCV(rf, method="sigmoid", cv=5).fit(X, y)

    bundle = {
        "model": calibrated,
        "feature_cols": feature_cols,
        "scope_encoder": scope_encoder,
        "model_version": MODEL_VERSION,
        "trained_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "n_train": int(len(df)),
        "n_train_real": n_real,
        "n_train_synthetic": n_syn,
        "loo_auc": float(loo_auc),
    }
    joblib.dump(bundle, MODEL_PATH)
    print(
        f"saved model_version={MODEL_VERSION} "
        f"n_train={bundle['n_train']} -> {MODEL_PATH.relative_to(REPO_ROOT)}"
    )


if __name__ == "__main__":
    train()
