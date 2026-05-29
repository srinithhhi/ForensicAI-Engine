"""LOO-CV evaluation report for RF + LogReg, including per-technique recall.

Usage:  python3 -m ai_triage.evaluate
"""
from __future__ import annotations

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    brier_score_loss,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import LeaveOneOut, cross_val_predict
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.pipeline import make_pipeline

from .data_loader import feature_columns, load_dataset


def _matrix(df):
    df = df.copy()
    df["scope_enc"] = LabelEncoder().fit_transform(df["scope"])
    cols = feature_columns(df)
    X = df[cols].to_numpy()
    y = df["is_attack"].astype(int).to_numpy()
    return X, y, df


def _report(name: str, model, X, y):
    probs = cross_val_predict(
        model, X, y, cv=LeaveOneOut(), method="predict_proba"
    )[:, 1]
    preds = (probs >= 0.5).astype(int)
    print(f"\n=== {name} (LOO-CV) ===")
    print(f"  AUC:   {roc_auc_score(y, probs):.3f}")
    print(f"  Brier: {brier_score_loss(y, probs):.3f}")
    print("  Confusion matrix (rows=truth, cols=pred) [benign, attack]:")
    print(f"    {confusion_matrix(y, preds).tolist()}")
    print(classification_report(y, preds, target_names=["benign", "attack"]))
    return probs


def _per_technique_recall(df, probs):
    print("\nPer-technique recall (RF, threshold=0.5):")
    techs = sorted({t for t in df["technique_ids"] if t})
    for tech in techs:
        mask = (df["technique_ids"] == tech).to_numpy()
        n = int(mask.sum())
        recall = float((probs[mask] >= 0.5).mean()) if n else 0.0
        print(f"  {tech:<30} n={n}  recall={recall:.2f}")


def evaluate() -> None:
    df = load_dataset(experiment_only=True)
    X, y, df = _matrix(df)

    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=8,
        class_weight="balanced",
        random_state=42,
    )
    # LogReg needs scaling — features span many orders of magnitude.
    logreg = make_pipeline(
        StandardScaler(),
        LogisticRegression(max_iter=2000, class_weight="balanced"),
    )

    rf_probs = _report("RandomForest", rf, X, y)
    _report("LogisticRegression", logreg, X, y)
    _per_technique_recall(df, rf_probs)


if __name__ == "__main__":
    evaluate()
