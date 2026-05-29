"""Load labeled feature vectors into a pandas DataFrame for training/eval."""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
LABELED_DIR = REPO_ROOT / "data" / "labeled"
SYNTHETIC_DIR = REPO_ROOT / "data" / "synthetic"
V0_STATE_PATH = REPO_ROOT / "data" / "experiments" / "v0_state.json"

# Ambient lab-signature features identified in model_card.md §"Honest
# interpretation". These reflect collection-environment differences between
# attack and benign runs (longer windows, more events, more logins, more
# background file touches) rather than attack behavior. Dropping them forces
# the model to find signal in the attack-specific features.
DROP_FEATURES: frozenset[str] = frozenset({
    "log_window_hours",
    "log_lines_total",
    "recently_modified_count",
    "auth_success_count",
})


def _experiment_incident_ids() -> set[str]:
    state = json.loads(V0_STATE_PATH.read_text())
    return {entry["incident_id"] for entry in state["completed"].values()}


def _row_from_vec(vec: dict, source: str) -> dict:
    row = {"incident_id": vec["incident_id"], "scope": vec["scope"], "source": source}
    row.update(vec["features"])
    row["is_attack"] = not vec["label"]["is_benign"]
    row["technique_ids"] = ",".join(vec["label"]["technique_ids"])
    return row


def load_dataset(experiment_only: bool = True, include_synthetic: bool = True) -> pd.DataFrame:
    """Return one row per labeled incident.

    Columns: incident_id, scope, source, <feature names>, is_attack, technique_ids.
    - `experiment_only=True` keeps only the 39 v0_state.completed real bundles
      (excludes 2 pre-experiment dev bundles in data/labeled/).
    - `include_synthetic=True` also pulls vectors from data/synthetic/ — the
      hand-crafted mid-scenarios. Each row gets `source` = "real" or "synthetic"
      so evaluate.py can split metrics by population.
    """
    wanted = _experiment_incident_ids() if experiment_only else None
    rows: list[dict] = []
    for path in sorted(LABELED_DIR.glob("*.json")):
        vec = json.loads(path.read_text())
        if wanted is not None and vec["incident_id"] not in wanted:
            continue
        rows.append(_row_from_vec(vec, source="real"))
    if include_synthetic and SYNTHETIC_DIR.exists():
        for path in sorted(SYNTHETIC_DIR.glob("*.json")):
            vec = json.loads(path.read_text())
            rows.append(_row_from_vec(vec, source="synthetic"))
    df = pd.DataFrame(rows).sort_values("incident_id").reset_index(drop=True)
    return df


def feature_columns(df: pd.DataFrame) -> list[str]:
    """The numeric feature columns the model trains on (incl. scope_enc).

    Excludes DROP_FEATURES — the ambient lab-signature features that
    dominated v0.1's top importances without representing attack behavior.
    """
    meta = {"incident_id", "scope", "source", "is_attack", "technique_ids"}
    return [c for c in df.columns if c not in meta and c not in DROP_FEATURES]
