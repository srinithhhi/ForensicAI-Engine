"""FastAPI entry point for the ForensicAI dashboard.

Run (dev):
    uvicorn ui.app:app --reload
Then open http://localhost:8000

M1 surface:
    GET  /                       landing (two mode tiles)
    GET  /upload                 upload form (drag-drop)
    POST /api/upload             accept zip, start scoring        (routes/pipeline)
    GET  /api/jobs/{job_id}      poll scoring status              (routes/pipeline)
    GET  /dashboard/{id}         results page (score card + features)
"""
from __future__ import annotations

import json

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import joblib
import numpy as np

from ai_triage.predict import MODEL_PATH, predict

from . import config, explain
from .routes import pipeline, timeline as timeline_routes

app = FastAPI(title="ForensicAI Triage", debug=config.DEBUG)
app.include_router(pipeline.router)
app.include_router(timeline_routes.router)

app.mount("/static", StaticFiles(directory=str(config.STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(config.TEMPLATES_DIR))


def _load_feature_importance() -> list[tuple[str, float]]:
    """Read mean RF feature importances from the calibrated model bundle.

    Ordered descending. The dashboard surfaces the top of this list so the
    feature panel reflects what the model actually weighs — not a guessed
    ordering. Falls back to an empty list if the model can't be read (the
    dashboard then shows features in schema order).
    """
    try:
        bundle = joblib.load(MODEL_PATH)
        cols = bundle["feature_cols"]
        model = bundle["model"]
        per_tree = [c.estimator.feature_importances_ for c in model.calibrated_classifiers_]
        imp = np.mean(per_tree, axis=0)
        ranked = sorted(zip(cols, imp), key=lambda kv: kv[1], reverse=True)
        return [(name, float(score)) for name, score in ranked]
    except Exception:  # noqa: BLE001 - dashboard must render even if model load fails
        return []


# Importance ordering computed once at startup. scope_enc is a model-internal
# encoding of the bundle scope, not a forensic signal — hide it from the panel.
_HIDDEN_FEATURES = {"scope_enc"}
FEATURE_IMPORTANCE = [
    (name, score)
    for name, score in _load_feature_importance()
    if name not in _HIDDEN_FEATURES
]
_IMPORTANCE_BY_NAME = dict(FEATURE_IMPORTANCE)


def _load_dataset_maxima() -> dict[str, float]:
    """Per-feature maximum across the training population (labeled+synthetic).

    Used to normalize feature values into a 0-1 "how unusual" scale for the
    contribution bars. Computed once at startup; empty dict on any failure so
    the dashboard still renders (bars then fall back to importance-only).
    """
    try:
        from ai_triage.data_loader import load_dataset

        df = load_dataset(experiment_only=False, include_synthetic=True)
        numeric = df.select_dtypes(include="number")
        return {col: float(numeric[col].max()) for col in numeric.columns}
    except Exception:  # noqa: BLE001
        return {}


DATASET_MAX = _load_dataset_maxima()


def _dashboard_context(incident_id: str) -> dict:
    """Build dashboard data from disk: re-run predict + load the feature vector.

    Predict is cheap (loads a 1.2 MB model + scores one row), so the dashboard
    is reconstructable from disk independent of the ephemeral job store — a
    refresh or a direct link still works.
    """
    labeled_path = config.DATA_LABELED / f"{incident_id}.json"
    if not labeled_path.exists():
        raise HTTPException(404, f"no scored incident {incident_id!r}")
    vector = json.loads(labeled_path.read_text())
    result = predict(incident_id)

    features = vector.get("features", {})
    feature_rows = explain.feature_contributions(
        features, _IMPORTANCE_BY_NAME, DATASET_MAX, top_n=10
    )
    why = explain.why_bullets(features, _IMPORTANCE_BY_NAME, max_bullets=5)
    return {
        "incident_id": incident_id,
        "result": result,
        "scope": vector.get("scope"),
        "label": vector.get("label", {}),
        "features": features,
        "feature_rows": feature_rows,
        "why_bullets": why,
    }


@app.get("/", response_class=HTMLResponse)
async def landing(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("landing.html", {"request": request})


@app.get("/upload", response_class=HTMLResponse)
async def upload_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("upload.html", {"request": request})


@app.get("/dashboard/{incident_id}", response_class=HTMLResponse)
async def dashboard(request: Request, incident_id: str) -> HTMLResponse:
    ctx = _dashboard_context(incident_id)
    ctx["request"] = request
    return templates.TemplateResponse("dashboard.html", ctx)
