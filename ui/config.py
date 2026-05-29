"""UI settings — single place for paths and toggles.

Kept dependency-free (no pydantic) so the UI has the same install surface as
the rest of the pipeline. Env overrides are read once at import time.
"""
from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

DATA_RAW = REPO_ROOT / "data" / "raw"
DATA_PROCESSED = REPO_ROOT / "data" / "processed"
DATA_LABELED = REPO_ROOT / "data" / "labeled"

UI_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = UI_DIR / "templates"
STATIC_DIR = UI_DIR / "static"


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


# MISP enrichment during feature extraction. Defaults on (matches the model
# card's training contract); feature_extractor degrades gracefully to ioc_*=0
# if the MISP server is unreachable, so leaving this on is safe offline.
USE_MISP = _env_bool("FORENSICAI_USE_MISP", True)

# Debug mode toggles uvicorn-style verbose errors in the page.
DEBUG = _env_bool("FORENSICAI_DEBUG", False)

# Max upload size (bytes). Bundles are large (tens of MB of NDJSON); cap at
# 500 MB to avoid an accidental memory blowup but allow real bundles.
MAX_UPLOAD_BYTES = int(os.environ.get("FORENSICAI_MAX_UPLOAD_MB", "500")) * 1024 * 1024
