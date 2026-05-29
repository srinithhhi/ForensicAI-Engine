"""Timeline endpoint — JSON the Plotly replay animates."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from .. import config
from ..timeline_data import build_timeline

router = APIRouter()


@router.get("/api/timeline/{incident_id}")
async def timeline(incident_id: str) -> JSONResponse:
    processed_dir = config.DATA_PROCESSED / incident_id
    if not processed_dir.is_dir():
        raise HTTPException(404, f"no processed events for {incident_id!r}")
    return JSONResponse(build_timeline(processed_dir))
