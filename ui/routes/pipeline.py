"""Upload + scoring routes.

Flow:
    POST /api/upload   multipart ZIP -> extract -> assign fresh INC-UPLOAD-{ts}
                       id -> place at data/raw/{id}/ -> spawn background scoring
                       thread -> return {job_id, incident_id}.
    GET  /api/jobs/{job_id}   poll status + log lines + (when done) result.

Why a fresh incident id per upload: the orchestrator writes
data/labeled/{incident_id}.json, and many of those files are tracked training
vectors. Re-scoring an uploaded copy of a real bundle under its original id
would clobber a training vector. Rewriting the manifest's incident_id to a
unique INC-UPLOAD-{timestamp} keeps training data pristine and guarantees the
dir-name == incident_id invariant score_bundle requires.
"""
from __future__ import annotations

import json
import shutil
import threading
import time
import zipfile
from pathlib import Path

from fastapi import APIRouter, HTTPException, UploadFile
from fastapi.responses import JSONResponse

from ai_triage.score import ScoringError, score_bundle

from .. import config, jobs

router = APIRouter()


def _safe_extract(zf: zipfile.ZipFile, dest: Path) -> None:
    """Extract a zip, rejecting absolute paths and parent traversal (zip-slip)."""
    dest = dest.resolve()
    for member in zf.namelist():
        target = (dest / member).resolve()
        if not str(target).startswith(str(dest)):
            raise HTTPException(400, f"unsafe path in zip: {member}")
    zf.extractall(dest)


def _find_bundle_root(extract_dir: Path) -> Path:
    """Locate the directory containing manifest.json.

    Bundles zip up either flat (manifest.json at the root) or wrapped in a
    single top-level folder. Handle both; reject anything else.
    """
    if (extract_dir / "manifest.json").exists():
        return extract_dir
    children = [p for p in extract_dir.iterdir() if p.is_dir()]
    if len(children) == 1 and (children[0] / "manifest.json").exists():
        return children[0]
    raise HTTPException(
        400,
        "could not find manifest.json in the uploaded zip (expected it at the "
        "root or inside a single top-level folder)",
    )


def _find_sim_manifest(extract_dir: Path) -> Path | None:
    """Locate a simulation_manifest.json anywhere in the extracted tree.

    Optional. When present, feature_extractor uses its `started_at` to window
    file/persistence/auth features to the attack period (matching how the
    training vectors were extracted) and its `runs[].technique_id` for the
    incident label. Bundles uploaded without one are scored unwindowed, which
    inflates file-based features — so demo bundles should include it.
    """
    candidates = [
        extract_dir / "simulation_manifest.json",
        *extract_dir.rglob("simulation_manifest.json"),
    ]
    for c in candidates:
        if c.is_file():
            return c
    return None


def _find_misp_cache(extract_dir: Path) -> Path | None:
    """Locate a misp_cache.json in the extracted tree (optional).

    When present and restored to data/processed/{id}/, the feature extractor
    serves every IOC lookup from cache instead of the network — so ioc_*
    features reproduce offline (no live MISP server needed). Cache MISSes never
    hit the network when the whole bundle's IOC set is already cached.
    """
    candidates = [
        extract_dir / "misp_cache.json",
        *extract_dir.rglob("misp_cache.json"),
    ]
    for c in candidates:
        if c.is_file():
            return c
    return None


def _run_scoring(job_id: str, raw_dir: Path) -> None:
    """Background worker: run the full pipeline, streaming logs into the job."""
    log = lambda line: jobs.store.log(job_id, line)
    jobs.store.set_status(job_id, jobs.RUNNING)
    try:
        result = score_bundle(raw_dir, use_misp=config.USE_MISP, log=log)
        jobs.store.finish(job_id, result)
        log("done.")
    except ScoringError as exc:
        jobs.store.fail(job_id, str(exc))
        log(f"FAILED: {exc}")
    except Exception as exc:  # noqa: BLE001 - surface any pipeline crash to the UI
        jobs.store.fail(job_id, f"unexpected error: {exc}")
        log(f"FAILED: unexpected error: {exc}")


@router.post("/api/upload")
async def upload(file: UploadFile) -> JSONResponse:
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(400, "please upload a .zip bundle")

    incident_id = f"INC-UPLOAD-{time.strftime('%Y%m%d-%H%M%S')}"
    raw_dir = config.DATA_RAW / incident_id
    if raw_dir.exists():
        # Same-second collision — extremely unlikely, but keep ids unique.
        incident_id = f"{incident_id}-{int(time.time() * 1000) % 1000:03d}"
        raw_dir = config.DATA_RAW / incident_id

    tmp_dir = config.DATA_RAW / f".tmp-{incident_id}"
    tmp_zip = config.DATA_RAW / f".tmp-{incident_id}.zip"
    config.DATA_RAW.mkdir(parents=True, exist_ok=True)

    # Stream the upload to disk with a size guard.
    size = 0
    try:
        with tmp_zip.open("wb") as out:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > config.MAX_UPLOAD_BYTES:
                    raise HTTPException(413, "upload exceeds size limit")
                out.write(chunk)

        if not zipfile.is_zipfile(tmp_zip):
            raise HTTPException(400, "uploaded file is not a valid zip")

        tmp_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(tmp_zip) as zf:
            _safe_extract(zf, tmp_dir)

        bundle_root = _find_bundle_root(tmp_dir)

        # Rewrite the manifest's incident_id so labeled output lands under the
        # fresh upload id and never overwrites a tracked training vector.
        manifest_path = bundle_root / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["incident_id"] = incident_id
        manifest_path.write_text(json.dumps(manifest, indent=2))

        # If the bundle carries a simulation manifest / MISP cache, read them
        # now (before the move) so we can install them under the fresh id: the
        # sim manifest drives windowed extraction, the cache reproduces ioc_*
        # features offline.
        sim_manifest_src = _find_sim_manifest(tmp_dir)
        sim_manifest_text = sim_manifest_src.read_text() if sim_manifest_src else None
        misp_cache_src = _find_misp_cache(tmp_dir)
        misp_cache_text = misp_cache_src.read_text() if misp_cache_src else None

        # Move the bundle into place at data/raw/{incident_id}/.
        if bundle_root != tmp_dir:
            shutil.move(str(bundle_root), str(raw_dir))
        else:
            shutil.move(str(tmp_dir), str(raw_dir))
            tmp_dir = None  # consumed by the move

        # Install the sim manifest where feature_extractor looks for it:
        # data/simulations/{incident_id}/simulation_manifest.json.
        if sim_manifest_text is not None:
            sim_dir = config.REPO_ROOT / "data" / "simulations" / incident_id
            sim_dir.mkdir(parents=True, exist_ok=True)
            (sim_dir / "simulation_manifest.json").write_text(sim_manifest_text)

        # Pre-place the MISP cache in the processed dir. run_mappers later does
        # mkdir(exist_ok=True) and only writes events.ndjson, so this survives.
        if misp_cache_text is not None:
            proc_dir = config.DATA_PROCESSED / incident_id
            proc_dir.mkdir(parents=True, exist_ok=True)
            (proc_dir / "misp_cache.json").write_text(misp_cache_text)
    finally:
        tmp_zip.unlink(missing_ok=True)
        if tmp_dir is not None and tmp_dir.exists():
            shutil.rmtree(tmp_dir, ignore_errors=True)

    job = jobs.store.create()
    jobs.store.set_incident(job.job_id, incident_id)

    thread = threading.Thread(
        target=_run_scoring, args=(job.job_id, raw_dir), daemon=True
    )
    thread.start()

    return JSONResponse({"job_id": job.job_id, "incident_id": incident_id})


@router.get("/api/jobs/{job_id}")
async def job_status(job_id: str) -> JSONResponse:
    job = jobs.store.get(job_id)
    if job is None:
        raise HTTPException(404, "no such job")
    return JSONResponse(job.to_dict())
