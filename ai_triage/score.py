"""Phase 6 orchestrator: raw Velociraptor bundle -> calibrated risk score.

Chains the three existing pipeline stages end-to-end so the UI (and any other
caller) can go from a `data/raw/{incident_id}/` bundle to a prediction dict in
one call:

    Stage 1  parsing.run_mappers        raw bundle -> data/processed/{id}/events.ndjson
    Stage 2  normalisation.feature_extractor  events -> data/labeled/{id}.json
    Stage 3  ai_triage.predict          labeled vector -> {risk, score, score_10, ...}

The function returns the Stage-3 prediction dict augmented with the raw OCSF
events list (under "events") for the M2 timeline. It also stashes the loaded
feature vector under "features" so the dashboard "why this score" panel can
render without re-reading the labeled file.

Pipeline contract notes (verified against the actual stage signatures):

- `feature_extractor` derives its incident_id + scope from
  `data/raw/{processed_dir.name}/manifest.json`, and writes the labeled vector
  under the manifest's `incident_id`. For that read to resolve, the raw bundle
  directory name MUST equal the manifest's `incident_id`. The upload route is
  responsible for placing bundles at `data/raw/{manifest_incident_id}/`; this
  module asserts the invariant rather than silently producing a vector under a
  different id than the caller expects.
- `run_mappers.run` returns an exit code, not data. Code 3 means the bundle or
  manifest is missing (fatal — no events written). Codes 1 (unmapped artifact)
  and 2 (dead-letter ratio over threshold) are soft: events.ndjson is still
  written, so we log and continue.
- `feature_extractor.run` returns 0 only when the labeled vector was written
  and validated. Any non-zero code means `predict` would fail with
  FileNotFoundError, so we raise a clear error here instead.

CLI:
    python -m ai_triage.score data/raw/INC-WIN-20260527-101631
    python -m ai_triage.score data/raw/INC-X --no-misp
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Callable

from normalisation import feature_extractor
from parsing import run_mappers

from .data_loader import REPO_ROOT
from .predict import predict

PROCESSED_DIR = REPO_ROOT / "data" / "processed"

LogFn = Callable[[str], None]


class ScoringError(RuntimeError):
    """Raised when a pipeline stage fails fatally (no usable result)."""


def _read_manifest_incident_id(raw_dir: Path) -> str:
    manifest_path = raw_dir / "manifest.json"
    if not manifest_path.exists():
        raise ScoringError(f"manifest not found: {manifest_path}")
    try:
        manifest = json.loads(manifest_path.read_text())
    except json.JSONDecodeError as exc:
        raise ScoringError(f"manifest is not valid JSON: {manifest_path} ({exc})")
    incident_id = manifest.get("incident_id")
    if not incident_id:
        raise ScoringError(f"manifest has no incident_id: {manifest_path}")
    return incident_id


def _load_events(events_path: Path) -> list[dict]:
    if not events_path.exists():
        return []
    events: list[dict] = []
    with events_path.open() as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def score_bundle(
    raw_dir: Path,
    *,
    use_misp: bool = True,
    log: LogFn = print,
) -> dict:
    """End-to-end: a raw bundle directory -> prediction dict (+ events, features).

    `raw_dir` must be `data/raw/{incident_id}` where the directory name matches
    the manifest's incident_id (see module docstring for why). `log` receives
    human-readable progress lines and defaults to print; the UI passes a job
    logger so the same messages stream to the browser.
    """
    raw_dir = Path(raw_dir).resolve()
    if not raw_dir.is_dir():
        raise ScoringError(f"raw bundle directory not found: {raw_dir}")

    incident_id = _read_manifest_incident_id(raw_dir)
    if raw_dir.name != incident_id:
        raise ScoringError(
            f"bundle directory name {raw_dir.name!r} does not match manifest "
            f"incident_id {incident_id!r}. The pipeline reads "
            f"data/raw/{{incident_id}}/manifest.json, so the bundle must live "
            f"at data/raw/{incident_id}/."
        )

    processed_dir = PROCESSED_DIR / incident_id

    # Stage 1 — OCSF mapping.
    log(f"[1/3] OCSF mapping {incident_id} ...")
    rc = run_mappers.run(raw_dir, processed_dir)
    if rc == 3:
        raise ScoringError(
            f"OCSF mapping failed: malformed manifest or missing bundle (rc=3)"
        )
    if rc == 1:
        log("      note: some artifacts had no mapper and were skipped (rc=1)")
    elif rc == 2:
        log("      warning: dead-letter ratio exceeded threshold (rc=2)")
    events_path = processed_dir / "events.ndjson"
    events = _load_events(events_path)
    log(f"      mapped {len(events):,} events -> {events_path}")

    # Stage 2 — feature extraction (writes data/labeled/{incident_id}.json).
    log(f"[2/3] extracting features (MISP={'on' if use_misp else 'off'}) ...")
    rc = feature_extractor.run(processed_dir, use_misp=use_misp)
    if rc != 0:
        raise ScoringError(
            f"feature extraction failed (rc={rc}) — no labeled vector written, "
            f"cannot score. Check the logs above for schema/validation errors."
        )

    # Stage 3 — predict.
    log("[3/3] scoring ...")
    result = predict(incident_id)
    log(
        f"      risk={result['risk']} score_10={result['score_10']} "
        f"p={result['score']}"
    )

    # Attach extras the dashboard / timeline consume directly.
    labeled_path = REPO_ROOT / "data" / "labeled" / f"{incident_id}.json"
    vector = json.loads(labeled_path.read_text())
    result["features"] = vector.get("features", {})
    result["scope"] = vector.get("scope")
    result["label"] = vector.get("label", {})
    result["events"] = events
    result["event_count"] = len(events)

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "raw_dir",
        type=Path,
        help="Path to data/raw/{incident_id} bundle directory",
    )
    parser.add_argument(
        "--no-misp",
        action="store_true",
        help="Skip MISP lookups; ioc_* features become 0.",
    )
    args = parser.parse_args()
    try:
        result = score_bundle(args.raw_dir, use_misp=not args.no_misp)
    except ScoringError as exc:
        print(f"[score] FATAL: {exc}", file=sys.stderr)
        return 1
    # Drop the bulky events list from the CLI summary.
    summary = {k: v for k, v in result.items() if k != "events"}
    summary["event_count"] = result.get("event_count", 0)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
