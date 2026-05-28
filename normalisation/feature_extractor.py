"""Phase 4 driver: events.ndjson → labeled feature vector.

Reads:
- `data/processed/{incident_id}/events.ndjson` (Phase 3 output)
- `data/simulations/{incident_id}/simulation_manifest.json` (optional label
  source — present for simulated bundles, absent for real incidents)
- MISP server (optional — graceful degradation if unreachable)

Writes:
- `data/labeled/{incident_id}.json` (validates against
  `schemas/feature_vector_v1.json`)
- `data/processed/{incident_id}/misp_cache.json` (replayability cache)

CLI:
    python -m normalisation.feature_extractor data/processed/INC-X
    python -m normalisation.feature_extractor data/processed/INC-X --no-misp

Exit codes:
    0  feature vector written and validated
    1  schema validation failed
    2  events.ndjson missing or malformed
    3  bundle metadata problem (no scope, no incident_id)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import jsonschema

from normalisation.features import (
    auth,
    detection,
    file as file_features,
    ioc,
    meta,
    network,
    persistence,
    process,
)
from normalisation.misp_client import MispClient, CACHE_FILENAME

REPO_ROOT = Path(__file__).resolve().parent.parent
FEATURE_SCHEMA_PATH = REPO_ROOT / "schemas" / "feature_vector_v1.json"
SCHEMA_VERSION = "v1"


def _parse_iso8601_ms(s: str | None) -> int | None:
    """Parse an ISO 8601 timestamp string into epoch ms, or return None."""
    if not s:
        return None
    from datetime import datetime, timezone
    try:
        # Normalise trailing Z to +00:00 for fromisoformat (Python <3.11).
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except (ValueError, TypeError):
        return None


# Clock-skew tolerance applied to the simulation window. Originally 300s
# (5 min) — wide enough to absorb the observed ~20s Windows VM clock skew,
# but turned out to be TOO wide: Linux bundles cleaning up an atomic-created
# user (`userdel`) re-touch /etc/passwd ~2-5 minutes before the NEXT bundle's
# simulation starts. With 5-min grace, those cleanup mtimes were counted as
# the new bundle's own user-creation signal → false positives in LB-08
# (T1098.004+T1543.002 falsely showed new_user_creations=1) and in LB-11
# (BENIGN falsely showed new_user_creations=1).
#
# 60s is wide enough for the worst-case clock skew + atomic execution lag we
# observed (~20s on Windows VM, plus the few-second gap between manifest
# creation and SSH connect) but tight enough that the previous bundle's
# cleanup (which always runs after acquisition completes, i.e. ~12-15
# minutes before the next bundle starts) never falls inside this window.
WINDOW_BACKWARD_GRACE_SEC = 60


def _load_events(processed_dir: Path) -> list[dict]:
    events_path = processed_dir / "events.ndjson"
    if not events_path.exists():
        raise FileNotFoundError(f"events.ndjson not found at {events_path}")
    events: list[dict] = []
    with events_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line))
    return events


def _load_label_and_window(simulations_dir: Path, incident_id: str) -> tuple[dict, int | None]:
    """Read simulation_manifest.json. Return ({technique_ids, is_benign}, started_at_ms).

    Returns started_at_ms=None if no simulation manifest exists — that
    disables the time-window filter on file-based persistence/auth signals
    (acceptable for real / unlabeled incidents).
    """
    sim_path = simulations_dir / incident_id / "simulation_manifest.json"
    if not sim_path.exists():
        return ({"technique_ids": [], "is_benign": False}, None)
    with sim_path.open() as f:
        sim = json.load(f)
    techniques = sorted({run["technique_id"] for run in sim.get("runs", []) if run.get("technique_id")})
    label = {
        "technique_ids": techniques,
        # A bundle is "benign" only when no techniques fired AND a manifest
        # exists (meaning it was a deliberate benign-baseline run, not just
        # a missing manifest).
        "is_benign": len(techniques) == 0,
    }
    started_ms = _parse_iso8601_ms(sim.get("started_at"))
    return (label, started_ms)


def _bundle_meta(processed_dir: Path) -> tuple[str, str]:
    """Pull incident_id + scope from the corresponding raw manifest.

    We don't ship a copy of the manifest into data/processed — we read it
    fresh from data/raw/{id}/manifest.json so a single source-of-truth
    governs incident_id and scope.
    """
    incident_id = processed_dir.name
    raw_manifest = REPO_ROOT / "data" / "raw" / incident_id / "manifest.json"
    if not raw_manifest.exists():
        raise FileNotFoundError(
            f"raw manifest not found at {raw_manifest} — "
            f"feature extractor expects data/raw/<incident_id>/manifest.json"
        )
    with raw_manifest.open() as f:
        manifest = json.load(f)
    return manifest["incident_id"], manifest["scope"]


def _validate(vector: dict) -> list[str]:
    with FEATURE_SCHEMA_PATH.open() as f:
        schema = json.load(f)
    validator = jsonschema.Draft202012Validator(schema)
    return [
        f"{'/'.join(str(p) for p in err.absolute_path) or '<root>'}: {err.message}"
        for err in validator.iter_errors(vector)
    ]


def run(processed_dir: Path, *, use_misp: bool = True) -> int:
    incident_id, scope = _bundle_meta(processed_dir)
    events = _load_events(processed_dir)
    print(f"[features] {incident_id} ({scope}): {len(events):,} events loaded", flush=True)

    # MISP client (or None if disabled / unreachable).
    misp: MispClient | None = None
    if use_misp:
        try:
            cache_path = processed_dir / CACHE_FILENAME
            misp = MispClient.from_env(cache_path=cache_path)
        except RuntimeError as exc:
            print(f"[features] MISP disabled ({exc}) — ioc_* features will be 0")

    label, simulation_started_ms = _load_label_and_window(
        REPO_ROOT / "data" / "simulations", incident_id
    )
    if simulation_started_ms is not None:
        # Apply backward grace BEFORE handing to feature modules — they get
        # the already-relaxed cutoff and don't need to know about skew.
        simulation_started_ms -= WINDOW_BACKWARD_GRACE_SEC * 1000
    if simulation_started_ms is None:
        print("[features] no simulation manifest — file-window filter disabled")
    else:
        from datetime import datetime, timezone
        sim_iso = datetime.fromtimestamp(simulation_started_ms / 1000, tz=timezone.utc).isoformat()
        print(f"[features] window filter active (incl. -{WINDOW_BACKWARD_GRACE_SEC}s grace): events at/after {sim_iso}")

    features: dict = {}
    features.update(meta.compute(events))
    features.update(auth.compute(events, simulation_started_ms=simulation_started_ms))
    features.update(process.compute(events))
    features.update(network.compute(events))
    features.update(file_features.compute(events, simulation_started_ms=simulation_started_ms))
    features.update(persistence.compute(events, simulation_started_ms=simulation_started_ms))
    features.update(detection.compute(events, simulation_started_ms=simulation_started_ms))

    # IOC pass last — it may override network.connections_to_threat_intel_ip.
    ioc_features = ioc.compute(events, misp)
    features.update(ioc_features)

    if misp is not None:
        misp.flush_cache()

    vector = {
        "incident_id": incident_id,
        "scope": scope,
        "schema_version": SCHEMA_VERSION,
        "features": features,
        "label": label,
    }

    errors = _validate(vector)
    if errors:
        print("[features] schema validation FAILED:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    out_dir = REPO_ROOT / "data" / "labeled"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{incident_id}.json"
    with out_path.open("w") as f:
        json.dump(vector, f, sort_keys=True, indent=2)
    print(f"[features] wrote {out_path}", flush=True)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "processed_dir",
        type=Path,
        help="Path to data/processed/{incident_id}",
    )
    parser.add_argument(
        "--no-misp",
        action="store_true",
        help="Skip MISP lookups; ioc_* features become 0.",
    )
    args = parser.parse_args()
    processed_dir = args.processed_dir.resolve()
    if not processed_dir.is_dir():
        print(f"not a directory: {processed_dir}", file=sys.stderr)
        return 2
    return run(processed_dir, use_misp=not args.no_misp)


if __name__ == "__main__":
    raise SystemExit(main())
