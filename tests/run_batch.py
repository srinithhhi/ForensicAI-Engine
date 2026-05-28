"""Batch runner — walks the v0 30-bundle experiment config end-to-end.

For each pending bundle slot in `data/experiments/v0_training_set.yaml`,
runs the full pipeline:

    simulate (or empty manifest for benign) → acquire → cleanup
        ↓
    parsing.run_mappers (Phase 3)
        ↓
    normalisation.feature_extractor (Phase 4, with MISP enrichment)

Per-bundle results are written to `data/experiments/v0_state.json` so the
batch is resumable: re-running skips slots whose state is "success".

CLI:
    python tests/run_batch.py                        # process all pending slots
    python tests/run_batch.py --interactive          # confirm before each bundle
    python tests/run_batch.py --only LB-01,LB-02     # only these slots
    python tests/run_batch.py --scope linux          # restrict to one scope
    python tests/run_batch.py --skip-preflight       # bypass MISP/Velo ping
    python tests/run_batch.py --no-misp              # Phase 4 skips MISP queries
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

CONFIG_PATH = REPO_ROOT / "data" / "experiments" / "v0_training_set.yaml"
STATE_PATH = REPO_ROOT / "data" / "experiments" / "v0_state.json"


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def make_incident_id(scope: str) -> str:
    prefix = "INC-WIN-" if scope == "windows" else "INC-"
    return f"{prefix}{_ts()}"


def _write_empty_simulation_manifest(incident_id: str, scope: str) -> Path:
    """Benign-baseline path: write an empty simulation_manifest.json
    directly without involving SSH. Matches what `simulate(incident_id, [])`
    would produce on a real VM, but doesn't require the VM to be up — which
    is the whole point of a "no attacks fired" baseline.
    """
    from acquisition.base import utcnow_iso  # canonical timestamp format
    sim_dir = REPO_ROOT / "data" / "simulations" / incident_id
    sim_dir.mkdir(parents=True, exist_ok=False)
    target = os.environ.get("SCOPE2_IP" if scope == "windows" else "SCOPE1_IP", "")
    manifest = {
        "incident_id": incident_id,
        "scope": "vmware" if scope == "windows" else "bare_metal",
        "target": target,
        "runner_version": "0.1.0-benign",
        "started_at": utcnow_iso(),
        "ended_at": utcnow_iso(),
        "runs": [],
    }
    out = sim_dir / "simulation_manifest.json"
    with out.open("w") as f:
        json.dump(manifest, f, sort_keys=True, indent=2)
    return out


def _load_config() -> dict:
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(f"experiment config not found at {CONFIG_PATH}")
    with CONFIG_PATH.open() as f:
        return yaml.safe_load(f)


def _load_state() -> dict:
    if STATE_PATH.exists():
        with STATE_PATH.open() as f:
            return json.load(f)
    return {"completed": {}, "failed": {}}


def _save_state(state: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_PATH.with_suffix(".tmp")
    with tmp.open("w") as f:
        json.dump(state, f, sort_keys=True, indent=2)
    tmp.replace(STATE_PATH)


def preflight(scopes_needed: set[str]) -> tuple[bool, list[str]]:
    """Lightweight infrastructure check. Returns (ok, list_of_failures).

    Checks:
    - MISP --ping (always required for Phase 4 IOC enrichment)
    - Velociraptor --ping (always required for acquisition)

    VMs themselves are NOT checked here — the acquirer's existing
    `check_agent_fresh` does that with the right freshness budget. Doing it
    again here would just slow things down.
    """
    failures: list[str] = []

    # MISP
    rc = subprocess.run(
        [sys.executable, "-W", "ignore", "-m", "normalisation.misp_client", "--ping"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    ).returncode
    if rc != 0:
        failures.append("MISP --ping failed (check that the docker container is up)")

    # Velociraptor — only need a check if we'll acquire anything
    if scopes_needed:
        rc = subprocess.run(
            [sys.executable, "-m", "acquisition.velociraptor_client", "--ping"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        ).returncode
        if rc != 0:
            failures.append("Velociraptor --ping failed (check that the server is running)")

    return (not failures, failures)


def run_bundle(slot: str, scope: str, techniques: list[str], use_misp: bool) -> dict:
    """Run one bundle slot end-to-end. Returns a result dict for the state log."""
    started_at = time.monotonic()
    incident_id = make_incident_id(scope)
    print(f"\n[batch] slot {slot} ({scope}) → incident_id={incident_id}")
    print(f"[batch]   techniques: {techniques or '(benign baseline)'}")

    # ── Simulation ───────────────────────────────────────────────────────
    sim_manifest = None
    runner = None
    if techniques:
        if scope == "linux":
            from simulation.atomic_runner import AtomicRedTeamRunner
            runner = AtomicRedTeamRunner()
        elif scope == "windows":
            from simulation.windows_runner import WindowsAtomicRunner
            runner = WindowsAtomicRunner()
        else:
            raise ValueError(f"unknown scope {scope!r}")
        print(f"[batch]   simulating {len(techniques)} atomics on {scope} VM (cleanup deferred)")
        sim_manifest = runner.simulate(incident_id, techniques, auto_cleanup=False)
        sim_fails = [r for r in sim_manifest.runs if not r.success]
        if sim_fails:
            for r in sim_fails:
                print(f"[batch]   SIM-FAIL {r.technique_id}#{r.test_number}: exit={r.exit_code}")
    else:
        print("[batch]   benign baseline — writing empty simulation manifest")
        _write_empty_simulation_manifest(incident_id, scope)

    # ── Acquisition ──────────────────────────────────────────────────────
    try:
        if scope == "linux":
            from acquisition.bare_metal_acquirer import BareMetalAcquirer
            acq_manifest = BareMetalAcquirer().acquire(incident_id)
        else:
            from acquisition.vmware_acquirer import VMwareAcquirer
            acq_manifest = VMwareAcquirer().acquire(incident_id)
        acq_fails = [s for s in acq_manifest.steps if s.status != "success"]
        print(
            f"[batch]   acquired {len(acq_manifest.steps)} steps, "
            f"{len(acq_fails)} failed → data/raw/{incident_id}/"
        )
        for s in acq_fails:
            print(f"[batch]     ACQ-FAIL {s.name}: {s.error}")
    finally:
        if runner is not None and sim_manifest is not None:
            print("[batch]   cleaning up VM state")
            runner.cleanup(sim_manifest)

    # ── Phase 3 — OCSF mapping ───────────────────────────────────────────
    print("[batch]   Phase 3: running OCSF mappers")
    bundle_dir = REPO_ROOT / "data" / "raw" / incident_id
    rc = subprocess.run(
        [sys.executable, "-m", "parsing.run_mappers", str(bundle_dir)],
        cwd=REPO_ROOT,
    ).returncode
    if rc not in (0, 1):
        # 0 = clean, 1 = "warned about unmapped artifacts" (also acceptable);
        # anything else = real failure
        raise RuntimeError(f"run_mappers exited with code {rc} for {incident_id}")

    # ── Phase 4 — feature extraction ─────────────────────────────────────
    print("[batch]   Phase 4: extracting features" + ("" if use_misp else " (--no-misp)"))
    processed_dir = REPO_ROOT / "data" / "processed" / incident_id
    cmd = [sys.executable, "-W", "ignore", "-m", "normalisation.feature_extractor", str(processed_dir)]
    if not use_misp:
        cmd.append("--no-misp")
    rc = subprocess.run(cmd, cwd=REPO_ROOT).returncode
    if rc != 0:
        raise RuntimeError(f"feature_extractor exited with code {rc} for {incident_id}")

    labeled_path = REPO_ROOT / "data" / "labeled" / f"{incident_id}.json"
    if not labeled_path.exists():
        raise RuntimeError(f"feature_extractor did not produce {labeled_path}")

    duration_sec = round(time.monotonic() - started_at, 1)
    print(f"[batch] ✓ slot {slot} complete in {duration_sec/60:.1f} min")
    return {
        "incident_id": incident_id,
        "scope": scope,
        "techniques": techniques,
        "labeled_path": str(labeled_path.relative_to(REPO_ROOT)),
        "duration_sec": duration_sec,
        "completed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interactive", action="store_true", help="prompt before each bundle")
    parser.add_argument("--only", help="comma-separated slot names to run (e.g. LB-01,LB-02)")
    parser.add_argument("--scope", choices=["linux", "windows"], help="restrict to one scope")
    parser.add_argument("--skip-preflight", action="store_true", help="skip MISP/Velociraptor ping")
    parser.add_argument("--no-misp", action="store_true", help="feature_extractor skips MISP queries")
    parser.add_argument("--retry-failed", action="store_true", help="re-run slots in state.failed")
    args = parser.parse_args()

    config = _load_config()
    state = _load_state()
    bundles = config["bundles"]

    # Filter slots by CLI options.
    if args.only:
        wanted = {s.strip() for s in args.only.split(",") if s.strip()}
        bundles = [b for b in bundles if b["slot"] in wanted]
    if args.scope:
        bundles = [b for b in bundles if b["scope"] == args.scope]
    if not args.retry_failed:
        bundles = [b for b in bundles if b["slot"] not in state["completed"]]
    else:
        # Retry mode: include slots in state.failed even if completed-set is empty.
        bundles = [b for b in bundles if b["slot"] in state.get("failed", {}) or b["slot"] not in state["completed"]]

    if not bundles:
        print("[batch] nothing to do — all targeted slots are already complete.")
        return 0

    scopes_needed = {b["scope"] for b in bundles}
    print(f"[batch] {len(bundles)} bundle(s) pending across scopes: {sorted(scopes_needed)}")
    for b in bundles:
        techs = ", ".join(b["techniques"]) or "benign"
        print(f"        {b['slot']:6s}  {b['scope']:8s}  {techs}")

    if not args.skip_preflight:
        print("\n[batch] preflight check…")
        ok, fails = preflight(scopes_needed)
        if not ok:
            print("[batch] PREFLIGHT FAILED:")
            for f in fails:
                print(f"        - {f}")
            print("[batch] re-run with --skip-preflight to bypass (not recommended)")
            return 2
        print("[batch] preflight OK ✓")

    successes = 0
    failures = 0
    for b in bundles:
        if args.interactive:
            techs = ", ".join(b["techniques"]) or "benign baseline"
            resp = input(f"\n[batch] Run slot {b['slot']} ({b['scope']}, {techs})? [y/N/q] ").strip().lower()
            if resp == "q":
                print("[batch] stopping by user request.")
                break
            if resp != "y":
                print(f"[batch] skipping {b['slot']} for this run.")
                continue
        try:
            result = run_bundle(b["slot"], b["scope"], b["techniques"], use_misp=not args.no_misp)
            state["completed"][b["slot"]] = result
            state.get("failed", {}).pop(b["slot"], None)
            _save_state(state)
            successes += 1
        except KeyboardInterrupt:
            print("\n[batch] interrupted by user; state saved so you can resume.")
            return 130
        except Exception as exc:
            failures += 1
            err_info = {
                "scope": b["scope"],
                "techniques": b["techniques"],
                "error": str(exc),
                "traceback": traceback.format_exc(),
                "failed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }
            state.setdefault("failed", {})[b["slot"]] = err_info
            _save_state(state)
            print(f"[batch] ✗ slot {b['slot']} FAILED: {exc}")
            print(traceback.format_exc())

    print(f"\n[batch] done. successes={successes}  failures={failures}  total_done={len(state['completed'])}/30")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
