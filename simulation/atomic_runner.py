"""Atomic Red Team runner — dev-only adversary emulation for Scope 1.

Drives `Invoke-AtomicTest` (PowerShell Core) on the Ubuntu VM over SSH. One-time
setup on the VM: install `pwsh` and the `invoke-atomicredteam` module (see
simulation/README.md).

Never invoked by the orchestrator. Only the dev harness in tests/ calls this.

Technique specs accept either `"T1053.003"` (test 1 by default) or
`"T1053.003#2"` (explicit test number 2). Per-technique test numbers are
necessary because different tests of the same technique often touch different
parts of the filesystem (e.g. T1053.003 test 1 modifies a user crontab,
test 2 drops a file in /etc/cron.d/).

Cleanup is decoupled from `simulate()` so the dev harness can interleave
attack → acquire → cleanup:
    sim = runner.simulate(incident_id, specs, auto_cleanup=False)
    try:
        acquirer.acquire(incident_id)   # captures evidence WHILE it exists
    finally:
        runner.cleanup(sim)             # restores VM state

With `auto_cleanup=True` (the default), cleanup runs inline immediately after
each test — safe for standalone use, but blocks the labeling workflow.
"""

from __future__ import annotations

import re
from pathlib import Path

from dotenv import load_dotenv
import os

from simulation.base import (
    RUNNER_VERSION,
    SimulationManifest,
    Simulator,
    TechniqueRun,
    utcnow_iso,
)
from simulation.ssh_client import SSHClient, from_env

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ENV_PATH = REPO_ROOT / "config" / ".env"
DEFAULT_SIM_DIR = REPO_ROOT / "data" / "simulations"

DEFAULT_TEST_NUMBER = 1
COMMAND_TIMEOUT_SEC = 600.0
# Accept either "T1053.003" or "T1053.003#2". The `#N` suffix overrides the
# default test number for that one technique.
TECHNIQUE_SPEC_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?(?:#\d+)?$")


def _safe_filename(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)


def _parse_technique_spec(spec: str) -> tuple[str, int]:
    """Split a technique spec into (technique_id, test_number).

    "T1053.003"   -> ("T1053.003", 1)
    "T1053.003#2" -> ("T1053.003", 2)
    """
    if "#" in spec:
        technique_id, test_str = spec.split("#", 1)
        return technique_id, int(test_str)
    return spec, DEFAULT_TEST_NUMBER


def _build_invoke_command(technique: str, test_number: int, atomics_path: str) -> str:
    pwsh_script = (
        f"$ErrorActionPreference = 'Continue';"
        f"Import-Module invoke-atomicredteam -Force;"
        f"Invoke-AtomicTest {technique} "
        f"-TestNumbers {test_number} "
        f"-PathToAtomicsFolder '{atomics_path}' "
        f"-GetPrereqs -Force; "
        f"Invoke-AtomicTest {technique} "
        f"-TestNumbers {test_number} "
        f"-PathToAtomicsFolder '{atomics_path}' "
        f"-Force"
    )
    # Single-quote the whole pwsh argument to keep the remote shell from interpreting it.
    escaped = pwsh_script.replace("'", "'\"'\"'")
    # Invoke-AtomicTest does NOT auto-escalate on Linux — it just prints
    # "Elevation required but not provided" and runs the embedded shell
    # commands at whatever privilege pwsh was launched with. To actually
    # execute atomics that need root (most filesystem-touching ones), we
    # launch pwsh itself under sudo. `-n` makes sudo fail immediately if
    # NOPASSWD is not configured rather than hanging on a password prompt.
    return f"sudo -n pwsh -NoProfile -Command '{escaped}'"


def _build_cleanup_command(technique: str, test_number: int, atomics_path: str) -> str:
    pwsh_script = (
        f"$ErrorActionPreference = 'Continue';"
        f"Import-Module invoke-atomicredteam -Force;"
        f"Invoke-AtomicTest {technique} "
        f"-TestNumbers {test_number} "
        f"-PathToAtomicsFolder '{atomics_path}' "
        f"-Cleanup -Force"
    )
    escaped = pwsh_script.replace("'", "'\"'\"'")
    # Cleanup must also run as root since the attack created root-owned files.
    return f"sudo -n pwsh -NoProfile -Command '{escaped}'"


class AtomicRedTeamRunner(Simulator):
    scope = "bare_metal"

    def __init__(
        self,
        sim_dir: Path | None = None,
        env_path: Path | None = None,
    ) -> None:
        self.sim_dir = sim_dir or DEFAULT_SIM_DIR
        load_dotenv(env_path or DEFAULT_ENV_PATH)
        self.atomics_path = os.environ.get(
            "ATOMICS_PATH", "/home/admin/atomic-red-team/atomics"
        )
        self.target = os.environ.get("SCOPE1_IP", "")

    def simulate(
        self,
        incident_id: str,
        techniques: list[str],
        auto_cleanup: bool = True,
    ) -> SimulationManifest:
        """Fire the listed atomic techniques against the VM.

        Each entry in `techniques` is a spec like "T1053.003" (test 1) or
        "T1053.003#2" (test 2). See `_parse_technique_spec`.

        When `auto_cleanup=True` (default — safe for standalone use), runs
        Invoke-AtomicTest -Cleanup immediately after each test so the VM is
        left clean when this method returns. When False, the caller MUST
        call `self.cleanup(manifest)` later to restore VM state — the
        labeled-training harness pattern.
        """
        for t in techniques:
            if not TECHNIQUE_SPEC_PATTERN.match(t):
                raise ValueError(
                    f"technique spec {t!r} does not match Txxxx[.yyy][#N]"
                )

        output_dir = self.sim_dir / incident_id
        if output_dir.exists():
            raise FileExistsError(
                f"simulation bundle for {incident_id} already exists at {output_dir}"
            )
        output_dir.mkdir(parents=True, exist_ok=False)

        manifest = SimulationManifest(
            incident_id=incident_id,
            scope=self.scope,
            target=self.target,
            runner_version=RUNNER_VERSION,
            started_at=utcnow_iso(),
        )

        try:
            with from_env() as ssh:
                for spec in techniques:
                    technique_id, test_number = _parse_technique_spec(spec)
                    manifest.add_run(
                        self._run_one(ssh, technique_id, test_number, output_dir)
                    )
                if auto_cleanup:
                    self._cleanup_with_ssh(ssh, manifest)
        finally:
            manifest.ended_at = utcnow_iso()
            manifest.write(output_dir)

        return manifest

    def cleanup(self, manifest: SimulationManifest) -> None:
        """Run Invoke-AtomicTest -Cleanup for every technique in the manifest.

        Idempotent: cleanup commands (typically `rm -f`, `userdel`, `crontab -r`)
        silently succeed if the target is already gone. Safe to call multiple
        times. Errors are swallowed — there is no production-critical state
        being managed here.
        """
        with from_env() as ssh:
            self._cleanup_with_ssh(ssh, manifest)

    def _cleanup_with_ssh(
        self, ssh: SSHClient, manifest: SimulationManifest
    ) -> None:
        for run in manifest.runs:
            cmd = _build_cleanup_command(
                run.technique_id, run.test_number, self.atomics_path
            )
            try:
                ssh.run(cmd, timeout_sec=COMMAND_TIMEOUT_SEC)
            except Exception:  # noqa: BLE001 — cleanup failure is best-effort
                pass

    def _run_one(
        self,
        ssh: SSHClient,
        technique: str,
        test_number: int,
        output_dir: Path,
    ) -> TechniqueRun:
        safe = _safe_filename(f"{technique}_test{test_number}")
        stdout_rel = f"{safe}.stdout.log"
        stderr_rel = f"{safe}.stderr.log"

        command = _build_invoke_command(technique, test_number, self.atomics_path)
        started_at = utcnow_iso()
        try:
            result = ssh.run(command, timeout_sec=COMMAND_TIMEOUT_SEC)
        except Exception as exc:  # noqa: BLE001
            return TechniqueRun(
                technique_id=technique,
                test_number=test_number,
                command=command,
                started_at=started_at,
                ended_at=utcnow_iso(),
                exit_code=-1,
                success=False,
                error=f"{type(exc).__name__}: {exc}",
            )

        (output_dir / stdout_rel).write_text(result.stdout)
        (output_dir / stderr_rel).write_text(result.stderr)

        return TechniqueRun(
            technique_id=technique,
            test_number=test_number,
            command=command,
            started_at=started_at,
            ended_at=utcnow_iso(),
            exit_code=result.exit_code,
            success=result.exit_code == 0,
            stdout_path=stdout_rel,
            stderr_path=stderr_rel,
        )
