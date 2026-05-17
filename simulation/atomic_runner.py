"""Atomic Red Team runner — dev-only adversary emulation for Scope 1.

Drives `Invoke-AtomicTest` (PowerShell Core) on the Ubuntu VM over SSH. One-time
setup on the VM: install `pwsh` and the `invoke-atomicredteam` module (see
simulation/README.md).

Never invoked by the orchestrator. Only the dev harness in tests/ calls this.
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
TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def _safe_filename(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)


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
    return f"pwsh -NoProfile -Command '{escaped}'"


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
    return f"pwsh -NoProfile -Command '{escaped}'"


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
        test_number: int = DEFAULT_TEST_NUMBER,
    ) -> SimulationManifest:
        for t in techniques:
            if not TECHNIQUE_PATTERN.match(t):
                raise ValueError(
                    f"technique {t!r} does not match MITRE pattern Txxxx[.yyy]"
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
                for technique in techniques:
                    manifest.add_run(
                        self._run_one(ssh, technique, test_number, output_dir)
                    )
        finally:
            manifest.ended_at = utcnow_iso()
            manifest.write(output_dir)

        return manifest

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

        # Always attempt cleanup — even if the test "failed", residual state on
        # the VM would taint downstream acquisitions.
        cleanup = _build_cleanup_command(technique, test_number, self.atomics_path)
        try:
            ssh.run(cleanup, timeout_sec=COMMAND_TIMEOUT_SEC)
        except Exception:  # noqa: BLE001 — cleanup failure is logged via stderr, not fatal
            pass

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
