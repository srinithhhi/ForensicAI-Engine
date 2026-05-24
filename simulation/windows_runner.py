"""Atomic Red Team runner — Scope 2 (Windows).

Drives `Invoke-AtomicTest` (PowerShell 7) on the Windows 10 VM over SSH. One-time
setup on the VM: pwsh 7 + invoke-atomicredteam module + atomics folder, all
driven by host_setup/windows/install_pwsh_atomics.ps1 (one shot, idempotent).

Same shape as `simulation.atomic_runner.AtomicRedTeamRunner` (Scope 1). The two
runners are intentionally not refactored into a shared base beyond Simulator;
the platform differences are load-bearing (Windows has no sudo, command shell
is cmd.exe, paths differ) and a "DRY" refactor would obscure them.

Technique specs accept either `"T1053.005"` (test 1 by default) or
`"T1053.005#2"` (explicit test number 2).

Cleanup is decoupled from `simulate()` so the dev harness can interleave
attack → acquire → cleanup, exactly like Scope 1.

PowerShell-over-SSH quoting notes
---------------------------------
The default OpenSSH shell on Windows is cmd.exe (NOT PowerShell). Embedding a
multi-line PowerShell script as a cmd-quoted argument is a quoting nightmare.
We bypass it entirely by base64-encoding the script as UTF-16LE and invoking
`pwsh -NoProfile -EncodedCommand <base64>` — Microsoft's intended way to ship
PowerShell over remoting / cross-shell. No escaping needed inside the script.

Defender
--------
Windows Defender will block several of the v0 atomics (T1003.001 LSASS dump is
the canonical blocked one). The install script adds a path exclusion for
C:\\AtomicRedTeam\\, but real-time protection still inspects process behavior.
For the labeled-training workflow, disable Defender real-time protection
before the harness run; see host_setup/windows/README.md.
"""

from __future__ import annotations

import base64
import os
import re
from pathlib import Path

from dotenv import load_dotenv

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
TECHNIQUE_SPEC_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?(?:#\d+)?$")

# pwsh 7 is added to system PATH by the MSI installer; fall back to the
# absolute path if PATH is not propagated to the cmd-spawned process.
PWSH_EXE = "pwsh"
DEFAULT_ATOMICS_PATH = r"C:\AtomicRedTeam\atomics"


def _safe_filename(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)


def _parse_technique_spec(spec: str) -> tuple[str, int]:
    if "#" in spec:
        technique_id, test_str = spec.split("#", 1)
        return technique_id, int(test_str)
    return spec, DEFAULT_TEST_NUMBER


def _encode_powershell(script: str) -> str:
    """Encode a PowerShell script as UTF-16LE base64 for -EncodedCommand."""
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def _build_invoke_script(technique: str, test_number: int, atomics_path: str) -> str:
    # Mirrors the Linux pattern: GetPrereqs first (downloads any required
    # tools like procdump.exe for T1003.001), then the real test run.
    # Single-quoted PowerShell strings — no escaping needed when wrapped in
    # -EncodedCommand. Each statement is on its own line.
    return (
        "$ErrorActionPreference = 'Continue'\n"
        "Import-Module invoke-atomicredteam -Force\n"
        f"Invoke-AtomicTest {technique} -TestNumbers {test_number} "
        f"-PathToAtomicsFolder '{atomics_path}' -GetPrereqs -Force\n"
        f"Invoke-AtomicTest {technique} -TestNumbers {test_number} "
        f"-PathToAtomicsFolder '{atomics_path}' -Force"
    )


def _build_cleanup_script(technique: str, test_number: int, atomics_path: str) -> str:
    return (
        "$ErrorActionPreference = 'Continue'\n"
        "Import-Module invoke-atomicredteam -Force\n"
        f"Invoke-AtomicTest {technique} -TestNumbers {test_number} "
        f"-PathToAtomicsFolder '{atomics_path}' -Cleanup -Force"
    )


def _wrap_for_ssh(ps_script: str) -> str:
    """Build the cmd-level command line that runs the PowerShell script."""
    return f"{PWSH_EXE} -NoProfile -EncodedCommand {_encode_powershell(ps_script)}"


class WindowsAtomicRunner(Simulator):
    scope = "vmware"

    def __init__(
        self,
        sim_dir: Path | None = None,
        env_path: Path | None = None,
    ) -> None:
        self.sim_dir = sim_dir or DEFAULT_SIM_DIR
        load_dotenv(env_path or DEFAULT_ENV_PATH)
        self.atomics_path = os.environ.get("SCOPE2_ATOMICS_PATH", DEFAULT_ATOMICS_PATH)
        self.target = os.environ.get("SCOPE2_IP", "")

    def simulate(
        self,
        incident_id: str,
        techniques: list[str],
        auto_cleanup: bool = True,
    ) -> SimulationManifest:
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
            with from_env("scope2") as ssh:
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
        """Idempotent best-effort cleanup. See atomic_runner.cleanup() docstring."""
        with from_env("scope2") as ssh:
            self._cleanup_with_ssh(ssh, manifest)

    def _cleanup_with_ssh(
        self, ssh: SSHClient, manifest: SimulationManifest
    ) -> None:
        for run in manifest.runs:
            script = _build_cleanup_script(
                run.technique_id, run.test_number, self.atomics_path
            )
            try:
                ssh.run(_wrap_for_ssh(script), timeout_sec=COMMAND_TIMEOUT_SEC)
            except Exception:  # noqa: BLE001
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

        script = _build_invoke_script(technique, test_number, self.atomics_path)
        command = _wrap_for_ssh(script)
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
