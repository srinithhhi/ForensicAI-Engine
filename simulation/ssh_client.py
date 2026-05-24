"""paramiko-based SSH wrapper.

Used by the simulation module today. Will be reused by Module A v1 for
forensic-grade memory and disk imaging (LiME, dc3dd streams). Kept deliberately
small — connect, run-one-command-with-timeout, close.

CLI:
    python -m simulation.ssh_client --ping
        SSHes into SCOPE1_IP and runs `uname -a` (verification step 7).
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import paramiko
from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ENV_PATH = REPO_ROOT / "config" / ".env"


@dataclass
class CommandResult:
    command: str
    stdout: str
    stderr: str
    exit_code: int
    duration_sec: float


class SSHClient:
    def __init__(
        self,
        host: str,
        user: str,
        key_path: Path,
        port: int = 22,
        timeout_sec: float = 30.0,
    ) -> None:
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._client.connect(
            hostname=host,
            port=port,
            username=user,
            key_filename=str(key_path),
            timeout=timeout_sec,
            look_for_keys=False,
            allow_agent=False,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "SSHClient":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def run(self, command: str, timeout_sec: float = 300.0) -> CommandResult:
        start = time.monotonic()
        stdin, stdout, stderr = self._client.exec_command(
            command, timeout=timeout_sec
        )
        stdin.close()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        exit_code = stdout.channel.recv_exit_status()
        return CommandResult(
            command=command,
            stdout=out,
            stderr=err,
            exit_code=exit_code,
            duration_sec=time.monotonic() - start,
        )


def from_env(scope: str = "scope1") -> SSHClient:
    """Build an SSHClient from per-scope env vars.

    scope='scope1' reads SCOPE1_IP / SCOPE1_USER / SCOPE1_SSH_KEY (Linux VM).
    scope='scope2' reads SCOPE2_IP / SCOPE2_USER and falls back to the same
    SSH key as Scope 1 (we use one key for both VMs).
    """
    load_dotenv(DEFAULT_ENV_PATH)
    prefix = scope.upper()
    host = os.environ.get(f"{prefix}_IP")
    user = os.environ.get(f"{prefix}_USER")
    # Per-scope key override; if not set, reuse SCOPE1_SSH_KEY (one keypair
    # signs both VM authorized_keys files — see project_windows_openssh_setup
    # memory for the Windows admin-group quirk on key placement).
    key = os.environ.get(f"{prefix}_SSH_KEY") or os.environ.get("SCOPE1_SSH_KEY")
    if not host or not user or not key:
        raise RuntimeError(
            f"{prefix}_IP, {prefix}_USER, and an SSH key must be set in config/.env"
        )
    return SSHClient(host=host, user=user, key_path=Path(key))


def _ping(scope: str) -> int:
    # cmd.exe is the default OpenSSH shell on Windows; `ver` works there
    # whereas `uname -a` only exists on Linux. Pick the right probe per scope.
    probe = "uname -a" if scope == "scope1" else "ver"
    with from_env(scope) as client:
        result = client.run(probe)
    print(result.stdout.rstrip())
    if result.stderr:
        print(result.stderr.rstrip(), file=sys.stderr)
    return result.exit_code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ping", action="store_true")
    parser.add_argument(
        "--scope", default="scope1", choices=["scope1", "scope2"],
        help="Target VM: scope1 = Linux (default), scope2 = Windows",
    )
    args = parser.parse_args()
    if args.ping:
        return _ping(args.scope)
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
