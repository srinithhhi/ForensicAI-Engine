"""Base classes and shared utilities for the acquisition layer.

The `Acquirer` ABC is the only surface the orchestrator sees. Concrete acquirers
(BareMetalAcquirer, later VMwareAcquirer, CloudAcquirer) compose `CollectionStep`
instances and produce a canonical `AcquisitionManifest` on disk.

The manifest format is the load-bearing contract with the OCSF mappers — it is
versioned via `schemas/acquisition_manifest_v1.json` and must not be changed
without bumping the schema version.
"""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from acquisition.velociraptor_client import VelociraptorClient

ACQUIRER_VERSION = "0.1.0"
MANIFEST_FILENAME = "manifest.json"


class AgentStaleError(RuntimeError):
    """Raised when the target client's last_seen_at is older than the freshness budget."""


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Stream a file through SHA256. Works on multi-GB inputs."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class StepResult:
    name: str
    kind: str
    status: str
    started_at: str
    ended_at: str
    artifact: str | None = None
    path: str | None = None
    sha256: str | None = None
    size_bytes: int | None = None
    error: str | None = None


@dataclass
class AcquisitionContext:
    incident_id: str
    scope: str
    output_dir: Path
    velociraptor_client: "VelociraptorClient"
    velociraptor_client_id: str


@dataclass
class AcquisitionManifest:
    incident_id: str
    scope: str
    acquirer_version: str
    started_at: str
    ended_at: str | None = None
    steps: list[StepResult] = field(default_factory=list)

    def add_step_result(self, result: StepResult) -> None:
        self.steps.append(result)

    def write(self, output_dir: Path) -> Path:
        path = output_dir / MANIFEST_FILENAME
        with path.open("w") as f:
            json.dump(asdict(self), f, indent=2, sort_keys=True)
        return path


class Acquirer(ABC):
    """The only acquisition surface the orchestrator sees."""

    scope: str
    # Per-scope freshness budget for the pre-flight agent-online check.
    # The Velociraptor agent's last_seen_at advances on poll/dispatch — when
    # nothing's happening the timestamp ages even though the agent will still
    # accept a flow on the next dispatch. The default (120s) is tight enough
    # to catch a truly offline agent without flagging idle ones. Scopes with
    # longer poll intervals can raise it.
    agent_freshness_max_age_sec: float = 120.0

    @abstractmethod
    def acquire(self, incident_id: str) -> AcquisitionManifest:
        """Run the full acquisition for one incident.

        Raises if `data/raw/{incident_id}/` already exists — replay must be
        explicit (use a new incident_id or rename the prior bundle).
        """
