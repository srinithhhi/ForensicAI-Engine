"""Base classes for the adversary simulation layer.

The `Simulator` ABC mirrors `Acquirer` in shape — one entry point, one canonical
manifest. The manifest's `incident_id` is the join key with the acquisition
bundle written to `data/raw/{incident_id}/`.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

RUNNER_VERSION = "0.1.0"
MANIFEST_FILENAME = "simulation_manifest.json"


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class TechniqueRun:
    technique_id: str
    test_number: int
    command: str
    started_at: str
    ended_at: str
    exit_code: int
    success: bool
    stdout_path: str | None = None
    stderr_path: str | None = None
    error: str | None = None


@dataclass
class SimulationManifest:
    incident_id: str
    scope: str
    target: str
    runner_version: str
    started_at: str
    ended_at: str | None = None
    runs: list[TechniqueRun] = field(default_factory=list)

    def add_run(self, run: TechniqueRun) -> None:
        self.runs.append(run)

    def write(self, output_dir: Path) -> Path:
        path = output_dir / MANIFEST_FILENAME
        with path.open("w") as f:
            json.dump(asdict(self), f, indent=2, sort_keys=True)
        return path


class Simulator(ABC):
    scope: str

    @abstractmethod
    def simulate(
        self, incident_id: str, techniques: list[str]
    ) -> SimulationManifest: ...
