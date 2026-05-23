"""Collection step abstractions.

`CollectionStep` is the extension point for the acquisition layer. v0 ships one
concrete subclass — `VelociraptorArtifactStep` — that drives the Velociraptor
gRPC API. v1 will add `SSHStreamStep` for forensic-grade evidence (LiME memory
dump, dc3dd disk image) without touching any v0 file.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path

from acquisition.base import (
    AcquisitionContext,
    StepResult,
    sha256_file,
    utcnow_iso,
)

VELOCIRAPTOR_SUBDIR = "velociraptor"


class CollectionStep(ABC):
    """One unit of collection. Produces files on disk + a StepResult entry."""

    name: str
    kind: str

    @abstractmethod
    def execute(self, ctx: AcquisitionContext) -> StepResult: ...


class VelociraptorArtifactStep(CollectionStep):
    """Drive the Velociraptor server to collect one VQL artifact from the agent.

    The agent runs the artifact, returns tabular rows; we write them as a JSON
    array to data/raw/{incident_id}/velociraptor/{artifact}.json.
    """

    kind = "velociraptor"

    def __init__(
        self,
        name: str,
        artifact_name: str,
        parameters: dict | None = None,
        max_rows: int | None = None,
        timeout_sec: float | None = None,
        output_filename: str | None = None,
        source_name: str | None = None,
    ) -> None:
        self.name = name
        self.artifact_name = artifact_name
        self.parameters = parameters or {}
        self.max_rows = max_rows
        self.timeout_sec = timeout_sec
        # When multiple steps dispatch the same artifact with different params
        # (e.g. Windows.EventLogs.Evtx with ChannelRegex=Security|System|Sysmon),
        # they would otherwise collide on the same output file. The override
        # lets each step land in its own JSON.
        self.output_filename = output_filename or artifact_name
        # For multi-source artifacts (Windows.Forensics.Amcache et al.), pick
        # which sub-source to read. None = artifact's default source.
        self.source_name = source_name

    def execute(self, ctx: AcquisitionContext) -> StepResult:
        started_at = utcnow_iso()
        velo_dir = ctx.output_dir / VELOCIRAPTOR_SUBDIR
        velo_dir.mkdir(parents=True, exist_ok=True)
        output_path = velo_dir / f"{self.output_filename}.json"
        relative_path = f"{VELOCIRAPTOR_SUBDIR}/{self.output_filename}.json"

        try:
            rows = ctx.velociraptor_client.collect_artifact(
                client_id=ctx.velociraptor_client_id,
                artifact_name=self.artifact_name,
                parameters=self.parameters,
                max_rows=self.max_rows,
                timeout_sec=self.timeout_sec,
                source_name=self.source_name,
            )
            with output_path.open("w") as f:
                json.dump(rows, f, indent=2, sort_keys=True)
        except Exception as exc:  # noqa: BLE001 — surface any client/server error into the manifest
            return StepResult(
                name=self.name,
                kind=self.kind,
                status="failed",
                started_at=started_at,
                ended_at=utcnow_iso(),
                artifact=self.artifact_name,
                error=f"{type(exc).__name__}: {exc}",
            )

        return StepResult(
            name=self.name,
            kind=self.kind,
            status="success",
            started_at=started_at,
            ended_at=utcnow_iso(),
            artifact=self.artifact_name,
            path=relative_path,
            sha256=sha256_file(output_path),
            size_bytes=output_path.stat().st_size,
        )
