"""Scope 1 acquirer — drives Velociraptor against the Ubuntu bare-metal VM.

Composes a fixed list of `VelociraptorArtifactStep` instances and writes the
canonical raw bundle to `data/raw/{incident_id}/`.

v0 covers logs, processes, sockets, persistence (cron + systemd), file integrity
(AIDE), and YARA-on-process. Memory and disk imaging are deferred to v1 — see
the plan's "How this leaves the door open for v1" section for the seam.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

from acquisition.base import (
    ACQUIRER_VERSION,
    Acquirer,
    AcquisitionContext,
    AcquisitionManifest,
    utcnow_iso,
)
from acquisition.steps import CollectionStep, VelociraptorArtifactStep
from acquisition.velociraptor_client import VelociraptorClient

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ENV_PATH = REPO_ROOT / "config" / ".env"
DEFAULT_RAW_DIR = REPO_ROOT / "data" / "raw"


def _default_steps() -> list[CollectionStep]:
    # Artifact names verified against the Velociraptor 0.76.1 default pack.
    # Deferred to a later session:
    #   - aide_diff (needs custom Linux.Sys.AIDE.yaml — no AIDE artifact in pack)
    #   - yara_proc (Linux.Detection.Yara.Process needs a Rules parameter;
    #     we'll wire parameter passing + read rules from $YARA_RULES later)
    return [
        VelociraptorArtifactStep("journald", "Linux.Forensics.Journal"),
        VelociraptorArtifactStep("processes", "Linux.Sys.Pslist"),
        VelociraptorArtifactStep("sockets", "Linux.Network.NetstatEnriched"),
        VelociraptorArtifactStep("cron", "Linux.Sys.Crontab"),
        VelociraptorArtifactStep("systemd", "Linux.Sys.Services"),
    ]


class BareMetalAcquirer(Acquirer):
    scope = "bare_metal"

    def __init__(
        self,
        steps: list[CollectionStep] | None = None,
        raw_dir: Path | None = None,
        env_path: Path | None = None,
    ) -> None:
        self.steps = steps if steps is not None else _default_steps()
        self.raw_dir = raw_dir or DEFAULT_RAW_DIR
        load_dotenv(env_path or DEFAULT_ENV_PATH)

        api_config = os.environ.get("VELO_API_CONFIG")
        client_id = os.environ.get("SCOPE1_CLIENT_ID")
        if not api_config or not client_id:
            raise RuntimeError(
                "VELO_API_CONFIG and SCOPE1_CLIENT_ID must be set in config/.env"
            )
        self._api_config_path = Path(api_config)
        self._client_id = client_id

    def acquire(self, incident_id: str) -> AcquisitionManifest:
        output_dir = self.raw_dir / incident_id
        if output_dir.exists():
            raise FileExistsError(
                f"raw bundle for incident {incident_id} already exists at "
                f"{output_dir}. Use a new incident_id or move the prior bundle."
            )

        # Fail fast if the agent is offline — avoid creating empty bundles
        # while polling flows that will never be picked up.
        with VelociraptorClient(self._api_config_path) as client:
            client.check_agent_fresh(self._client_id)

        output_dir.mkdir(parents=True, exist_ok=False)

        manifest = AcquisitionManifest(
            incident_id=incident_id,
            scope=self.scope,
            acquirer_version=ACQUIRER_VERSION,
            started_at=utcnow_iso(),
        )

        try:
            with VelociraptorClient(self._api_config_path) as client:
                ctx = AcquisitionContext(
                    incident_id=incident_id,
                    scope=self.scope,
                    output_dir=output_dir,
                    velociraptor_client=client,
                    velociraptor_client_id=self._client_id,
                )
                for step in self.steps:
                    manifest.add_step_result(step.execute(ctx))
        finally:
            manifest.ended_at = utcnow_iso()
            manifest.write(output_dir)

        return manifest

    def run_step(self, step_name: str, incident_id: str) -> AcquisitionManifest:
        """Run a single named step (verification step 2 from the plan)."""
        step = next((s for s in self.steps if s.name == step_name), None)
        if step is None:
            raise KeyError(f"unknown step: {step_name}")
        prior_steps = self.steps
        self.steps = [step]
        try:
            return self.acquire(incident_id)
        finally:
            self.steps = prior_steps
