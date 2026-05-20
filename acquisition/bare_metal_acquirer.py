"""Scope 1 acquirer — drives Velociraptor against the Ubuntu bare-metal VM.

Composes a fixed list of `VelociraptorArtifactStep` instances and writes the
canonical raw bundle to `data/raw/{incident_id}/`.

v0 covers logs, processes, sockets, persistence (cron + systemd), file integrity
(AIDE), YARA-on-process, plus four supporting snapshot steps (bash history,
authorized SSH keys, SUID binaries, recently-modified files in attacker drop
targets). Memory and disk imaging are deferred to v1 — see the plan's "How this
leaves the door open for v1" section for the seam.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
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
from acquisition.yara_loader import load_yara_rules

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ENV_PATH = REPO_ROOT / "config" / ".env"
DEFAULT_RAW_DIR = REPO_ROOT / "data" / "raw"

# YARA scan caps. Per the "collect raw, filter downstream" project principle,
# we don't pre-filter noisy rule namespaces at acquisition — that's the OCSF
# mapper's job. We DO need a flow-level cap so a runaway scan can't fill the
# disk, but it must be high enough that normal scans never trigger it.
# Empirically a clean Ubuntu VM produces ~400 matches with all 4 curated
# subdirs (mostly crypto-constant rules matching every TLS-linking daemon).
# 2000 leaves comfortable headroom while still bounding worst case.
# Velociraptor uses Go's RE2 which does not support lookaheads — `(?!...)`
# silently never matches. `^[^\[]` is the RE2-safe way to say "name does
# not start with `[`" (kernel threads in /proc are reported as `[name]`).
YARA_PROCESS_REGEX = r"^[^\[]"
YARA_FLOW_MAX_ROWS = 2000
# YARA scans of user-space processes against 884 rules take ~2–5 minutes
# in isolation but can stretch to 10+ min when chained after AIDE (CPU/IO
# contention from aide's filesystem walk). 1200s gives comfortable
# headroom for the chained case. The global default (180s) still applies
# to the other v0 artifacts.
YARA_FLOW_TIMEOUT_SEC = 1200.0

# AIDE walks the filesystem subset defined in /etc/aide/aide.conf (default
# Ubuntu config covers /etc, /bin, /sbin, /usr/bin, /usr/sbin, /lib, etc.).
# Walk time scales with disk usage of monitored paths and with kernel cache
# state. Empirically: 390s in isolation (warm cache), >600s when chained
# after other steps (cold cache, I/O contention). 1200s gives comfortable
# headroom for the worst case without ever blocking that long on healthy runs.
# Loaded into the server via the --definitions flag;
# see [[project-velociraptor-custom-artifacts-via-definitions-flag]].
AIDE_FLOW_TIMEOUT_SEC = 1200.0

# authorized_keys hunt: default artifact glob misses /root/.ssh. SSH key
# persistence (T1098.004) is a common attacker move so root must be included.
AUTH_KEYS_GLOB = "/{root,home/*}/.ssh/authorized_keys*"

# recently_modified scope: attacker drop targets that AIDE's default config
# does NOT watch. /tmp and /var/tmp are common curl/wget destinations
# (T1105); /dev/shm is an in-memory FS some attackers use to avoid disk
# artifacts; /root and /home cover user-space staging.
RECENTLY_MODIFIED_GLOB = "/{tmp,var/tmp,root,dev/shm,home}/**"
# Files modified in the last 24h. Computed at acquirer init-time, so a
# long-lived acquirer instance would see drift — acceptable for the
# one-shot usage pattern; refactor to compute-at-execute if a service
# wraps this. The cutoff is intentionally generous; the OCSF mapper will
# filter further by joining with the simulation manifest's time window.
RECENTLY_MODIFIED_WINDOW_HOURS = 24
RECENTLY_MODIFIED_MAX_ROWS = 5000
RECENTLY_MODIFIED_TIMEOUT_SEC = 300.0


def _recently_modified_cutoff() -> str:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=RECENTLY_MODIFIED_WINDOW_HOURS)
    return cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")


def _default_steps() -> list[CollectionStep]:
    # Artifact names verified against the Velociraptor 0.76.1 default pack,
    # except Custom.Linux.Sys.AIDE which lives in
    # acquisition/velociraptor_artifacts/ and is loaded via the server's
    # --definitions flag.
    #
    # Step order is intentionally fast-to-slow. The first five plus the
    # four "alignment" steps are seconds each; aide_diff is ~5-15 min,
    # yara_proc is ~5 min. Putting slow steps last lets a partial run still
    # capture the cheap high-signal artifacts if the slow steps time out.
    #
    # Coverage matrix for the v0 attack set (Module B):
    #   T1078.003 (local user)    -> journald, processes, aide_diff
    #   T1059.004 (encoded shell) -> bash_history (partial)
    #   T1053.003 (cron)          -> cron, aide_diff
    #   T1543.002 (systemd)       -> systemd, aide_diff
    #   T1105     (file transfer) -> recently_modified
    return [
        # snapshot of system state (fast, no params)
        VelociraptorArtifactStep("journald", "Linux.Forensics.Journal"),
        VelociraptorArtifactStep("processes", "Linux.Sys.Pslist"),
        VelociraptorArtifactStep("sockets", "Linux.Network.NetstatEnriched"),
        VelociraptorArtifactStep("cron", "Linux.Sys.Crontab"),
        VelociraptorArtifactStep("systemd", "Linux.Sys.Services"),
        # alignment steps — close gaps left by the original 7 against the
        # v0 attack set. See coverage matrix above.
        VelociraptorArtifactStep("bash_history", "Linux.Sys.BashHistory"),
        VelociraptorArtifactStep(
            "auth_keys",
            "Linux.Ssh.AuthorizedKeys",
            parameters={"sshKeyFilesGlob": AUTH_KEYS_GLOB},
        ),
        VelociraptorArtifactStep("suid_files", "Linux.Sys.SUID"),
        VelociraptorArtifactStep(
            "recently_modified",
            "Linux.Search.FileFinder",
            parameters={
                "SearchFilesGlob": RECENTLY_MODIFIED_GLOB,
                "MoreRecentThan": _recently_modified_cutoff(),
                "LocalFilesystemOnly": "Y",
            },
            max_rows=RECENTLY_MODIFIED_MAX_ROWS,
            timeout_sec=RECENTLY_MODIFIED_TIMEOUT_SEC,
        ),
        # slow steps last
        VelociraptorArtifactStep(
            "aide_diff",
            "Custom.Linux.Sys.AIDE",
            timeout_sec=AIDE_FLOW_TIMEOUT_SEC,
        ),
        VelociraptorArtifactStep(
            "yara_proc",
            "Linux.Detection.Yara.Process",
            parameters={
                "YaraRule": load_yara_rules(),
                "ProcessRegex": YARA_PROCESS_REGEX,
            },
            max_rows=YARA_FLOW_MAX_ROWS,
            timeout_sec=YARA_FLOW_TIMEOUT_SEC,
        ),
    ]


class BareMetalAcquirer(Acquirer):
    scope = "bare_metal"

    def __init__(
        self,
        steps: list[CollectionStep] | None = None,
        raw_dir: Path | None = None,
        env_path: Path | None = None,
    ) -> None:
        # Load env BEFORE building the default steps — _default_steps() reads
        # YARA_RULES from the environment to load the rule corpus.
        load_dotenv(env_path or DEFAULT_ENV_PATH)
        self.steps = steps if steps is not None else _default_steps()
        self.raw_dir = raw_dir or DEFAULT_RAW_DIR

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
