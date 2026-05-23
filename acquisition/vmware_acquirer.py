"""Scope 2 acquirer — drives Velociraptor against the VMware Windows 10 VM.

Same shape as `BareMetalAcquirer` (Scope 1). Composes a fixed list of
`VelociraptorArtifactStep` instances against the Windows agent and writes the
canonical raw bundle to `data/raw/{incident_id}/`.

v0 covers Windows event logs (Security / System / Sysmon channels), process and
network snapshots, persistence (services, scheduled tasks, autoruns), execution
forensics (Prefetch, Amcache, MFT timeline), PowerShell history, recently
modified files, and YARA scans on processes + files. Maps the Scope 2 column of
the project's pipeline diagram with these substitutions:

  - PowerCLI / VDDK live memory + disk pull -> deferred to v1 (matches Scope 1
    LiME / dc3dd treatment).
  - KAPE evtx / registry / MFT -> covered by Windows.EventLogs.Evtx,
    Windows.Forensics.Amcache, Windows.Timeline.MFT respectively.
  - EvtxECmd parse -> redundant; Windows.EventLogs.Evtx already returns parsed
    rows.
  - vCenter Events API, ESXi syslog -> deferred to v1 (need vSphere/ESXi; this
    deployment runs on VMware Workstation/Player).
  - PowerShell Get-ADUser / Get-ADComputer -> Windows.Sys.Users covers the
    local-machine subset; true AD query is v1.
  - YARA scan -> yara_proc + yara_files (same 884-rule corpus as Scope 1).
  - MISP IOC lookup -> Phase 4 (feature extractor), not an acquisition step.
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

# Event log channel filters. Windows.EventLogs.Evtx walks every *.evtx under
# %SystemRoot%\System32\winevt\Logs\ and returns rows from channels matching
# ChannelRegex. RE2-unanchored, so anchor the precise ones with ^...$.
# Sysmon's channel is "Microsoft-Windows-Sysmon/Operational" — substring match
# is sufficient and survives Sysmon version renames.
EVTX_CHANNEL_SECURITY = r"^Security$"
EVTX_CHANNEL_SYSTEM = r"^System$"
EVTX_CHANNEL_SYSMON = r"Sysmon"

# Recently-modified file scope on Windows. Mirrors the Linux principle: glob
# attacker drop targets that the system's own logging does not. Forward slashes
# work on Windows in Velociraptor's globber and avoid double-backslash
# escaping headaches.
RECENTLY_MODIFIED_GLOBS_CSV = (
    "Glob\n"
    "C:/Users/**\n"
    "C:/Windows/Temp/**\n"
    "C:/ProgramData/**\n"
)
RECENTLY_MODIFIED_WINDOW_HOURS = 24
RECENTLY_MODIFIED_MAX_ROWS = 5000
RECENTLY_MODIFIED_TIMEOUT_SEC = 300.0

# YARA scan caps. Same logic as Scope 1: no rule-namespace filtering at
# acquisition; just bound disk usage and runtime. The 884-rule corpus is
# cross-platform — PE detection rules sit alongside ELF rules and only the
# applicable ones match.
YARA_PROCESS_REGEX = r".*"  # Windows process names don't have the kernel-thread `[name]` pattern
# Exclude C:\Windows\* processes from the YARA scan. Win10 has ~80-100
# processes under System32 / SysWOW64 / servicing / WinSxS, and scanning all
# of them against 884 rules blew past Velociraptor's 600s default per-flow
# timeout. The exclusion is forensically justified: malware that already lives
# in C:\Windows\System32 has by definition achieved admin escalation and will
# be caught by Sysmon + Pslist regardless. The high-signal targets for YARA
# are user-space binaries in C:\Users, C:\ProgramData, C:\Program Files.
YARA_EXE_PATH_WHITELIST = r"(?i)^C:\\Windows\\"
# Empirically Windows produces ~2800 matches on a clean Sysmon-instrumented VM
# (vs. ~400 on clean Ubuntu) — many PE rules in the corpus match Windows DLLs
# loaded into ordinary svchost / explorer processes. 10000 leaves headroom.
YARA_FLOW_MAX_ROWS = 10000
YARA_FLOW_TIMEOUT_SEC = 1200.0

# Windows.Detection.Yara.Glob's PathGlob is a single glob string, not a CSV
# list. Velociraptor's glob() accepts brace expansion. Scope to actual attacker
# drop targets — Linux's equivalent globs /tmp /var/tmp /home/*. The full
# C:/Users/** is too noisy (every browser cache and app DLL); narrowed here to
# AppData/Local/Temp + Downloads which are the typical T1105 / T1059 staging
# paths.
YARA_FILES_PATHGLOB = (
    "C:/{Users/*/AppData/Local/Temp,Users/*/Downloads,Windows/Temp,ProgramData}/**"
)
YARA_FILES_SIZE_MAX = 10 * 1024 * 1024
YARA_FILES_HITS_PER_FILE = 100
# Same logic as YARA_FLOW_MAX_ROWS — Windows produces more hits per file
# than Linux because the corpus has many PE-signature rules that match
# innocuous DLLs sitting under C:/Users (Steam libs, Office, etc.).
YARA_FILES_MAX_ROWS = 10000
YARA_FILES_TIMEOUT_SEC = 1500.0

# Windows.Timeline.MFT parses every $MFT record on the volume and derives
# tampering signals (FNCreatedShift, PossibleCopy, VolumeCopy). On a typical
# Windows 10 install this is ~200-500k records and takes 5-10 min cold-cache.
# NOTE on the KAPE-MFT slot from the pipeline diagram:
#
# Both Windows.Timeline.MFT and Windows.Forensics.Usn were trialled here. Both
# produced 100k+ rows on a vanilla Win10 install and Velociraptor's max_rows is
# a hard cancel rather than a soft truncate. The artifacts' own DateAfter
# parameters did not actually filter (the row count was identical with and
# without DateAfter set to 7 days ago, suggesting the timestamp() epoch parser
# was not consuming our ISO string).
#
# File-activity coverage in v0 remains comprehensive without MFT/USN:
#   - recently_modified (live FS view via Windows.Search.FileFinder)
#   - prefetch          (last ~1024 executions)
#   - amcache           (every binary registered in InventoryApplicationFile)
#   - sysmon Event ID 11 (FileCreate, on every disk write)
#
# Deferred to v0.5: write Custom.Windows.Forensics.RecentFiles wrapping
# parse_mft() + parse_usn() with a server-side WHERE clause that we know
# filters, plus a 24h epoch-arithmetic computed at-dispatch.


def _recently_modified_cutoff() -> str:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=RECENTLY_MODIFIED_WINDOW_HOURS)
    return cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")


def _default_steps() -> list[CollectionStep]:
    # Artifact names verified 2026-05-23 against Velociraptor 0.76.1's default
    # pack via SELECT name FROM artifact_definitions() WHERE name =~ '^Windows'.
    #
    # Step order is fast-to-slow. Event log pulls and snapshot artifacts are
    # seconds each; mft_timeline and the YARA scans can take minutes. Putting
    # slow steps last lets a partial run still capture cheap high-signal data.
    #
    # Output filenames:
    #   - The 3 Evtx steps would collide on Windows.EventLogs.Evtx.json without
    #     an output_filename override (added to VelociraptorArtifactStep for
    #     exactly this case).
    #   - All other steps use a unique artifact, so the default
    #     output_filename = artifact_name is fine.
    yara_rules = load_yara_rules()
    return [
        # Event logs — three channels, one artifact dispatched three times.
        VelociraptorArtifactStep(
            "event_security",
            "Windows.EventLogs.Evtx",
            parameters={"ChannelRegex": EVTX_CHANNEL_SECURITY},
            output_filename="event_security",
        ),
        VelociraptorArtifactStep(
            "event_system",
            "Windows.EventLogs.Evtx",
            parameters={"ChannelRegex": EVTX_CHANNEL_SYSTEM},
            output_filename="event_system",
        ),
        # Sysmon — the strongest signal source on Windows. Confirmed installed
        # (Sysmon64 service Running) on 2026-05-23.
        VelociraptorArtifactStep(
            "sysmon",
            "Windows.EventLogs.Evtx",
            parameters={"ChannelRegex": EVTX_CHANNEL_SYSMON},
            output_filename="sysmon",
        ),
        # Snapshot of process + network + persistence state (fast, no params).
        VelociraptorArtifactStep("processes", "Windows.System.Pslist"),
        # Windows.Network.NetstatEnriched returns 0 rows on this 0.76.1 build
        # (suspected agent-side enrichment query issue); Windows.Network.Netstat
        # is the unembellished view and returns the actual ~60-row list of
        # connections. The OCSF mapper enriches with the agent's own process
        # state from the `processes` step downstream.
        VelociraptorArtifactStep("sockets", "Windows.Network.Netstat"),
        VelociraptorArtifactStep("services", "Windows.System.Services"),
        # scheduled_tasks: Windows.System.TaskScheduler returns 0 rows on this
        # build despite the Tasks folder being populated; same for
        # Windows.EventLogs.ScheduledTasks. Persistence vectors are still
        # covered by services + startup_items. Deferred to v0.5 with a
        # Custom.Windows.Sys.Schtasks.yaml wrapping `schtasks /query /fo CSV /v`.
        # Registry-based startup enumeration. Windows.Sysinternals.Autoruns was
        # the first choice (broader coverage — WMI, image hijacks, winlogon,
        # etc.) but it depends on autorunsc.exe being pre-staged in the
        # Velociraptor tools repo, which is a server-side config we haven't
        # done. Windows.Sys.StartupItems is the pure-VQL fallback: enumerates
        # Run / RunOnce keys and Startup folder entries directly via
        # read_reg_key + glob. Covers the most common persistence vectors
        # (registry Run keys + startup folder); WMI / image-hijack / winlogon
        # is deferred to v0.5 alongside autorunsc.exe staging.
        VelociraptorArtifactStep("startup_items", "Windows.Sys.StartupItems"),
        # Local user enumeration. Standalone-VM analog of the diagram's
        # PowerShell Get-ADUser / Get-ADComputer (which needs a DC).
        VelociraptorArtifactStep("local_users", "Windows.Sys.Users"),
        # osquery — independent dual-view of process state (parallels
        # Custom.Linux.Sys.Osquery's processes table on Scope 1). Windows.OSQuery.Generic
        # is single-query; multi-table curated bundle is deferred to a custom
        # YAML wrapper (Custom.Windows.Sys.Osquery) — see the v0.5 backlog.
        # For v0 we pull the single highest-value table: processes. The OCSF
        # mapper will diff this against Windows.System.Pslist; any disagreement
        # is itself a tampering signal.
        VelociraptorArtifactStep(
            "osquery",
            "Windows.OSQuery.Generic",
            parameters={
                # Drop `username` — present in Linux osquery's processes table
                # but not Windows (Windows processes table exposes uid/euid as
                # UNIX-style ints that are always -1 here). SELECT * keeps us
                # forward-compat with osquery schema bumps and the OCSF mapper
                # picks the columns it needs.
                "Query": "SELECT * FROM processes",
            },
        ),
        # PowerShell command history — analog of Linux bash_history. Reads
        # per-user ConsoleHost_history.txt files written by PSReadLine.
        VelociraptorArtifactStep(
            "powershell_history",
            "Windows.System.Powershell.PSReadline",
        ),
        # Execution evidence. Prefetch (filesystem-based) + Amcache (registry-
        # based) cross-validate each other: discrepancies between the two
        # views are themselves a tampering signal.
        VelociraptorArtifactStep("prefetch", "Windows.Forensics.Prefetch"),
        # Amcache is a 9-source artifact; InventoryApplicationFile is the
        # richest single source (Name, SHA1, FullPath, BinaryType, LinkDate,
        # OriginalFileName) — every binary the system has seen on disk.
        VelociraptorArtifactStep(
            "amcache",
            "Windows.Forensics.Amcache",
            source_name="InventoryApplicationFile",
        ),
        # (MFT/USN-equivalent slot deferred to v0.5 — see module-level note.)
        # Live filesystem view, scoped to attacker drop targets.
        VelociraptorArtifactStep(
            "recently_modified",
            "Windows.Search.FileFinder",
            parameters={
                "SearchFilesGlobTable": RECENTLY_MODIFIED_GLOBS_CSV,
                "MoreRecentThan": _recently_modified_cutoff(),
            },
            max_rows=RECENTLY_MODIFIED_MAX_ROWS,
            timeout_sec=RECENTLY_MODIFIED_TIMEOUT_SEC,
        ),
        # YARA — process memory then file glob. Same 884-rule corpus as
        # Scope 1; the cross-platform rules carry over and the Linux-only
        # rules silently no-match.
        VelociraptorArtifactStep(
            "yara_proc",
            "Windows.Detection.Yara.Process",
            parameters={
                "YaraRule": yara_rules,
                "ProcessRegex": YARA_PROCESS_REGEX,
                "ExePathWhitelist": YARA_EXE_PATH_WHITELIST,
            },
            max_rows=YARA_FLOW_MAX_ROWS,
            timeout_sec=YARA_FLOW_TIMEOUT_SEC,
        ),
        VelociraptorArtifactStep(
            "yara_files",
            "Windows.Detection.Yara.Glob",
            parameters={
                "PathGlob": YARA_FILES_PATHGLOB,
                "YaraRule": yara_rules,
                "SizeMax": YARA_FILES_SIZE_MAX,
                "NumberOfHits": YARA_FILES_HITS_PER_FILE,
            },
            max_rows=YARA_FILES_MAX_ROWS,
            timeout_sec=YARA_FILES_TIMEOUT_SEC,
        ),
    ]


class VMwareAcquirer(Acquirer):
    scope = "vmware"
    # Windows agent observed checking in on a multi-minute cadence (vs. Linux's
    # ~30s). The 120s default would false-positive an online-but-idle agent.
    agent_freshness_max_age_sec = 600.0

    def __init__(
        self,
        steps: list[CollectionStep] | None = None,
        raw_dir: Path | None = None,
        env_path: Path | None = None,
    ) -> None:
        load_dotenv(env_path or DEFAULT_ENV_PATH)
        self.steps = steps if steps is not None else _default_steps()
        self.raw_dir = raw_dir or DEFAULT_RAW_DIR

        api_config = os.environ.get("VELO_API_CONFIG")
        client_id = os.environ.get("SCOPE2_CLIENT_ID")
        if not api_config or not client_id:
            raise RuntimeError(
                "VELO_API_CONFIG and SCOPE2_CLIENT_ID must be set in config/.env"
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

        with VelociraptorClient(self._api_config_path) as client:
            client.check_agent_fresh(
                self._client_id,
                max_age_sec=self.agent_freshness_max_age_sec,
            )

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
        """Run a single named step — verification helper."""
        step = next((s for s in self.steps if s.name == step_name), None)
        if step is None:
            raise KeyError(f"unknown step: {step_name}")
        prior_steps = self.steps
        self.steps = [step]
        try:
            return self.acquire(incident_id)
        finally:
            self.steps = prior_steps
