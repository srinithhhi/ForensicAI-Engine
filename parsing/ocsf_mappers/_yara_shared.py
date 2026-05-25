"""Shared helper for yara_proc and yara_glob mappers.

Both Velociraptor yara artifacts (process scan + filesystem glob scan) emit
the same hit shape: `Rule`, `Meta` (author/date/description), `YaraString`,
`HitContext` with stored md5/sha256, plus a target (process info for
Linux.Detection.Yara.Process / file path for Linux.Detection.Yara.Glob).

We emit one OCSF Detection Finding (class_uid=2004) per hit, severity High
(4) — every yara hit is a triage-worthy signal in our pipeline.
"""

from __future__ import annotations

from typing import Iterable, Iterator

from parsing.ocsf_base import MapperContext, ocsf_event, to_epoch_millis


def yara_hit_to_detection(
    rows: Iterable[dict],
    context: MapperContext,
    target_kind: str,
) -> Iterator[dict]:
    """Emit OCSF 2004 Detection Finding events for yara hits.

    `target_kind` is either "process" (yara_proc) or "file" (yara_glob) — it
    determines which fields carry the actor/target information. The hit's
    target identifier (pid+process_name OR filesystem path) is added to
    `unmapped.yara_rule` along with the rule name for fast Phase 4 grouping.
    """
    for row in rows:
        rule = row.get("Rule")
        hit_ctx = row.get("HitContext") or {}
        meta = row.get("Meta") or {}

        # Both flavours of artifact lack their own per-hit timestamp.
        # yara_glob has Mtime on the matched file; yara_proc has nothing.
        # Fall back to acquisition time for yara_proc; use Mtime for yara_glob.
        time_val = row.get("Mtime")
        try:
            time_ms = (
                to_epoch_millis(time_val) if time_val else context.acquisition_time_ms
            )
        except ValueError:
            time_ms = context.acquisition_time_ms

        actor: dict = {}
        if target_kind == "process":
            pid_raw = row.get("Pid")
            try:
                pid = int(pid_raw) if pid_raw is not None else None
            except (TypeError, ValueError):
                pid = None
            actor["process"] = {
                "pid": pid,
                "name": row.get("ProcessName"),
                "cmd_line": row.get("CommandLine"),
                "file": {
                    "path": None,
                    "fingerprints": _ctx_fingerprints(hit_ctx),
                },
            }
        else:  # file
            actor["process"] = {
                "pid": None,
                "name": None,
                "cmd_line": None,
                "file": {
                    "path": row.get("OSPath"),
                    "fingerprints": _ctx_fingerprints(hit_ctx),
                },
            }

        author = meta.get("author") or "unknown"
        description = meta.get("description") or ""
        message = f"YARA rule {rule!r} ({author}) — {description}".strip()

        yield ocsf_event(
            class_uid=2004,
            activity_id=1,  # 1 = Create (a detection finding was created)
            time_ms=time_ms,
            raw_row=row,
            context=context,
            severity_id=4,  # High — every yara hit gets attention
            actor=actor,
            message=message,
            unmapped_extra={"yara_rule": rule},
        )


def _ctx_fingerprints(hit_ctx: dict) -> list[dict]:
    """Pull md5/sha256 from HitContext into OCSF fingerprints array.

    Velociraptor's HitContext lowercases the hash keys (`md5`, `sha256`),
    unlike Pslist's Hash dict which uppercases them — so we can't reuse
    `normalise_hash()` directly.
    """
    out: list[dict] = []
    if hit_ctx.get("md5"):
        out.append({"algorithm_id": 1, "value": hit_ctx["md5"].lower()})
    if hit_ctx.get("sha256"):
        out.append({"algorithm_id": 3, "value": hit_ctx["sha256"].lower()})
    return out
