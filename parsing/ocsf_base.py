"""Shared utilities used by every OCSF mapper.

Every mapper module imports these helpers; mapper modules themselves never
import `json`, `datetime`, or the schema directly — go through these helpers
so that schema/format drift is a one-place change.

Provides:
- `ocsf_event(...)`: factory that constructs and stamps an OCSF event dict.
- `to_epoch_millis(...)`: parses ISO8601, epoch-seconds, epoch-microseconds,
  and Windows FILETIME into a uniform epoch-millis integer.
- `normalise_hash(...)`: maps Velociraptor's `{MD5,SHA1,SHA256}` hash dicts
  into OCSF's `fingerprints` array shape.
- `read_artifact_rows(...)`: streams a Velociraptor JSON-array artifact file.
- `MapperContext`: per-incident context handed to every mapper (carries the
  scope, incident_id, and source-step provenance fields that go in `unmapped`).
- `validate_event(...)`: jsonschema check against `schemas/ocsf_event_v1.json`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import jsonschema

REPO_ROOT = Path(__file__).resolve().parent.parent
OCSF_SCHEMA_PATH = REPO_ROOT / "schemas" / "ocsf_event_v1.json"
OCSF_VERSION = "1.3.0"
PRODUCT_NAME = "ForensicAI-Engine"

# Windows FILETIME epoch (1601-01-01) → Unix epoch (1970-01-01) offset in 100-ns units.
# Used to detect FILETIME integers (very large epoch values) and convert them.
FILETIME_EPOCH_OFFSET_100NS = 116444736000000000


@dataclass(frozen=True)
class MapperContext:
    """Per-incident context every mapper receives.

    Carries provenance fields that every emitted event needs in its `unmapped`
    block, plus `acquisition_time_ms` — used by mappers whose artifact is a
    *snapshot* (systemd unit list, bash_history file contents, authorized_keys
    inventory) and therefore has no per-row event time. These mappers fall
    back to "what time did the collector observe this state?" which is the
    step's `started_at`.

    Created once per step by the driver from the manifest, never mutated.
    """

    scope: str
    incident_id: str
    source_step: str
    source_artifact: str
    acquisition_time_ms: int


# Lazy-loaded jsonschema validator. Loaded on first validate_event() call.
_validator: jsonschema.Draft202012Validator | None = None


def _get_validator() -> jsonschema.Draft202012Validator:
    global _validator
    if _validator is None:
        with OCSF_SCHEMA_PATH.open() as f:
            schema = json.load(f)
        _validator = jsonschema.Draft202012Validator(schema)
    return _validator


def to_epoch_millis(value: Any) -> int:
    """Coerce a timestamp value into epoch milliseconds.

    Accepts:
    - ISO 8601 / RFC 3339 strings (`"2026-05-23T13:43:52Z"`,
      `"2026-05-23T11:57:01.525437Z"`, with or without microseconds and
      timezone designator)
    - Integers/floats interpreted as either seconds, milliseconds,
      microseconds, or Windows FILETIME based on magnitude
    - `None` → 0 (caller should usually filter these out instead)

    Raises ValueError on unparseable input.
    """
    if value is None or value == "":
        return 0
    if isinstance(value, (int, float)):
        v = int(value)
        # Magnitude heuristic — pick the unit by orders of magnitude.
        # Unix epoch in 2020 ≈ 1.6e9 seconds, 1.6e12 ms, 1.6e15 us.
        # FILETIME (100ns since 1601) for 2020 ≈ 1.3e17.
        if v >= 10**17:
            # FILETIME (100ns since 1601-01-01)
            unix_100ns = v - FILETIME_EPOCH_OFFSET_100NS
            return unix_100ns // 10_000
        if v >= 10**14:
            # Microseconds since Unix epoch
            return v // 1_000
        if v >= 10**11:
            # Milliseconds since Unix epoch (already)
            return v
        # Seconds since Unix epoch
        return v * 1_000
    if isinstance(value, str):
        s = value.strip()
        # Python <3.11 fromisoformat is strict: microseconds must be exactly
        # 3 or 6 digits, and "Z" suffix is rejected. Velociraptor/journald
        # emit 5-digit microseconds (e.g. ".27676Z"), so we normalise both
        # quirks here. Drop to using a regex rather than datetime.strptime
        # because the timestamp can have variable precision (no fraction,
        # 3, 5, 6, or even 9 digits depending on source).
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        # Normalise fractional seconds to exactly 6 digits.
        import re
        m = re.match(r"^(.+?T\d{2}:\d{2}:\d{2})\.(\d+)(.*)$", s)
        if m:
            base, frac, tail = m.groups()
            frac = (frac + "000000")[:6]  # pad or truncate to microsecond
            s = f"{base}.{frac}{tail}"
        try:
            dt = datetime.fromisoformat(s)
        except ValueError as exc:
            raise ValueError(f"unparseable timestamp string: {value!r}") from exc
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1_000)
    raise ValueError(f"unsupported timestamp type {type(value).__name__}: {value!r}")


def normalise_hash(hashes: dict | None) -> list[dict]:
    """Convert Velociraptor hash dict into OCSF `fingerprints` array.

    Velociraptor emits `{"MD5": "...", "SHA1": "...", "SHA256": "..."}` (with
    case-insensitive variants). OCSF expects an array of
    `{"algorithm_id": <int>, "value": "<hex>"}` entries.

    Returns an empty list if `hashes` is None/empty.
    """
    if not hashes:
        return []
    # OCSF algorithm_id: 1=MD5 2=SHA1 3=SHA256 4=SHA512.
    algo_map = {"MD5": 1, "SHA1": 2, "SHA256": 3, "SHA512": 4}
    out: list[dict] = []
    for k, v in hashes.items():
        if not v:
            continue
        algo_id = algo_map.get(k.upper())
        if algo_id is None:
            continue
        out.append({"algorithm_id": algo_id, "value": v.lower()})
    return out


def read_artifact_rows(bundle_dir: Path, relative_path: str) -> Iterator[dict]:
    """Stream rows from a Velociraptor artifact JSON file.

    Velociraptor emits a top-level JSON array. We load it once (artifacts are
    bounded by Velociraptor's max_rows + our 100 MB gRPC cap) and yield rows.

    Yields nothing if the file is empty (`[]`) — callers must not assume any
    rows exist.
    """
    full_path = bundle_dir / relative_path
    with full_path.open() as f:
        # Streaming parse would help for the 34 MB Windows EVTX files, but the
        # input fits in memory comfortably; ijson would add a dep for marginal
        # gain. Revisit if we ever process bundles >1 GB.
        rows = json.load(f)
    if not isinstance(rows, list):
        raise ValueError(f"{full_path} did not contain a top-level JSON array")
    for row in rows:
        yield row


def ocsf_event(
    *,
    class_uid: int,
    activity_id: int,
    time_ms: int,
    raw_row: Any,
    context: MapperContext,
    severity_id: int = 1,
    status_id: int | None = None,
    actor: dict | None = None,
    src_endpoint: dict | None = None,
    dst_endpoint: dict | None = None,
    message: str | None = None,
    unmapped_extra: dict | None = None,
) -> dict:
    """Factory for a single OCSF event dict.

    Every mapper builds events through this function; it stamps `metadata`,
    fills the `unmapped` provenance block from the `context`, and JSON-encodes
    the original row into `raw_data` for replayability.

    `severity_id` defaults to 1 (Informational) — mappers override for known
    high-severity events (auth failures, yara hits, etc.).

    `unmapped_extra` is merged into the standard `unmapped` block — used for
    artifact-specific provenance fields (e.g. `syslog_facility`, `event_id`).
    """
    event: dict = {
        "metadata": {"version": OCSF_VERSION, "product": {"name": PRODUCT_NAME}},
        "class_uid": class_uid,
        "activity_id": activity_id,
        "time": time_ms,
        "severity_id": severity_id,
        "raw_data": json.dumps(raw_row, sort_keys=True, default=str),
        "unmapped": {
            "scope": context.scope,
            "incident_id": context.incident_id,
            "source_step": context.source_step,
            "source_artifact": context.source_artifact,
        },
    }
    if status_id is not None:
        event["status_id"] = status_id
    if actor:
        event["actor"] = actor
    if src_endpoint:
        event["src_endpoint"] = src_endpoint
    if dst_endpoint:
        event["dst_endpoint"] = dst_endpoint
    if message:
        event["message"] = message
    if unmapped_extra:
        event["unmapped"].update(unmapped_extra)
    return event


def validate_event(event: dict) -> list[str]:
    """Validate an event against `schemas/ocsf_event_v1.json`.

    Returns a list of error paths (empty list = valid). The driver routes
    events with non-empty errors to `dead_letter.ndjson` so they can be
    inspected without crashing the run.
    """
    validator = _get_validator()
    return [
        f"{'/'.join(str(p) for p in err.absolute_path) or '<root>'}: {err.message}"
        for err in validator.iter_errors(event)
    ]
