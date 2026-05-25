"""Custom.Linux.Sys.AIDE → OCSF File System Activity (class_uid 1001).

AIDE's `raw_report` is a multi-section text dump. We parse it into three
streams:

- Added entries (line prefix `f+++…` or `l+++…` followed by `: /path`)
- Removed entries (line prefix `f---…` or `l---…` followed by `: /path`)
- Changed entries (top-level `Entry /path in databases has different…`,
  AND lines in the `Changed entries:` section with format `<mixed flags>: /path`)

Each parsed change becomes one OCSF 1001 event:
- added   → activity_id=1 (Create)
- removed → activity_id=4 (Delete)
- changed → activity_id=3 (Update)

severity_id=2 by default (Low). Paths under /etc, /usr/bin, /usr/sbin,
/root, /var/spool/cron are escalated to severity_id=3 (Medium) — these are
high-value attack targets and Phase 4 reads severity for triage features.

AIDE has one row per artifact run (with summary counts + the raw_report
text); we emit zero events if the input is empty/missing.
"""

from __future__ import annotations

import re
from typing import Iterable, Iterator

from parsing.ocsf_base import MapperContext, ocsf_event

# Sections inside raw_report — the headers separate added/removed/changed.
_SECTION_HEADER_RE = re.compile(
    r"^-{3,}\s*\n\s*(Added entries|Removed entries|Changed entries)\s*:\s*\n-{3,}\s*\n",
    re.MULTILINE,
)
# Top-level "Entry /path in databases has different attributes: ..." lines —
# AIDE emits these BEFORE the section markers as a quick-glance summary of
# changed files. We capture them as activity_id=3 (Update) with severity=2.
_TOPLEVEL_CHANGED_RE = re.compile(
    r"^Entry (.+?) in databases has different attributes: (.+)$",
    re.MULTILINE,
)
# Within a section, each entry is `<flags>: <path>`. Flags are 18 chars of
# `+`, `-`, `.`, ` `, or letters indicating which attributes changed. We
# don't interpret them; we just want the path.
_ENTRY_LINE_RE = re.compile(r"^[\S]{2,30}:\s+(/[^\s].*)$", re.MULTILINE)

_HIGH_VALUE_PREFIXES = (
    "/etc/",
    "/usr/bin/",
    "/usr/sbin/",
    "/root/",
    "/var/spool/cron/",
    "/home/",  # bash_history, ssh keys
)


def _severity_for(path: str) -> int:
    return 3 if path.startswith(_HIGH_VALUE_PREFIXES) else 2


def _parse_report(raw_report: str) -> Iterator[tuple[str, str]]:
    """Yield (action, path) tuples. action ∈ {'added','removed','changed'}.

    Walks the report in two passes:
    1. Top-level `Entry ... has different attributes` lines → 'changed'.
    2. Sectioned `Added entries:` / `Removed entries:` / `Changed entries:`
       blocks → one entry per matching line.
    """
    if not raw_report:
        return

    # Pass 1 — top-level changed entries (before section headers).
    for m in _TOPLEVEL_CHANGED_RE.finditer(raw_report):
        yield ("changed", m.group(1))

    # Pass 2 — walk sectioned entries.
    # Find each section header and parse from there to the next section
    # (or end of report).
    section_matches = list(_SECTION_HEADER_RE.finditer(raw_report))
    for idx, section in enumerate(section_matches):
        section_name = section.group(1)
        action = {
            "Added entries": "added",
            "Removed entries": "removed",
            "Changed entries": "changed",
        }.get(section_name)
        if action is None:
            continue
        body_start = section.end()
        body_end = (
            section_matches[idx + 1].start() if idx + 1 < len(section_matches) else len(raw_report)
        )
        body = raw_report[body_start:body_end]
        for m in _ENTRY_LINE_RE.finditer(body):
            yield (action, m.group(1).rstrip())


_ACTIVITY_FOR = {"added": 1, "removed": 4, "changed": 3}


def map_rows(rows: Iterable[dict], context: MapperContext) -> Iterator[dict]:
    for row in rows:
        report = row.get("raw_report") or ""
        for action, path in _parse_report(report):
            actor = {
                "process": {
                    "pid": None,
                    "name": None,
                    "cmd_line": None,
                    "file": {"path": path, "fingerprints": []},
                },
            }
            yield ocsf_event(
                class_uid=1001,
                activity_id=_ACTIVITY_FOR[action],
                time_ms=context.acquisition_time_ms,
                raw_row={"aide_action": action, "path": path},
                context=context,
                severity_id=_severity_for(path),
                actor=actor,
                message=f"AIDE: {action} {path}",
            )
