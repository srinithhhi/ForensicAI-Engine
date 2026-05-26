"""Process features (class_uid=1007 + shell-history obfuscation markers).

Process counts come from 1007 events; obfuscation/encoded-command counts
scan BOTH 1007 events (cmd_line) and 6004 shell-history events (bash_history,
powershell_history). Suspicious-LOLBin matching uses a small curated list —
these are the well-known living-off-the-land binaries that adversaries reach
for on Windows; the model gets a feature for "did any of them appear?"
"""

from __future__ import annotations

import re

# LOLBins — common abuse-prone Windows binaries. Linux gets implicit zero
# because none of these appear in normal Linux process trees.
_LOLBIN_RE = re.compile(
    r"\b(certutil|bitsadmin|regsvr32|mshta|rundll32 javascript:|wmic process call create|"
    r"powershell\.exe -nop|cscript|wscript|installutil|msbuild|msiexec /i http)\b",
    re.IGNORECASE,
)
_OBFUSCATION_RE = re.compile(
    r"(frombase64string|iex \(new-object|iex \(\[char\]|invoke-expression \(new-object|"
    r"-w\s+hidden|-windowstyle\s+hidden|`[a-z]`[a-z])",
    re.IGNORECASE,
)
_ENCODED_RE = re.compile(r"(-encodedcommand|\b-enc\b|encodedcommand:)", re.IGNORECASE)

_SHELL_SOURCE_STEPS = {"bash_history", "powershell_history"}


def compute(events: list[dict]) -> dict:
    processes = [e for e in events if e["class_uid"] == 1007 and e.get("activity_id") == 1]
    elevated = sum(
        1 for e in processes if e["unmapped"].get("is_privileged") is True
    )

    suspicious = 0
    obfuscated = 0
    encoded = 0
    # Pool process events + shell-history events for obfuscation/encoded scans.
    pool = list(processes)
    pool.extend(
        e for e in events
        if e["class_uid"] == 6004 and e["unmapped"].get("source_step") in _SHELL_SOURCE_STEPS
    )
    for e in pool:
        text = " ".join(filter(None, [
            (e.get("actor") or {}).get("process", {}).get("cmd_line"),
            e.get("message"),
        ]))
        if _LOLBIN_RE.search(text):
            suspicious += 1
        if _OBFUSCATION_RE.search(text):
            obfuscated += 1
        if _ENCODED_RE.search(text):
            encoded += 1

    return {
        "process_count": len(processes),
        "elevated_process_count": elevated,
        "suspicious_proc_count": suspicious,
        "powershell_obfuscation_count": obfuscated,
        "encoded_command_count": encoded,
    }
