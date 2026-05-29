"""Build the timeline payload for the dashboard replay.

Turns data/processed/{id}/events.ndjson into a compact, render-friendly JSON the
Plotly chart animates. Three jobs:

1. Attack-flag each event (handoff M2 §1 logic, adapted to the real schema:
   source_step + event_id live under event["unmapped"], YARA hits use
   severity_id 4, the Windows glob step is named "yara_files").

2. Window the x-axis. Raw event times span *years* because file-system events
   carry ancient mtimes (AIDE/plaso/recently-modified). A literal earliest→
   latest axis would bury the acquisition-time burst in a one-pixel sliver. We
   anchor the window to the latest event and look back at most WINDOW_CAP_HOURS,
   trimming stale-mtime outliers so the replay shows the forensically
   interesting period.

3. Downsample to keep Plotly smooth. 50k dots animate like sludge. We cap total
   dots, but FIRST keep every "rare" attack (sysmon high-sev, evtx
   4720/4625/7045) — those are the real story and must never be sampled out —
   then stride-sample the noisy YARA attacks and the benign background to fill
   the budget.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

# class_uid -> lane label (canonical names from the OCSF mappers).
CLASS_LANES: list[tuple[int, str]] = [
    (2004, "Detection"),
    (1007, "Process"),
    (3002, "Authentication"),
    (4001, "Network"),
    (1001, "File System"),
    (6004, "System"),
]
_LANE_INDEX = {uid: i for i, (uid, _) in enumerate(CLASS_LANES)}

# Evtx event_ids that are attack signals on their own.
ATTACK_EVENT_IDS = {4720, 4625, 7045}  # user created / failed logon / service installed
YARA_STEPS = {"yara_proc", "yara_glob", "yara_files"}
HIGH_SEVERITY = 4  # OCSF severity_id: 4 = High

WINDOW_CAP_HOURS = 72
MAX_DOTS = 800
MAX_ATTACK_DOTS = 400


def _classify(event: dict) -> tuple[bool, Optional[str]]:
    """Return (is_attack, reason). reason is a short tag for the rare signals."""
    u = event.get("unmapped", {})
    step = u.get("source_step")
    if step in YARA_STEPS:
        return True, "yara"
    if step == "sysmon" and event.get("severity_id", 0) >= HIGH_SEVERITY:
        return True, "sysmon-high"
    eid = u.get("event_id")
    if eid in ATTACK_EVENT_IDS:
        return True, f"evtx-{eid}"
    return False, None


def _is_rare_attack(reason: Optional[str]) -> bool:
    """Rare = the high-value, low-volume signals we must always show."""
    return bool(reason) and reason != "yara"


def _stride_sample(items: list, budget: int) -> list:
    """Evenly sample `budget` items across `items`, preserving order."""
    if budget <= 0:
        return []
    if len(items) <= budget:
        return items
    step = len(items) / budget
    return [items[int(i * step)] for i in range(budget)]


def load_events(processed_dir: Path) -> list[dict]:
    events_path = processed_dir / "events.ndjson"
    if not events_path.exists():
        return []
    out: list[dict] = []
    with events_path.open() as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def build_timeline(processed_dir: Path) -> dict:
    raw = load_events(processed_dir)
    # Drop events without a usable timestamp (time<=0 sorts to epoch 0).
    timed = [e for e in raw if e.get("time", 0) > 0 and e.get("class_uid") in _LANE_INDEX]

    if not timed:
        return {
            "lanes": [name for _, name in CLASS_LANES],
            "window": {"start_ms": 0, "end_ms": 0},
            "events": [],
            "total_events": len(raw),
            "attack_total": 0,
            "shown": 0,
        }

    max_t = max(e["time"] for e in timed)
    window_start = max_t - WINDOW_CAP_HOURS * 3600 * 1000
    windowed = [e for e in timed if e["time"] >= window_start]
    # If the cap trimmed everything to a sliver, fall back to all timed events.
    if len(windowed) < min(20, len(timed)):
        windowed = timed
        window_start = min(e["time"] for e in timed)

    # Classify + split.
    rare: list[dict] = []
    yara: list[dict] = []
    benign: list[dict] = []
    attack_total = 0
    for e in windowed:
        is_attack, reason = _classify(e)
        rec = {
            "t": e["time"],
            "c": e["class_uid"],
            "lane": _LANE_INDEX[e["class_uid"]],
            "s": e.get("severity_id", 1),
            "a": 1 if is_attack else 0,
            "step": e.get("unmapped", {}).get("source_step", ""),
            "reason": reason or "",
            "msg": (str(e.get("message", "")) or "")[:120],
        }
        if is_attack:
            attack_total += 1
            (rare if _is_rare_attack(reason) else yara).append(rec)
        else:
            benign.append(rec)

    # Budget: every rare attack, then fill attack budget with sampled yara,
    # then fill the rest with sampled benign.
    kept_rare = rare  # always keep all
    yara_budget = max(0, MAX_ATTACK_DOTS - len(kept_rare))
    kept_yara = _stride_sample(yara, yara_budget)
    attack_kept = kept_rare + kept_yara
    benign_budget = max(0, MAX_DOTS - len(attack_kept))
    kept_benign = _stride_sample(benign, benign_budget)

    dots = attack_kept + kept_benign
    dots.sort(key=lambda d: d["t"])

    return {
        "lanes": [name for _, name in CLASS_LANES],
        "window": {"start_ms": window_start, "end_ms": max_t},
        "events": dots,
        "total_events": len(raw),
        "attack_total": attack_total,
        "rare_attack_total": len(rare),
        "shown": len(dots),
    }
