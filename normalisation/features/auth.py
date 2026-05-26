"""Auth features (class_uid=3002).

Pulls from:
- Linux journald sshd / PAM lines (parsed into status_id by mapper)
- Windows Security.evtx EventID 4624/4625/4634/4720/4732
- Authorized_keys snapshot rows
- Windows local_users snapshot rows
- Plaso UTMP timeline events

`new_user_creations` counts events that look like user account creations:
- Linux: message contains "useradd" or sshd "session opened for" (first time)
- Windows: EventID 4720 (event_id field) OR local_users rows
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

# SSH session-opened lines double as a weak proxy for "user touched the host"
# but are too noisy to count as user creations — we restrict to explicit
# useradd / AccountCreated patterns.
_USERADD_RE = re.compile(r"\b(useradd|net user .* /add|new-localuser)\b", re.IGNORECASE)


def _extract_src_ip(message: str) -> str | None:
    """Pull an IPv4 dotted-quad out of an sshd 'from <ip>' message."""
    if not message:
        return None
    m = re.search(r"\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\b", message)
    return m.group(1) if m else None


def _is_offhours(time_ms: int) -> bool:
    """True if the event falls outside 08:00–18:00 host-local. We don't carry
    host timezone, so we approximate with UTC — acceptable since our v0 hosts
    sit in a single TZ and the model just needs a relative signal."""
    if time_ms <= 0:
        return False
    dt = datetime.fromtimestamp(time_ms / 1000, tz=timezone.utc)
    return dt.hour < 8 or dt.hour >= 18


def compute(events: list[dict]) -> dict:
    auth = [e for e in events if e["class_uid"] == 3002]

    failures = sum(1 for e in auth if e.get("status_id") == 2)
    successes = sum(1 for e in auth if e.get("status_id") == 1)
    total_known = failures + successes
    failure_ratio = round(failures / total_known, 4) if total_known else 0.0

    src_ips: set[str] = set()
    for e in auth:
        ip = _extract_src_ip(e.get("message") or "")
        if ip:
            src_ips.add(ip)

    offhours = 0
    for e in auth:
        if e.get("status_id") == 1 and e.get("activity_id") == 1:
            if _is_offhours(e.get("time", 0)):
                offhours += 1

    # New user creation signals:
    # - Windows EventID 4720 (event_id field in unmapped)
    # - Linux journald useradd messages
    # - Local users snapshot rows (source_step=local_users)
    new_users = 0
    for e in auth:
        if e["unmapped"].get("event_id") == 4720:
            new_users += 1
            continue
        if e["unmapped"].get("source_step") == "local_users":
            new_users += 1
            continue
        if _USERADD_RE.search(e.get("message") or ""):
            new_users += 1

    return {
        "auth_failure_count": failures,
        "auth_success_count": successes,
        "auth_failure_ratio": failure_ratio,
        "unique_src_ips": len(src_ips),
        "offhours_logins": offhours,
        "new_user_creations": new_users,
    }
