"""Linux.Ssh.AuthorizedKeys → OCSF Authentication (class_uid 3002).

Velociraptor walks every authorized_keys file under /root and /home and
emits one row per key present at collection time. This is an inventory
snapshot, not an event stream — we emit each key as an Authentication event
with activity_id=99 (Other) and status_id=1 (Success), tagged with the
fingerprint comment so Phase 4 can flag unexpected key additions.
"""

from __future__ import annotations

from typing import Iterable, Iterator

from parsing.ocsf_base import MapperContext, ocsf_event


def _user_from_path(path: str | None) -> str | None:
    if not path:
        return None
    parts = path.split("/")
    if len(parts) >= 3 and parts[1] == "home":
        return parts[2]
    if len(parts) >= 2 and parts[1] == "root":
        return "root"
    return None


def map_rows(rows: Iterable[dict], context: MapperContext) -> Iterator[dict]:
    for row in rows:
        ospath = row.get("OSPath")
        user = _user_from_path(ospath)
        keytype = row.get("keytype")
        comment = row.get("comment") or ""

        actor = {"user": {"name": user, "uid": None}} if user else None
        message = f"authorized_key present ({keytype}) — {comment}".strip()

        yield ocsf_event(
            class_uid=3002,
            activity_id=99,  # Other — neither logon nor logoff; key-inventory entry
            time_ms=context.acquisition_time_ms,
            raw_row=row,
            context=context,
            severity_id=2,  # auth_keys snapshot is notable for persistence triage
            status_id=1,
            actor=actor,
            message=message,
        )
