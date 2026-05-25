"""Windows Security.evtx → OCSF Authentication (class_uid 3002).

Every event in the Security channel maps to an Authentication event with the
activity / status / severity chosen by EventID dispatch. Unknown EventIDs
emit activity_id=99 (Other) at Informational severity — they still produce a
valid event so log-volume features (Phase 4) stay accurate.

High-severity EventIDs for triage:
- 4625 failed logon         → severity High
- 4720 user account created → severity High (lateral-movement / persistence)
- 4672 special privs assigned → severity Medium
- 4732 group membership added → severity High
"""

from __future__ import annotations

from typing import Iterable, Iterator

from parsing.ocsf_base import MapperContext, ocsf_event
from parsing.ocsf_mappers._evtx_shared import extract

# EventID → (activity_id, status_id, severity_id, label).
# activity_id: 1=Logon, 2=Logoff, 99=Other.
# status_id:   1=Success, 2=Failure, None=N/A.
# severity_id: 1=Informational ... 4=High.
SEC_DISPATCH: dict[int, tuple[int, int | None, int, str]] = {
    4624: (1, 1, 1, "logon_success"),
    4625: (1, 2, 4, "logon_failure"),
    4634: (2, 1, 1, "logoff"),
    4647: (2, 1, 1, "logoff_user_initiated"),
    4648: (1, 1, 2, "logon_explicit_creds"),
    4672: (99, 1, 3, "special_privileges_assigned"),
    4688: (99, 1, 1, "process_created"),
    4720: (99, 1, 4, "user_account_created"),
    4722: (99, 1, 3, "user_account_enabled"),
    4724: (99, 1, 3, "password_reset_attempt"),
    4725: (99, 1, 2, "user_account_disabled"),
    4726: (99, 1, 3, "user_account_deleted"),
    4732: (99, 1, 4, "user_added_to_group"),
    4733: (99, 1, 2, "user_removed_from_group"),
    4738: (99, 1, 2, "user_account_changed"),
    4740: (99, 2, 3, "user_account_locked"),
    4767: (99, 1, 2, "user_account_unlocked"),
    4798: (99, 1, 1, "user_group_membership_enumerated"),
    4799: (99, 1, 1, "security_group_enumerated"),
    4907: (99, 1, 1, "audit_settings_changed"),
    5061: (99, 1, 1, "cryptographic_operation"),
    5379: (99, 1, 1, "credential_manager_read"),
}


def map_rows(rows: Iterable[dict], context: MapperContext) -> Iterator[dict]:
    for row in rows:
        e = extract(row, context)
        activity_id, status_id, severity_id, label = SEC_DISPATCH.get(
            e.event_id or -1, (99, None, 1, "unknown")
        )

        # Account name + SID come from common EventData fields; their exact
        # field names vary by EventID, so we try the most common first.
        ed = e.event_data
        user_name = (
            ed.get("TargetUserName")
            or ed.get("SubjectUserName")
            or ed.get("MemberName")
        )
        user_sid = ed.get("TargetUserSid") or ed.get("SubjectUserSid")

        actor: dict = {}
        if user_name or user_sid:
            actor["user"] = {
                "name": user_name if user_name not in (None, "-", "") else None,
                "uid": user_sid if user_sid not in (None, "S-1-0-0") else None,
            }

        src_endpoint = {"hostname": e.computer} if e.computer else None

        yield ocsf_event(
            class_uid=3002,
            activity_id=activity_id,
            time_ms=e.time_ms,
            raw_row=e.raw_row,
            context=context,
            severity_id=severity_id,
            status_id=status_id,
            actor=actor or None,
            src_endpoint=src_endpoint,
            message=row.get("Message", "").split("\n", 1)[0] if row.get("Message") else None,
            unmapped_extra={"event_id": e.event_id},
        )
