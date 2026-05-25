"""Linux.Forensics.Journal → OCSF events.

Pattern-setter mapper. Two output classes:

- **3002 Authentication** for rows with `SYSLOG_FACILITY in {4, 10}` (auth +
  authpriv). The MESSAGE text is parsed for known sshd/PAM signatures to set
  `activity_id` (1=Logon 2=Logoff 11=Other/CredentialChange) and `status_id`
  (1=success 2=failure).
- **6004 System Activity** for everything else (kernel, daemon, cron, mail,
  syslog, news, etc.). `activity_id` left at 0 (Unknown); message + identifier
  preserved for downstream parsing.

The mapper does NOT silently drop rows. Every input row maps to exactly one
event so feature aggregation (Phase 4) can count log volume accurately.
"""

from __future__ import annotations

from typing import Iterable, Iterator

from parsing.ocsf_base import MapperContext, ocsf_event, to_epoch_millis

# Syslog facility numbers (RFC 5424). 4=auth, 10=authpriv. Everything else is
# non-auth and goes to System Activity.
AUTH_FACILITIES = {4, 10}

# Auth activity dispatch by sshd/PAM message signature. Order matters: failure
# patterns checked before success because "Failed password for ..." also
# contains "for" which could match user-creation patterns in a looser regex.
# Conservative substring matching — anything we don't recognise falls through
# to activity_id=0 (Unknown) and the row still emits a valid event.
def _classify_auth(message: str) -> tuple[int, int]:
    """Return (activity_id, status_id) for an auth-facility message.

    OCSF Authentication (class_uid=3002) activity values:
      0 Unknown, 1 Logon, 2 Logoff, 3 AuthTicket, 4 ServiceTicketRequest,
      5 ServiceTicketRenew, 6 Preauth, 99 Other.
    OCSF status_id: 1=Success, 2=Failure.
    """
    msg = message.lower() if message else ""
    # Failures first.
    if "failed password" in msg or "authentication failure" in msg or "invalid user" in msg:
        return (1, 2)  # logon attempt, failure
    if "session closed" in msg or "logged out" in msg or "disconnected from" in msg:
        return (2, 1)  # logoff
    if "accepted publickey" in msg or "accepted password" in msg or "session opened" in msg:
        return (1, 1)  # logon, success
    if "new session" in msg:
        return (1, 1)
    # Unknown auth-facility line — emit but flag unknown activity.
    return (0, 0)


def map_rows(rows: Iterable[dict], context: MapperContext) -> Iterator[dict]:
    """Map every Linux.Forensics.Journal row to one OCSF event.

    Time source: prefer `System.SOURCE_REALTIME_TIMESTAMP` (when the event
    actually happened on the originating host) over `System.Timestamp` (when
    journald wrote it). Falls back to Timestamp if SOURCE_REALTIME_TIMESTAMP
    is missing.
    """
    for row in rows:
        event_data = row.get("EventData") or {}
        system = row.get("System") or {}

        facility = event_data.get("SYSLOG_FACILITY")
        identifier = event_data.get("SYSLOG_IDENTIFIER")
        message = event_data.get("MESSAGE") or ""
        priority = event_data.get("PRIORITY")

        hostname = system.get("_HOSTNAME")
        pid = system.get("_PID")
        uid = system.get("_UID")
        comm = system.get("_COMM")
        cmdline = system.get("_CMDLINE")

        time_value = (
            system.get("SOURCE_REALTIME_TIMESTAMP")
            or system.get("Timestamp")
        )
        try:
            time_ms = to_epoch_millis(time_value)
        except ValueError:
            time_ms = 0

        actor: dict = {}
        if uid is not None or comm:
            actor["user"] = {
                "name": comm or None,  # journald has no user name field; identify by process command
                "uid": str(uid) if uid is not None else None,
            }
        if pid is not None or cmdline or comm:
            actor["process"] = {
                "pid": pid if isinstance(pid, int) else None,
                "name": comm,
                "cmd_line": cmdline,
            }

        src_endpoint = {"hostname": hostname} if hostname else None

        unmapped_extra = {
            "syslog_facility": facility if isinstance(facility, int) else None,
            "syslog_identifier": identifier,
        }

        if facility in AUTH_FACILITIES:
            activity_id, status_id = _classify_auth(message)
            # Severity: failed auth = 4 (High), unknown auth = 3 (Medium),
            # success = 1 (Informational). Driven by status_id, not message.
            if status_id == 2:
                severity_id = 4
            elif status_id == 0:
                severity_id = 3
            else:
                severity_id = 1
            yield ocsf_event(
                class_uid=3002,
                activity_id=activity_id,
                time_ms=time_ms,
                raw_row=row,
                context=context,
                severity_id=severity_id,
                status_id=status_id,
                actor=actor or None,
                src_endpoint=src_endpoint,
                message=message,
                unmapped_extra=unmapped_extra,
            )
        else:
            # Map syslog priority (0-7, lower=more severe) to OCSF severity_id
            # (1-6, higher=more severe). Defaults to 1 (Info) for missing.
            sev = 1
            if isinstance(priority, int):
                if priority <= 2:
                    sev = 5  # Critical/Alert/Emergency
                elif priority == 3:
                    sev = 4  # Error → High
                elif priority == 4:
                    sev = 3  # Warning → Medium
                elif priority == 5:
                    sev = 2  # Notice → Low
                else:
                    sev = 1  # Info/Debug → Informational
            yield ocsf_event(
                class_uid=6004,
                activity_id=0,
                time_ms=time_ms,
                raw_row=row,
                context=context,
                severity_id=sev,
                actor=actor or None,
                src_endpoint=src_endpoint,
                message=message,
                unmapped_extra=unmapped_extra,
            )
