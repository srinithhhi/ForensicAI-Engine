"""IOC enrichment via MISP (the only network-calling feature module).

Three lookup classes:
- **hashes** — SHA256/MD5 from class_uid=1007 process events and
  class_uid=2004 yara hits (HitContext.sha256 lives in the actor's
  process.file.fingerprints OCSF array).
- **IPs** — distinct remote IPs from class_uid=4001 events (via
  network.extract_remote_ips).
- **domains** — DNS query names from Sysmon EventID 22 events (which the
  sysmon mapper stores in dst_endpoint.hostname).

Graceful degradation: if `misp_client` is None or `bulk_lookup` raises
(server unreachable, bad key, TLS error), all ioc_* features return 0 and
the connections_to_threat_intel_ip override is skipped. This preserves
schema validity so the feature vector can still be produced and re-run
later when MISP is reachable.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from normalisation.features.network import extract_remote_ips

if TYPE_CHECKING:
    from normalisation.misp_client import MispClient


def _iter_fingerprint_values(events: list[dict], algo_id: int) -> set[str]:
    """Pull lowercased hex values for a given OCSF algorithm_id from any
    event's actor.process.file.fingerprints array."""
    out: set[str] = set()
    for e in events:
        proc = ((e.get("actor") or {}).get("process") or {})
        fps = (proc.get("file") or {}).get("fingerprints") or []
        for fp in fps:
            if fp.get("algorithm_id") == algo_id and fp.get("value"):
                out.add(fp["value"].lower())
    return out


def _extract_dns_query_names(events: list[dict]) -> set[str]:
    out: set[str] = set()
    for e in events:
        if e["class_uid"] != 4001:
            continue
        if e["unmapped"].get("event_id") != 22:
            continue
        name = (e.get("dst_endpoint") or {}).get("hostname")
        if name and "." in name:
            out.add(name.lower())
    return out


def _all_zero() -> dict:
    return {
        "ioc_hash_matches": 0,
        "ioc_ip_matches": 0,
        "ioc_domain_matches": 0,
        "ioc_match_threat_levels_max": 0,
        "connections_to_threat_intel_ip": 0,
    }


def compute(events: list[dict], misp_client: "MispClient | None") -> dict:
    if misp_client is None:
        return _all_zero()

    # SHA256 (algorithm_id=3) is the dominant hash in our pipeline; MD5
    # (algorithm_id=1) is included for completeness because Velociraptor's
    # Pslist still emits it on Windows.
    hashes = _iter_fingerprint_values(events, 3) | _iter_fingerprint_values(events, 1)
    ips = extract_remote_ips(events)
    domains = _extract_dns_query_names(events)

    try:
        hash_result = misp_client.bulk_lookup(sorted(hashes), "hash") if hashes else None
        ip_result = misp_client.bulk_lookup(sorted(ips), "ip") if ips else None
        domain_result = misp_client.bulk_lookup(sorted(domains), "domain") if domains else None
    except Exception as exc:  # MISP is best-effort; degrade gracefully
        print(f"[ioc] MISP lookup failed — returning zeros. ({exc})")
        return _all_zero()

    threat_levels = []
    for result in (hash_result, ip_result, domain_result):
        if result:
            tl = result.max_threat_level_id()
            if tl:
                threat_levels.append(tl)
    # MISP threat_level_id semantics: 1=High, 4=Undefined → we report the MIN
    # (highest-priority) found, or 0 if none.
    max_threat = min(threat_levels) if threat_levels else 0

    return {
        "ioc_hash_matches": len(hash_result.matched_values()) if hash_result else 0,
        "ioc_ip_matches": len(ip_result.matched_values()) if ip_result else 0,
        "ioc_domain_matches": len(domain_result.matched_values()) if domain_result else 0,
        "ioc_match_threat_levels_max": max_threat,
        "connections_to_threat_intel_ip": (
            len(ip_result.matched_values()) if ip_result else 0
        ),
    }
