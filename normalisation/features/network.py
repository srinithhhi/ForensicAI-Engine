"""Network features (class_uid=4001).

Pulls remote IPs / listen ports / DNS queries from the Network Activity
events. `connections_to_threat_intel_ip` is computed in the ioc module
(which has the MISP client) — this module just returns the set of distinct
remote IPs so ioc can do the lookup.
"""

from __future__ import annotations

# Local / private IP prefixes we exclude from "remote" counts. The model
# learns from genuinely outbound or pivoted traffic, not loopback.
_LOCAL_PREFIXES = ("127.", "0.0.0.0", "::", "::1", "fe80")


def _is_remote(ip: str | None) -> bool:
    if not ip or ip == "0.0.0.0":
        return False
    return not ip.startswith(_LOCAL_PREFIXES)


def extract_remote_ips(events: list[dict]) -> set[str]:
    """Public helper used by ioc.py to know which IPs to MISP-lookup."""
    ips: set[str] = set()
    for e in events:
        if e["class_uid"] != 4001:
            continue
        dst = (e.get("dst_endpoint") or {}).get("ip")
        if _is_remote(dst):
            ips.add(dst)
    return ips


def compute(events: list[dict]) -> dict:
    net = [e for e in events if e["class_uid"] == 4001]
    remote_ips = extract_remote_ips(events)

    listen_ports: set[int] = set()
    for e in net:
        if e.get("activity_id") == 7:  # 7 = Listen
            port = (e.get("src_endpoint") or {}).get("port")
            if isinstance(port, int) and port > 0:
                listen_ports.add(port)

    # DNS = Sysmon EventID 22.
    dns_count = sum(
        1 for e in net if e["unmapped"].get("event_id") == 22
    )

    return {
        "unique_remote_ips": len(remote_ips),
        "listen_port_count": len(listen_ports),
        "dns_query_count": dns_count,
        # `connections_to_threat_intel_ip` is filled in by ioc.compute(),
        # which has the MISP client. We seed it to 0 here so the schema
        # never sees a missing key.
        "connections_to_threat_intel_ip": 0,
    }
