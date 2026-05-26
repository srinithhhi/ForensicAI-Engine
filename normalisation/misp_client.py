"""PyMISP wrapper with disk-backed cache for replayability.

Replayability is the load-bearing requirement here: if we re-run Phase 4
on the same bundle a week later, the output must be byte-identical even
if MISP has new events / new IOCs / is offline. The cache file
`data/processed/{incident_id}/misp_cache.json` is written on first run and
consulted forever after; only cache MISSes hit the network.

CLI:
    python -m normalisation.misp_client --ping
        connects to MISP_URL with MISP_KEY and prints the authenticated user.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from pymisp import PyMISP

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ENV_PATH = REPO_ROOT / "config" / ".env"
CACHE_FILENAME = "misp_cache.json"

# Supported IOC categories — keys used in the cache file.
IOC_TYPES = ("hash", "ip", "domain")


@dataclass
class MispMatch:
    """One IOC → MISP attribute correspondence, distilled to the few fields
    Phase 4 actually consumes. Full attribute dicts are preserved in the
    cache file (`raw` is not in this dataclass) but not surfaced to features.
    """

    value: str
    ioc_type: str
    threat_level_id: int | None
    event_id: int | None
    category: str | None


@dataclass
class MispLookupResult:
    """Result of one `bulk_lookup` call. Indexed by IOC value (lowercase)."""

    matches: dict[str, MispMatch] = field(default_factory=dict)

    def matched_values(self) -> set[str]:
        return set(self.matches.keys())

    def max_threat_level_id(self) -> int:
        """Return the highest-priority threat_level_id (lowest int = highest priority).
        Returns 0 if no matches; MISP threat levels: 1=High 2=Medium 3=Low 4=Undef.
        """
        levels = [m.threat_level_id for m in self.matches.values() if m.threat_level_id]
        return min(levels) if levels else 0


class MispClient:
    """Lazy PyMISP wrapper. Only connects on first lookup call.

    `cache_path` is the per-incident cache file. Pass None to disable caching
    (useful for --ping or one-off scripts).
    """

    def __init__(
        self,
        url: str,
        key: str,
        cache_path: Path | None = None,
        verify_tls: bool = False,
    ) -> None:
        self._url = url
        self._key = key
        self._verify_tls = verify_tls
        self._cache_path = cache_path
        self._cache: dict[str, dict[str, Any]] = {}
        self._client: PyMISP | None = None
        self._dirty = False
        if cache_path is not None and cache_path.exists():
            with cache_path.open() as f:
                self._cache = json.load(f)

    @classmethod
    def from_env(cls, cache_path: Path | None = None) -> "MispClient":
        load_dotenv(DEFAULT_ENV_PATH)
        url = os.environ.get("MISP_URL")
        key = os.environ.get("MISP_KEY")
        if not url or not key:
            raise RuntimeError(
                "MISP_URL and MISP_KEY must be set in config/.env (or the environment)"
            )
        return cls(url=url, key=key, cache_path=cache_path)

    def _connect(self) -> PyMISP:
        if self._client is None:
            # `cert=False` skips TLS verification — our lab MISP uses a
            # self-signed cert. Tighten for production.
            self._client = PyMISP(
                self._url,
                self._key,
                ssl=self._verify_tls,
                debug=False,
            )
        return self._client

    def ping(self) -> dict[str, Any]:
        """Authenticated round-trip to /users/view/me. Used by `--ping` CLI."""
        client = self._connect()
        # PyMISP.get_user('me') hits /users/view/me
        return client.get_user("me")

    def bulk_lookup(self, values: list[str], ioc_type: str) -> MispLookupResult:
        """Look up multiple IOC values of one type.

        Cache key is `{ioc_type}:{value_lowercase}`. Cache stores ALL the
        attribute fields PyMISP returns (`category`, `to_ids`, `value`,
        `Event.threat_level_id`, …) so re-running with a different feature
        layer doesn't require re-querying.
        """
        if ioc_type not in IOC_TYPES:
            raise ValueError(f"unsupported ioc_type {ioc_type!r}")

        bucket = self._cache.setdefault(ioc_type, {})
        to_query: list[str] = []
        for v in values:
            v_norm = v.lower().strip()
            if not v_norm:
                continue
            if v_norm not in bucket:
                to_query.append(v_norm)

        if to_query:
            client = self._connect()
            # PyMISP.search returns events with attributes; we want attributes
            # directly. `controller="attributes"` is the right scope here.
            response = client.search(
                controller="attributes",
                value=to_query,
                pythonify=False,
            )
            # response shape: {"Attribute": [...]} in older PyMISP, sometimes a
            # bare list. Normalise.
            attributes = []
            if isinstance(response, dict):
                attributes = response.get("Attribute") or response.get("attributes") or []
            elif isinstance(response, list):
                attributes = response
            # Index returned attributes by value (lowercased) for fast merge.
            for attr in attributes:
                val = (attr.get("value") or "").lower().strip()
                if not val:
                    continue
                bucket[val] = attr
            # Cache MISSes too — stop re-querying values that don't exist.
            for v in to_query:
                bucket.setdefault(v, None)
            self._dirty = True

        # Build MispLookupResult from cache state for the requested values.
        result = MispLookupResult()
        for v in values:
            v_norm = v.lower().strip()
            attr = bucket.get(v_norm)
            if not attr:
                continue
            event = attr.get("Event") or {}
            threat = event.get("threat_level_id")
            try:
                threat = int(threat) if threat is not None else None
            except (TypeError, ValueError):
                threat = None
            event_id = event.get("id")
            try:
                event_id = int(event_id) if event_id is not None else None
            except (TypeError, ValueError):
                event_id = None
            result.matches[v_norm] = MispMatch(
                value=v_norm,
                ioc_type=ioc_type,
                threat_level_id=threat,
                event_id=event_id,
                category=attr.get("category"),
            )
        return result

    def flush_cache(self) -> None:
        """Write the cache to disk if dirty. Called by the feature extractor
        once per run, after all lookups complete."""
        if not self._dirty or self._cache_path is None:
            return
        self._cache_path.parent.mkdir(parents=True, exist_ok=True)
        with self._cache_path.open("w") as f:
            json.dump(self._cache, f, sort_keys=True, indent=2)
        self._dirty = False


def _ping_cmd() -> int:
    try:
        client = MispClient.from_env(cache_path=None)
    except RuntimeError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2
    try:
        user = client.ping()
    except Exception as exc:
        print(f"FAIL: cannot reach MISP at {client._url}: {exc}", file=sys.stderr)
        return 3
    if not isinstance(user, dict):
        print(f"FAIL: unexpected /users/view/me response shape: {user!r}", file=sys.stderr)
        return 4
    user_block = user.get("User") or user
    email = user_block.get("email", "<unknown>")
    org = (user.get("Organisation") or {}).get("name", "<unknown>")
    print(f"OK     MISP user {email} @ {client._url}  org={org}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ping", action="store_true", help="authenticate against MISP and print user info")
    args = parser.parse_args()
    if args.ping:
        return _ping_cmd()
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
