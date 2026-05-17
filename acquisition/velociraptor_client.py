"""Thin gRPC wrapper around the Velociraptor server API.

All gRPC details — channel setup, mTLS auth, VQL submission, flow polling,
result streaming — live here. Nothing else in the acquisition layer should
import `grpc` or `pyvelociraptor` directly.

CLI:
    python -m acquisition.velociraptor_client --ping
        lists connected clients (verification step 1 from the plan)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import grpc
import yaml
from dotenv import load_dotenv
from pyvelociraptor import api_pb2, api_pb2_grpc

from acquisition.base import AgentStaleError

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ENV_PATH = REPO_ROOT / "config" / ".env"

FLOW_POLL_INTERVAL_SEC = 2.0
FLOW_TIMEOUT_SEC = 180.0
AGENT_FRESHNESS_MAX_AGE_SEC = 120.0


class VelociraptorClient:
    """One-shot client. Reads api.config.yaml, holds a gRPC channel."""

    def __init__(self, api_config_path: Path) -> None:
        with api_config_path.open() as f:
            config = yaml.safe_load(f)

        creds = grpc.ssl_channel_credentials(
            root_certificates=config["ca_certificate"].encode(),
            private_key=config["client_private_key"].encode(),
            certificate_chain=config["client_cert"].encode(),
        )
        options = (("grpc.ssl_target_name_override", "VelociraptorServer"),)
        self._channel = grpc.secure_channel(
            config["api_connection_string"], creds, options
        )
        self._stub = api_pb2_grpc.APIStub(self._channel)

    def close(self) -> None:
        self._channel.close()

    def __enter__(self) -> "VelociraptorClient":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def _run_vql(self, vql: str, name: str = "query") -> list[dict[str, Any]]:
        request = api_pb2.VQLCollectorArgs(
            max_wait=10,
            Query=[api_pb2.VQLRequest(Name=name, VQL=vql)],
        )
        rows: list[dict[str, Any]] = []
        for response in self._stub.Query(request):
            if response.Response:
                rows.extend(json.loads(response.Response))
        return rows

    def list_clients(self) -> list[dict[str, Any]]:
        return self._run_vql(
            "SELECT client_id, os_info.hostname AS hostname, last_seen_at "
            "FROM clients()",
            name="list_clients",
        )

    def agent_age_seconds(self, client_id: str) -> float:
        """Return seconds since the agent last checked in. Raises if client unknown."""
        rows = self._run_vql(
            f"SELECT last_seen_at FROM clients() WHERE client_id = '{client_id}'",
            name="agent_age",
        )
        if not rows:
            raise AgentStaleError(f"client {client_id} has no record on the server")
        ls_us = rows[0].get("last_seen_at")
        if not ls_us:
            raise AgentStaleError(f"client {client_id} has no last_seen_at")
        last_seen = datetime.fromtimestamp(ls_us / 1e6, tz=timezone.utc)
        return (datetime.now(timezone.utc) - last_seen).total_seconds()

    def check_agent_fresh(
        self, client_id: str, max_age_sec: float = AGENT_FRESHNESS_MAX_AGE_SEC
    ) -> None:
        """Raise AgentStaleError if the client's last_seen_at is too old."""
        age = self.agent_age_seconds(client_id)
        if age > max_age_sec:
            raise AgentStaleError(
                f"agent {client_id} last checked in {age:.0f}s ago "
                f"(budget {max_age_sec:.0f}s) — agent likely offline; acquire aborted"
            )

    def collect_artifact(
        self,
        client_id: str,
        artifact_name: str,
        parameters: dict | None = None,
    ) -> list[dict[str, Any]]:
        """Dispatch one artifact to the agent, poll until done, return result rows.

        Note: we deliberately do NOT pass `wait=TRUE` to `collect_client`. In
        Velociraptor 0.76.x, that flag causes the function to return null
        instead of the expected flow context. Instead we schedule the flow,
        capture the `flow_id` from the immediate return value, and poll
        `flows()` until state is FINISHED.
        """
        params_clause = ""
        if parameters:
            kv = ", ".join(f"'{k}', '''{v}'''" for k, v in parameters.items())
            params_clause = f", env=dict({kv})"

        collect_vql = (
            f"SELECT collect_client("
            f"client_id='{client_id}', "
            f"artifacts=['{artifact_name}']"
            f"{params_clause}"
            f") AS flow FROM scope()"
        )
        collect_rows = self._run_vql(collect_vql, name="collect")
        if not collect_rows:
            raise RuntimeError(f"collect_client returned no rows for {artifact_name}")

        flow = collect_rows[0].get("flow")
        if not isinstance(flow, dict):
            raise RuntimeError(
                f"collect_client returned unexpected shape for {artifact_name}: "
                f"{collect_rows[0]!r}"
            )
        flow_id = flow.get("flow_id") or flow.get("FlowId")
        if not flow_id:
            raise RuntimeError(f"no flow_id in collect_client response: {flow}")

        self._wait_for_flow(client_id=client_id, flow_id=flow_id)

        source_vql = (
            f"SELECT * FROM source("
            f"client_id='{client_id}', "
            f"flow_id='{flow_id}', "
            f"artifact='{artifact_name}'"
            f")"
        )
        return self._run_vql(source_vql, name=f"source_{artifact_name}")

    def _wait_for_flow(self, client_id: str, flow_id: str) -> None:
        deadline = time.monotonic() + FLOW_TIMEOUT_SEC
        while time.monotonic() < deadline:
            rows = self._run_vql(
                f"SELECT state, status FROM flows("
                f"client_id='{client_id}', flow_id='{flow_id}')",
                name="flow_state",
            )
            if rows:
                state = rows[0].get("state", "")
                if state in ("FINISHED", "ERROR"):
                    if state == "ERROR":
                        raise RuntimeError(
                            f"flow {flow_id} errored: {rows[0].get('status')}"
                        )
                    return
            time.sleep(FLOW_POLL_INTERVAL_SEC)
        raise TimeoutError(f"flow {flow_id} did not finish within {FLOW_TIMEOUT_SEC}s")


def _from_env() -> VelociraptorClient:
    load_dotenv(DEFAULT_ENV_PATH)
    api_config = os.environ.get("VELO_API_CONFIG")
    if not api_config:
        raise RuntimeError("VELO_API_CONFIG not set in config/.env")
    return VelociraptorClient(Path(api_config))


def _ping() -> int:
    with _from_env() as client:
        clients = client.list_clients()
    if not clients:
        print("no clients connected", file=sys.stderr)
        return 1
    expected = os.environ.get("SCOPE1_CLIENT_ID")
    found = False
    for c in clients:
        marker = " <-- SCOPE1" if expected and c.get("client_id") == expected else ""
        print(f"{c.get('client_id')}\t{c.get('hostname')}{marker}")
        if expected and c.get("client_id") == expected:
            found = True
    if expected and not found:
        print(f"SCOPE1_CLIENT_ID {expected} not in connected clients", file=sys.stderr)
        return 2
    return 0


def _check_agent() -> int:
    with _from_env() as client:
        client_id = os.environ.get("SCOPE1_CLIENT_ID")
        if not client_id:
            print("SCOPE1_CLIENT_ID not set in config/.env", file=sys.stderr)
            return 2
        try:
            age = client.agent_age_seconds(client_id)
        except AgentStaleError as exc:
            print(f"STALE  {exc}", file=sys.stderr)
            return 3
    if age > AGENT_FRESHNESS_MAX_AGE_SEC:
        print(f"STALE  agent {client_id} last seen {age:.0f}s ago", file=sys.stderr)
        return 3
    print(f"OK     agent {client_id} last seen {age:.0f}s ago")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ping", action="store_true", help="list connected clients")
    parser.add_argument(
        "--check-agent",
        action="store_true",
        help="exit 0 if SCOPE1 agent is fresh, 3 if stale",
    )
    args = parser.parse_args()
    if args.ping:
        return _ping()
    if args.check_agent:
        return _check_agent()
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
