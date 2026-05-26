"""One module per feature group.

Each module exposes a `compute(events, context) -> dict[str, Any]` function
that consumes the events stream and returns a flat dict mapping feature
name → value. The driver merges all dicts into the final feature vector and
validates against `schemas/feature_vector_v1.json`.

Module dependencies are flat — no module imports another. The driver
sequences calls when one feature depends on another (e.g. persistence.* is
derived from cron/service/startup counts produced by the persistence module
itself in one pass; `connections_to_threat_intel_ip` is in the ioc module
which receives the network IPs as part of its `context`).
"""
