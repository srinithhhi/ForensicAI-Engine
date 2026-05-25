"""OCSF mapping layer.

Transforms raw Velociraptor bundles produced by the acquisition layer into
canonical OCSF v1.3.0 events that downstream layers (feature extractor, AI
triage model) consume scope-agnostically.

Public surface:
- `parsing.run_mappers`: CLI driver that walks a bundle's manifest and writes
  `data/processed/{incident_id}/events.ndjson`.
- `parsing.ocsf_base`: shared utilities every mapper uses (event factory,
  timestamp parsing, hash normalisation, schema validation).
"""
