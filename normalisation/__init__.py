"""Feature extraction + IOC enrichment layer (Phase 4).

Reads `data/processed/{incident_id}/events.ndjson` (Phase 3 output) plus
the matching `data/simulations/{incident_id}/simulation_manifest.json` and
writes `data/labeled/{incident_id}.json` — a single ~40-feature vector per
incident, validating against `schemas/feature_vector_v1.json`.

This layer is the only one that talks to MISP. Phase 3 stays a pure local
file-to-file transform.
"""
