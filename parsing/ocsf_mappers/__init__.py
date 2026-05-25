"""One mapper module per artifact.

Each module exposes a single `map_rows(rows, context) -> Iterable[dict]` function
that consumes the artifact's native row shape and yields OCSF events.

Mappers are registered in `parsing.run_mappers.MAPPER_REGISTRY` keyed by
Velociraptor artifact name (e.g. `Linux.Forensics.Journal`).
"""
