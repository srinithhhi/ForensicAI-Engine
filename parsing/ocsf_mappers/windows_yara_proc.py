"""Windows.Detection.Yara.Process → OCSF Detection Finding (class_uid 2004).

Identical row shape to the Linux yara_proc artifact — reuses the shared
helper. Scope/provenance lives in MapperContext so the output events are
distinguishable downstream.
"""

from __future__ import annotations

from typing import Iterable, Iterator

from parsing.ocsf_base import MapperContext
from parsing.ocsf_mappers._yara_shared import yara_hit_to_detection


def map_rows(rows: Iterable[dict], context: MapperContext) -> Iterator[dict]:
    yield from yara_hit_to_detection(rows, context, target_kind="process")
