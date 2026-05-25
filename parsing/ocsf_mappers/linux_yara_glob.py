"""Linux.Detection.Yara.Glob → OCSF Detection Finding (class_uid 2004)."""

from __future__ import annotations

from typing import Iterable, Iterator

from parsing.ocsf_base import MapperContext
from parsing.ocsf_mappers._yara_shared import yara_hit_to_detection


def map_rows(rows: Iterable[dict], context: MapperContext) -> Iterator[dict]:
    yield from yara_hit_to_detection(rows, context, target_kind="file")
