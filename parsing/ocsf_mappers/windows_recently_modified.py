"""Windows.Search.FileFinder → OCSF File System Activity (class_uid 1001).

The Windows FileFinder artifact emits the same row shape as the Linux one,
so we reuse the Linux mapper. The MapperContext carries scope + source_step
provenance into the unmapped block, so Phase 4 can still tell Windows file
events apart from Linux ones if needed.
"""

from __future__ import annotations

from parsing.ocsf_mappers.linux_recently_modified import map_rows  # noqa: F401
