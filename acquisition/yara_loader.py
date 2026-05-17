"""YARA rule loader for the Scope 1 acquirer.

Reads a curated subset of YARA rule files from disk and concatenates them
into a single string suitable for the `YaraRule` parameter of the
`Linux.Detection.Yara.Process` Velociraptor artifact.

v0 curation: webshells, crypto, capabilities, antidebug_antivm. These are the
highest signal-to-byte categories for an Ubuntu server. The corpus at
`/Users/srinithi/yara-rules` (the YARA-Rules/rules repo) is ~6 MB total — far
too large to ship inline through gRPC's default 4 MB message limit. The
curated subset lands at ~450 KB, well under the ceiling.

Non-index files in this corpus are self-contained (no `include` directives),
so simple concatenation produces valid YARA source. If that changes in a
future rule update, this loader will need an include-resolver.
"""

from __future__ import annotations

import os
from pathlib import Path

# v0 subdirectories to include. Order matters only for provenance comments —
# all rules are merged into one compilation unit.
DEFAULT_INCLUDED_SUBDIRS = (
    "webshells",
    "crypto",
    "capabilities",
    "antidebug_antivm",
)

# Defensive cap — if the curation expands and someone accidentally pulls in
# malware/ or packers/, we want a loud failure, not a silent gRPC RESOURCE_EXHAUSTED.
MAX_TOTAL_BYTES = 3 * 1024 * 1024  # 3 MB — leaves headroom under gRPC's 4 MB default


class YaraLoadError(RuntimeError):
    pass


def load_yara_rules(
    rules_dir: Path | str | None = None,
    included_subdirs: tuple[str, ...] = DEFAULT_INCLUDED_SUBDIRS,
) -> str:
    """Concatenate every .yar/.yara file in the chosen subdirs into one string.

    Each file is prefixed with a `// from <relative_path>` comment so matches
    can be traced back to the source rule file in post-analysis.

    Falls back to `os.environ['YARA_RULES']` when `rules_dir` is None.
    """
    if rules_dir is None:
        env_val = os.environ.get("YARA_RULES")
        if not env_val:
            raise YaraLoadError(
                "rules_dir not given and YARA_RULES not set in environment"
            )
        rules_dir = env_val
    root = Path(rules_dir)
    if not root.is_dir():
        raise YaraLoadError(f"rules directory does not exist: {root}")

    chunks: list[str] = []
    total_bytes = 0
    file_count = 0
    for sub in included_subdirs:
        sub_path = root / sub
        if not sub_path.is_dir():
            continue
        for path in sorted(sub_path.rglob("*.yar")) + sorted(sub_path.rglob("*.yara")):
            text = path.read_text(encoding="utf-8", errors="replace")
            rel = path.relative_to(root)
            chunks.append(f"// from {rel}\n{text}\n")
            total_bytes += len(text)
            file_count += 1
            if total_bytes > MAX_TOTAL_BYTES:
                raise YaraLoadError(
                    f"rule corpus exceeded {MAX_TOTAL_BYTES} bytes at {rel}; "
                    f"narrow the curation or bump gRPC max_send_message_size"
                )

    if file_count == 0:
        raise YaraLoadError(
            f"no .yar/.yara files found under {root} in subdirs {included_subdirs}"
        )

    return "\n".join(chunks)
