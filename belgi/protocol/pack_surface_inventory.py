from __future__ import annotations

MANIFEST_FILENAME = "ProtocolPackManifest.json"

PACK_SOURCE_BINDINGS: tuple[tuple[str, str], ...] = (
    ("schemas", "schemas"),
    ("gates", "gates"),
    ("tiers", "tiers"),
)

_PACK_ALLOWED_FOLDER_ORDER: tuple[str, ...] = tuple(dst_rel for _src_rel, dst_rel in PACK_SOURCE_BINDINGS)

PACK_CONTENT_PREFIXES: tuple[str, ...] = tuple(f"{folder}/" for folder in _PACK_ALLOWED_FOLDER_ORDER)
PACK_ALLOWED_FOLDERS = frozenset(_PACK_ALLOWED_FOLDER_ORDER)
PACK_ALLOWED_FILES = frozenset({MANIFEST_FILENAME})

C3_CANONICAL_MIRROR_BINDINGS: tuple[tuple[str, str], ...] = (
    ("CANONICALS.md", "belgi/canonicals/CANONICALS.md"),
    ("terminology.md", "belgi/canonicals/terminology.md"),
    ("trust-model.md", "belgi/canonicals/trust-model.md"),
    ("docs/operations/consistency-sweep.md", "belgi/canonicals/docs/operations/consistency-sweep.md"),
    ("docs/operations/cli.md", "belgi/canonicals/docs/operations/cli.md"),
    ("docs/operations/evidence-bundles.md", "belgi/canonicals/docs/operations/evidence-bundles.md"),
    ("docs/operations/evidence-ownership.md", "belgi/canonicals/docs/operations/evidence-ownership.md"),
    ("docs/operations/operator-anchors.md", "belgi/canonicals/docs/operations/operator-anchors.md"),
    ("docs/operations/running-belgi.md", "belgi/canonicals/docs/operations/running-belgi.md"),
    ("docs/operations/security.md", "belgi/canonicals/docs/operations/security.md"),
    ("docs/operations/waivers.md", "belgi/canonicals/docs/operations/waivers.md"),
    ("docs/research/README.md", "belgi/canonicals/docs/research/README.md"),
    ("docs/research/experiment-design.md", "belgi/canonicals/docs/research/experiment-design.md"),
    ("docs/research/metrics.md", "belgi/canonicals/docs/research/metrics.md"),
)

__all__ = [
    "MANIFEST_FILENAME",
    "PACK_SOURCE_BINDINGS",
    "PACK_CONTENT_PREFIXES",
    "PACK_ALLOWED_FOLDERS",
    "PACK_ALLOWED_FILES",
    "C3_CANONICAL_MIRROR_BINDINGS",
    "iter_pack_source_bindings",
    "iter_pack_content_prefixes",
    "iter_pack_allowed_folders",
    "iter_pack_allowed_files",
    "iter_c3_canonical_mirror_bindings",
]


def iter_pack_source_bindings() -> tuple[tuple[str, str], ...]:
    return PACK_SOURCE_BINDINGS


def iter_pack_content_prefixes() -> tuple[str, ...]:
    return PACK_CONTENT_PREFIXES


def iter_pack_allowed_folders() -> tuple[str, ...]:
    return _PACK_ALLOWED_FOLDER_ORDER


def iter_pack_allowed_files() -> tuple[str, ...]:
    return tuple(sorted(PACK_ALLOWED_FILES))


def iter_c3_canonical_mirror_bindings() -> tuple[tuple[str, str], ...]:
    return C3_CANONICAL_MIRROR_BINDINGS
