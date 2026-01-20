from __future__ import annotations

import importlib
import importlib.resources
import json
import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Protocol, Union

from belgi.core.hash import is_hex_sha256, sha256_bytes
from belgi.core.jail import normalize_repo_rel_path
from belgi.core.json_canon import canonical_json_bytes


MANIFEST_FILENAME = "ProtocolPackManifest.json"

# Pack content prefixes: only files under these directories are included in pack_id.
# This ensures scaffolding files (*.py, __pycache__, __init__.py) do not affect pack_id.
_PACK_CONTENT_PREFIXES = ("schemas/", "gates/", "tiers/")

# Files/directories explicitly excluded from pack scanning (scaffolding, OS junk).
_PACK_EXCLUDED_NAMES = frozenset({
    "__init__.py",
    "__pycache__",
    ".DS_Store",
    ".gitkeep",
    "Thumbs.db",
    "desktop.ini",
})

# File extensions explicitly excluded from pack scanning.
_PACK_EXCLUDED_EXTENSIONS = frozenset({".py", ".pyc", ".pyo"})


class DevOverrideNotAllowedError(RuntimeError):
    """Raised when dev-override is used without BELGI_DEV=1 or in CI."""
    pass


def _assert_no_symlinks_anywhere(pack_root: Path) -> None:
    """Pre-pass: reject ANY symlink under pack_root, even inside excluded dirs.

    This must run BEFORE pruning so that symlinks nested inside __pycache__ etc.
    are still detected.
    """
    for root, dirnames, filenames in os.walk(pack_root, topdown=True, followlinks=False):
        root_path = Path(root)
        dirnames.sort()
        filenames.sort()

        for d in dirnames:
            p = root_path / d
            if p.is_symlink():
                raise ValueError(f"symlink directory not allowed in protocol pack: {p}")

        for f in filenames:
            p = root_path / f
            if p.is_symlink():
                raise ValueError(f"symlink file not allowed in protocol pack: {p}")


def _check_dev_override_allowed() -> None:
    """Fail-closed guard for dev-override protocol pack loading.

    Dev-override is forbidden in CI (CI env var set) and requires BELGI_DEV=1.
    This centralizes the check so any future caller cannot forget it.
    """
    if os.environ.get("CI"):
        raise DevOverrideNotAllowedError("dev-override protocol pack is not allowed in CI")
    if os.environ.get("BELGI_DEV") != "1":
        raise DevOverrideNotAllowedError("dev-override protocol pack requires BELGI_DEV=1")


def _is_pack_content_file(relpath: str) -> bool:
    """Check if relpath is protocol content (not scaffolding).

    Pack content must:
    - Start with one of _PACK_CONTENT_PREFIXES
    - Not have excluded names or extensions
    - Not be the manifest itself
    """
    if relpath == MANIFEST_FILENAME:
        return False

    # Check prefix allowlist
    if not any(relpath.startswith(prefix) for prefix in _PACK_CONTENT_PREFIXES):
        return False

    # Check excluded names (basename)
    parts = relpath.split("/")
    basename = parts[-1] if parts else ""
    if basename in _PACK_EXCLUDED_NAMES:
        return False

    # Check if any path component is excluded
    for part in parts[:-1]:  # directories
        if part in _PACK_EXCLUDED_NAMES:
            return False

    # Check excluded extensions
    for ext in _PACK_EXCLUDED_EXTENSIONS:
        if basename.endswith(ext):
            return False

    return True


class _Traversable(Protocol):
    # Minimal subset of importlib.resources.abc.Traversable we need.
    name: str

    def iterdir(self) -> Iterable["_Traversable"]: ...

    def is_dir(self) -> bool: ...

    def read_bytes(self) -> bytes: ...

    def joinpath(self, *descendants: str) -> "_Traversable": ...


@dataclass(frozen=True)
class ProtocolPackFileEntry:
    relpath: str  # POSIX relpath
    sha256: str
    size_bytes: int


def scan_pack_dir(pack_root: Path) -> list[ProtocolPackFileEntry]:
    """Scan pack_root and return deterministic file entries.

    Excludes MANIFEST_FILENAME and scaffolding files from the returned entries.
    Only files matching _PACK_CONTENT_PREFIXES are included (pack_id excludes scaffolding).

    Fail-closed:
      - pack_root must exist and be a directory
      - pack_root must not be a symlink
      - any symlink anywhere under pack_root is rejected (even inside excluded dirs)
    """

    if not isinstance(pack_root, Path):
        raise TypeError("pack_root must be a pathlib.Path")
    if not pack_root.exists():
        raise ValueError(f"pack_root does not exist: {pack_root}")
    if not pack_root.is_dir():
        raise ValueError(f"pack_root is not a directory: {pack_root}")
    if pack_root.is_symlink():
        raise ValueError(f"symlink directory not allowed in protocol pack: {pack_root}")

    # Pre-pass: reject symlinks anywhere (including inside excluded dirs like __pycache__).
    _assert_no_symlinks_anywhere(pack_root)

    entries: list[ProtocolPackFileEntry] = []

    for root, dirnames, filenames in os.walk(pack_root):
        root_path = Path(root)

        # Deterministic traversal
        dirnames.sort()
        filenames.sort()

        # Prune excluded directories from traversal.
        dirnames[:] = [d for d in dirnames if d not in _PACK_EXCLUDED_NAMES]

        for name in filenames:
            file_path = root_path / name
            relpath = file_path.relative_to(pack_root).as_posix()
            relpath = normalize_repo_rel_path(relpath)

            # Filter: only protocol content files
            if not _is_pack_content_file(relpath):
                continue

            data = file_path.read_bytes()
            entries.append(
                ProtocolPackFileEntry(
                    relpath=relpath,
                    sha256=sha256_bytes(data),
                    size_bytes=len(data),
                )
            )

    entries.sort(key=lambda e: e.relpath)
    return entries


def scan_pack_tree(pack_root: _Traversable) -> list[ProtocolPackFileEntry]:
    """Scan a Traversable protocol pack (importlib.resources) deterministically.

    This supports installed-package mode where pack files may not exist as a
    normal filesystem directory (e.g., zipimport).

    Excludes MANIFEST_FILENAME and scaffolding files. Only files matching
    _PACK_CONTENT_PREFIXES are included (pack_id excludes scaffolding).

    Fail-closed:
      - rejects any non-file/non-dir nodes (by treating them as files and requiring read_bytes)
    """

    entries: list[ProtocolPackFileEntry] = []

    def walk(node: _Traversable, prefix: str) -> None:
        children = list(node.iterdir())
        children.sort(key=lambda c: c.name)
        for child in children:
            # Skip excluded names early (directories and files)
            if child.name in _PACK_EXCLUDED_NAMES:
                continue

            rel = f"{prefix}{child.name}" if not prefix else f"{prefix}{child.name}"
            if child.is_dir():
                walk(child, rel + "/")
                continue

            relpath = normalize_repo_rel_path(rel)

            # Filter: only protocol content files
            if not _is_pack_content_file(relpath):
                continue

            data = child.read_bytes()
            entries.append(
                ProtocolPackFileEntry(
                    relpath=relpath,
                    sha256=sha256_bytes(data),
                    size_bytes=len(data),
                )
            )

    walk(pack_root, "")
    entries.sort(key=lambda e: e.relpath)
    return entries


def compute_pack_id(entries: Iterable[ProtocolPackFileEntry]) -> str:
    """Compute pack_id per INFRA: sha256 over concatenated (relpath, sha256, size_bytes).

    Fail-closed if entries are not already in stable relpath order.
    All entries must pass _is_pack_content_file (no scaffolding, no manifest).
    """

    entries_list = list(entries)
    relpaths = [e.relpath for e in entries_list]
    if relpaths != sorted(relpaths):
        raise ValueError("entries must be sorted by relpath")

    h_parts: list[bytes] = []
    for entry in entries_list:
        relpath = normalize_repo_rel_path(entry.relpath)
        if not _is_pack_content_file(relpath):
            raise ValueError(f"entry is not protocol content (scaffolding/manifest excluded): {relpath}")
        if not is_hex_sha256(entry.sha256):
            raise ValueError(f"entry.sha256 must be 64-hex chars: {entry.sha256!r}")
        if not isinstance(entry.size_bytes, int) or isinstance(entry.size_bytes, bool) or entry.size_bytes < 0:
            raise ValueError("entry.size_bytes must be a non-negative int")

        h_parts.append((relpath + "\n").encode("utf-8", errors="strict"))
        h_parts.append((entry.sha256 + "\n").encode("utf-8", errors="strict"))
        h_parts.append((str(entry.size_bytes) + "\n").encode("utf-8", errors="strict"))

    return sha256_bytes(b"".join(h_parts))


def build_manifest_obj(
    *,
    pack_root: Path,
    pack_name: str,
    pack_format_version: int = 1,
    pack_semver: str | None = None,
) -> dict[str, Any]:
    if not isinstance(pack_name, str) or not pack_name:
        raise ValueError("pack_name missing/empty")
    if not isinstance(pack_format_version, int) or isinstance(pack_format_version, bool):
        raise ValueError("pack_format_version must be int")

    entries = scan_pack_dir(pack_root)

    files = [
        {
            "relpath": e.relpath,
            "sha256": e.sha256,
            "size_bytes": e.size_bytes,
        }
        for e in entries
    ]

    manifest: dict[str, Any] = {
        "pack_format_version": pack_format_version,
        "pack_name": pack_name,
        "files": files,
        "pack_id": compute_pack_id(entries),
    }

    if pack_semver is not None:
        if not isinstance(pack_semver, str) or not pack_semver:
            raise ValueError("pack_semver must be a non-empty string when provided")
        manifest["pack_semver"] = pack_semver

    return manifest


def build_manifest_bytes(
    *,
    pack_root: Path,
    pack_name: str,
    pack_format_version: int = 1,
    pack_semver: str | None = None,
) -> bytes:
    return canonical_json_bytes(
        build_manifest_obj(
            pack_root=pack_root,
            pack_name=pack_name,
            pack_format_version=pack_format_version,
            pack_semver=pack_semver,
        )
    )


def compute_manifest_sha256(manifest_bytes: bytes) -> str:
    return sha256_bytes(bytes(manifest_bytes))


def _require_type(value: Any, expected: type, label: str) -> Any:
    if not isinstance(value, expected):
        raise ValueError(f"{label} must be {expected.__name__}")
    return value


def validate_manifest_bytes(*, pack_root: Path, manifest_bytes: bytes) -> None:
    """Validate manifest bytes against the pack directory.

    Fail-closed:
      - manifest must be valid UTF-8 JSON
      - manifest bytes must be canonical (stable JSON encoding)
      - file list must exactly match scanned pack files (excluding manifest)
      - pack_id must match recomputation from pack bytes
    """

    if not isinstance(manifest_bytes, (bytes, bytearray)):
        raise TypeError("manifest_bytes must be bytes")

    try:
        parsed = json.loads(bytes(manifest_bytes).decode("utf-8", errors="strict"))
    except Exception as e:
        raise ValueError(f"manifest is not valid UTF-8 JSON: {e}")

    _require_type(parsed, dict, "manifest")

    pack_format_version = parsed.get("pack_format_version")
    if not isinstance(pack_format_version, int) or isinstance(pack_format_version, bool):
        raise ValueError("manifest.pack_format_version must be int")

    pack_name = parsed.get("pack_name")
    if not isinstance(pack_name, str) or not pack_name:
        raise ValueError("manifest.pack_name missing/empty")

    declared_pack_id = parsed.get("pack_id")
    if not is_hex_sha256(declared_pack_id):
        raise ValueError("manifest.pack_id must be 64-hex chars")

    files = parsed.get("files")
    _require_type(files, list, "manifest.files")

    seen: set[str] = set()
    relpaths_in_order: list[str] = []
    for i, entry in enumerate(files):
        _require_type(entry, dict, f"manifest.files[{i}]")

        relpath_raw = entry.get("relpath")
        if not isinstance(relpath_raw, str) or not relpath_raw:
            raise ValueError(f"manifest.files[{i}].relpath missing/empty")

        relpath = normalize_repo_rel_path(relpath_raw)
        if relpath == MANIFEST_FILENAME:
            raise ValueError("manifest.files must not include ProtocolPackManifest.json")

        if relpath in seen:
            raise ValueError(f"manifest.files contains duplicate relpath: {relpath}")
        seen.add(relpath)
        relpaths_in_order.append(relpath)

        sha = entry.get("sha256")
        if not is_hex_sha256(sha):
            raise ValueError(f"manifest.files[{i}].sha256 must be 64-hex chars")

        size_bytes = entry.get("size_bytes")
        if not isinstance(size_bytes, int) or isinstance(size_bytes, bool) or size_bytes < 0:
            raise ValueError(f"manifest.files[{i}].size_bytes must be a non-negative int")

    if relpaths_in_order != sorted(relpaths_in_order):
        raise ValueError("manifest.files must be sorted by relpath")

    scanned_entries = scan_pack_dir(pack_root)
    expected_files = [
        {"relpath": e.relpath, "sha256": e.sha256, "size_bytes": e.size_bytes}
        for e in scanned_entries
    ]

    if files != expected_files:
        raise ValueError("manifest.files do not match scanned pack contents")

    computed_pack_id = compute_pack_id(scanned_entries)
    if declared_pack_id != computed_pack_id:
        raise ValueError("manifest.pack_id mismatch (declared != computed)")

    canonical = canonical_json_bytes(parsed)
    if bytes(manifest_bytes) != canonical:
        raise ValueError("manifest JSON is not canonical")


def validate_manifest_bytes_tree(*, pack_root: _Traversable, manifest_bytes: bytes) -> None:
    """Validate manifest bytes against a Traversable pack tree.

    Same contract as validate_manifest_bytes(), but uses scan_pack_tree() to
    avoid filesystem assumptions.
    """

    if not isinstance(manifest_bytes, (bytes, bytearray)):
        raise TypeError("manifest_bytes must be bytes")

    try:
        parsed = json.loads(bytes(manifest_bytes).decode("utf-8", errors="strict"))
    except Exception as e:
        raise ValueError(f"manifest is not valid UTF-8 JSON: {e}")

    _require_type(parsed, dict, "manifest")

    pack_format_version = parsed.get("pack_format_version")
    if not isinstance(pack_format_version, int) or isinstance(pack_format_version, bool):
        raise ValueError("manifest.pack_format_version must be int")

    pack_name = parsed.get("pack_name")
    if not isinstance(pack_name, str) or not pack_name:
        raise ValueError("manifest.pack_name missing/empty")

    declared_pack_id = parsed.get("pack_id")
    if not is_hex_sha256(declared_pack_id):
        raise ValueError("manifest.pack_id must be 64-hex chars")

    files = parsed.get("files")
    _require_type(files, list, "manifest.files")

    seen: set[str] = set()
    relpaths_in_order: list[str] = []
    for i, entry in enumerate(files):
        _require_type(entry, dict, f"manifest.files[{i}]")

        relpath_raw = entry.get("relpath")
        if not isinstance(relpath_raw, str) or not relpath_raw:
            raise ValueError(f"manifest.files[{i}].relpath missing/empty")

        relpath = normalize_repo_rel_path(relpath_raw)
        if relpath == MANIFEST_FILENAME:
            raise ValueError("manifest.files must not include ProtocolPackManifest.json")

        if relpath in seen:
            raise ValueError(f"manifest.files contains duplicate relpath: {relpath}")
        seen.add(relpath)
        relpaths_in_order.append(relpath)

        sha = entry.get("sha256")
        if not is_hex_sha256(sha):
            raise ValueError(f"manifest.files[{i}].sha256 must be 64-hex chars")

        size_bytes = entry.get("size_bytes")
        if not isinstance(size_bytes, int) or isinstance(size_bytes, bool) or size_bytes < 0:
            raise ValueError(f"manifest.files[{i}].size_bytes must be a non-negative int")

    if relpaths_in_order != sorted(relpaths_in_order):
        raise ValueError("manifest.files must be sorted by relpath")

    scanned_entries = scan_pack_tree(pack_root)
    expected_files = [
        {"relpath": e.relpath, "sha256": e.sha256, "size_bytes": e.size_bytes}
        for e in scanned_entries
    ]

    if files != expected_files:
        raise ValueError("manifest.files do not match scanned pack contents")

    computed_pack_id = compute_pack_id(scanned_entries)
    if declared_pack_id != computed_pack_id:
        raise ValueError("manifest.pack_id mismatch (declared != computed)")

    canonical = canonical_json_bytes(parsed)
    if bytes(manifest_bytes) != canonical:
        raise ValueError("manifest JSON is not canonical")


ProtocolPackRoot = Union[Path, _Traversable]


@dataclass(frozen=True)
class ProtocolContext:
    pack_id: str
    pack_name: str
    source: str  # "builtin" | "repo" | "override"
    manifest_sha256: str
    manifest: dict[str, Any]
    root: ProtocolPackRoot

    def read_bytes(self, relpath: str) -> bytes:
        rel = normalize_repo_rel_path(relpath)
        if isinstance(self.root, Path):
            p = (self.root / rel)
            if not p.exists() or not p.is_file():
                raise ValueError(f"protocol pack missing file: {rel}")
            if p.is_symlink():
                raise ValueError(f"symlink file not allowed in protocol pack: {rel}")
            return p.read_bytes()

        # Python 3.10/3.11 MultiplexedPath.joinpath() only accepts single arg;
        # iterate to support multi-segment paths portably.
        # Fail-closed: reject empty, ".", ".." segments.
        parts = PurePosixPath(rel).parts
        for part in parts:
            if part in ("", ".", ".."):
                raise ValueError(f"invalid path segment in protocol pack relpath: {rel!r}")
        node = self.root
        for part in parts:
            node = node.joinpath(part)
        try:
            return node.read_bytes()
        except Exception as e:
            raise ValueError(f"protocol pack missing/unreadable file: {rel} ({e})")

    def read_text(self, relpath: str) -> str:
        return self.read_bytes(relpath).decode("utf-8", errors="strict")

    def read_json(self, relpath: str) -> Any:
        return json.loads(self.read_text(relpath))


def load_protocol_context_from_dir(*, pack_root: Path, source: str) -> ProtocolContext:
    """Load protocol context from a directory pack.

    source must be one of: "builtin", "override", "dev-override"

    If source is "dev-override", enforces BELGI_DEV=1 and forbids CI environment.
    This centralized check ensures any caller cannot bypass the dev-override guard.
    """
    # Centralized dev-override guard: fail-closed if conditions not met.
    if source == "dev-override":
        _check_dev_override_allowed()

    manifest_bytes = (pack_root / MANIFEST_FILENAME).read_bytes()
    validate_manifest_bytes(pack_root=pack_root, manifest_bytes=manifest_bytes)
    manifest = json.loads(manifest_bytes.decode("utf-8", errors="strict"))
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be a JSON object")
    pack_id = manifest.get("pack_id")
    pack_name = manifest.get("pack_name")
    if not is_hex_sha256(pack_id):
        raise ValueError("manifest.pack_id must be 64-hex chars")
    if not isinstance(pack_name, str) or not pack_name:
        raise ValueError("manifest.pack_name missing/empty")
    return ProtocolContext(
        pack_id=pack_id,
        pack_name=pack_name,
        source=source,
        manifest_sha256=compute_manifest_sha256(manifest_bytes),
        manifest=manifest,
        root=pack_root,
    )


def load_protocol_context_from_tree(*, pack_root: _Traversable, source: str) -> ProtocolContext:
    manifest_node = pack_root.joinpath(MANIFEST_FILENAME)
    manifest_bytes = manifest_node.read_bytes()
    validate_manifest_bytes_tree(pack_root=pack_root, manifest_bytes=manifest_bytes)
    manifest = json.loads(manifest_bytes.decode("utf-8", errors="strict"))
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be a JSON object")
    pack_id = manifest.get("pack_id")
    pack_name = manifest.get("pack_name")
    if not is_hex_sha256(pack_id):
        raise ValueError("manifest.pack_id must be 64-hex chars")
    if not isinstance(pack_name, str) or not pack_name:
        raise ValueError("manifest.pack_name missing/empty")
    return ProtocolContext(
        pack_id=pack_id,
        pack_name=pack_name,
        source=source,
        manifest_sha256=compute_manifest_sha256(manifest_bytes),
        manifest=manifest,
        root=pack_root,
    )


def get_builtin_protocol_context() -> ProtocolContext:
    """Return the builtin protocol pack context shipped with the belgi package."""

    mod = importlib.import_module("belgi._protocol_packs.v1")
    tree = importlib.resources.files(mod)
    return load_protocol_context_from_tree(pack_root=tree, source="builtin")
