from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

# Allow running as a script (python -m tools.build_builtin_pack) without shadowing the
# belgi/ package via tools/belgi_tools.py.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
for _k in list(sys.modules.keys()):
    if _k == "belgi" or _k.startswith("belgi."):
        del sys.modules[_k]

from belgi.protocol.pack import MANIFEST_FILENAME, build_manifest_bytes, validate_manifest_bytes


# Protocol pack v1 allowed content (whitelist).
# Pack MUST contain ONLY these folders + the manifest file.
PACK_ALLOWED_FOLDERS = frozenset({"schemas", "gates", "tiers"})
PACK_ALLOWED_FILES = frozenset({MANIFEST_FILENAME})


def _repo_root_from_this_file() -> Path:
    # tools/build_builtin_pack.py -> <repo_root>/tools/build_builtin_pack.py
    return Path(__file__).resolve().parents[1]


def _assert_under_repo_root(repo_root: Path, p: Path) -> None:
    rr = repo_root.resolve()
    pr = p.resolve()
    if rr != pr and rr not in pr.parents:
        raise ValueError(f"scope escape (refusing to write outside repo root): {p}")


def _copy_tree_bytes(*, src_root: Path, dst_root: Path) -> None:
    if not src_root.exists() or not src_root.is_dir():
        raise ValueError(f"missing source directory: {src_root}")
    if src_root.is_symlink():
        raise ValueError(f"symlink source directory not allowed: {src_root}")

    for root, dirnames, filenames in os.walk(src_root):
        root_path = Path(root)
        if root_path.is_symlink():
            raise ValueError(f"symlink directory not allowed: {root_path}")

        # Deterministic traversal
        dirnames.sort()
        filenames.sort()

        for d in dirnames:
            if (root_path / d).is_symlink():
                raise ValueError(f"symlink directory not allowed: {root_path / d}")

        for name in filenames:
            src_path = root_path / name
            if src_path.is_symlink():
                raise ValueError(f"symlink file not allowed: {src_path}")

            rel = src_path.relative_to(src_root).as_posix()
            dst_path = dst_root / rel
            dst_path.parent.mkdir(parents=True, exist_ok=True)
            dst_path.write_bytes(src_path.read_bytes())


def build_builtin_pack(*, repo_root: Path, pack_root: Path, pack_name: str) -> None:
    _assert_under_repo_root(repo_root, pack_root)

    if pack_root.exists():
        if pack_root.is_symlink():
            raise ValueError(f"refusing to delete symlink path: {pack_root}")
        shutil.rmtree(pack_root)

    pack_root.mkdir(parents=True, exist_ok=True)

    # Source-of-truth protocol folders (during development): repo root.
    _copy_tree_bytes(src_root=repo_root / "schemas", dst_root=pack_root / "schemas")
    _copy_tree_bytes(src_root=repo_root / "gates", dst_root=pack_root / "gates")
    _copy_tree_bytes(src_root=repo_root / "tiers", dst_root=pack_root / "tiers")

    manifest_bytes = build_manifest_bytes(pack_root=pack_root, pack_name=pack_name)
    (pack_root / MANIFEST_FILENAME).write_bytes(manifest_bytes)

    # Fail-closed: validate the on-disk pack immediately.
    validate_manifest_bytes(pack_root=pack_root, manifest_bytes=manifest_bytes)

    # Fail-closed: verify pack shape (no unexpected content).
    _assert_pack_shape(pack_root)


def _assert_pack_shape(pack_root: Path) -> None:
    """Fail if pack contains unexpected top-level entries."""
    for item in pack_root.iterdir():
        name = item.name
        if item.is_dir():
            if name not in PACK_ALLOWED_FOLDERS:
                raise ValueError(f"unexpected directory in pack: {name}")
        elif item.is_file():
            if name not in PACK_ALLOWED_FILES:
                raise ValueError(f"unexpected file in pack: {name}")
        else:
            raise ValueError(f"unexpected item type in pack: {name}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build builtin protocol pack under belgi/_protocol_packs/v1")
    ap.add_argument("--pack-name", default="belgi-protocol-pack-v1", help="Protocol pack name for manifest")
    ap.add_argument(
        "--out",
        default=None,
        help="Override output pack root (default: belgi/_protocol_packs/v1 under repo root)",
    )

    ns = ap.parse_args(argv)

    repo_root = _repo_root_from_this_file()
    pack_root = Path(ns.out).resolve() if ns.out is not None else (repo_root / "belgi" / "_protocol_packs" / "v1")

    try:
        build_builtin_pack(repo_root=repo_root, pack_root=pack_root, pack_name=ns.pack_name)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    print(f"OK: built builtin protocol pack at {pack_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
