#!/usr/bin/env python3
"""Check for drift between root protocol mirrors and belgi/_protocol_packs/v1/.

Canonical source: root {schemas, gates, tiers} folders.
Runtime pack: belgi/_protocol_packs/v1/{schemas, gates, tiers}.

This script fails if:
  A) Any mirrored file differs between the two locations.
  B) Pack contains unexpected top-level entries (shape violation).

The build_builtin_pack.py tool copies root -> pack; this guard ensures they stay in sync.

Exit codes:
  0: No drift, pack shape valid
  1: Drift detected or shape violation
  2: Internal error
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Allow running as a script (python -m tools.check_drift) without shadowing the
# belgi/ package via tools/belgi_tools.py.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from belgi.protocol.pack import validate_manifest_bytes


# Protocol pack v1 allowed content (whitelist).
PACK_ALLOWED_FOLDERS = frozenset({"schemas", "gates", "tiers"})
PACK_ALLOWED_FILES = frozenset({"ProtocolPackManifest.json"})


def _sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def check_drift(repo_root: Path) -> list[str]:
    """Return list of drifted files (empty if none)."""
    pack_root = repo_root / "belgi" / "_protocol_packs" / "v1"
    drifted: list[str] = []

    for folder in ("schemas", "gates", "tiers"):
        root_dir = repo_root / folder
        pack_dir = pack_root / folder

        if not root_dir.exists():
            # Canonical folder missing but pack folder present => pack-only surface.
            if pack_dir.exists():
                for pack_file in sorted(pack_dir.iterdir()):
                    if pack_file.is_file():
                        drifted.append(
                            f"{folder}/{pack_file.name}: exists in pack but canonical folder missing"
                        )
            continue

        if not pack_dir.exists():
            # Canonical folder exists but pack folder missing.
            for root_file in sorted(root_dir.iterdir()):
                if root_file.is_file():
                    drifted.append(f"{folder}/{root_file.name}: missing in pack")
            continue

        for root_file in sorted(root_dir.iterdir()):
            if not root_file.is_file():
                continue

            pack_file = pack_dir / root_file.name
            if not pack_file.exists():
                drifted.append(f"{folder}/{root_file.name}: missing in pack")
                continue

            h1 = _sha256_file(root_file)
            h2 = _sha256_file(pack_file)
            if h1 != h2:
                drifted.append(f"{folder}/{root_file.name}: DRIFT (root != pack)")

        # Detect pack-only additions (silent runtime surface expansion).
        for pack_file in sorted(pack_dir.iterdir()):
            if not pack_file.is_file():
                continue
            root_file = root_dir / pack_file.name
            if not root_file.exists():
                drifted.append(
                    f"{folder}/{pack_file.name}: exists in pack but missing in canonical root"
                )

    return drifted


def check_pack_shape(repo_root: Path) -> list[str]:
    """Return list of pack shape violations (empty if none)."""
    pack_root = repo_root / "belgi" / "_protocol_packs" / "v1"
    violations: list[str] = []

    if not pack_root.exists():
        violations.append("pack root does not exist")
        return violations

    for item in sorted(pack_root.iterdir(), key=lambda p: p.name):
        name = item.name
        if item.is_dir():
            if name not in PACK_ALLOWED_FOLDERS:
                violations.append(f"unexpected directory: {name}")
        elif item.is_file():
            if name not in PACK_ALLOWED_FILES:
                violations.append(f"unexpected file: {name}")
        else:
            violations.append(f"unexpected item type: {name}")

    return violations


def main() -> int:
    repo_root = REPO_ROOT
    failed = False

    # A) Check pack shape (no unexpected content)
    shape_violations = check_pack_shape(repo_root)
    if shape_violations:
        print("PACK SHAPE VIOLATION:", file=sys.stderr)
        for item in shape_violations:
            print(f"  - {item}", file=sys.stderr)
        failed = True

    # B) Check content drift (root mirrors vs pack)
    drifted = check_drift(repo_root)
    if drifted:
        print("CONTENT DRIFT DETECTED:", file=sys.stderr)
        for item in drifted:
            print(f"  - {item}", file=sys.stderr)
        failed = True

    # C) Validate ProtocolPackManifest.json is consistent with scanned pack contents.
    pack_root = repo_root / "belgi" / "_protocol_packs" / "v1"
    manifest_path = pack_root / "ProtocolPackManifest.json"
    if not manifest_path.exists() or not manifest_path.is_file():
        print("PACK MANIFEST VIOLATION:", file=sys.stderr)
        print("  - Missing belgi/_protocol_packs/v1/ProtocolPackManifest.json", file=sys.stderr)
        failed = True
    else:
        try:
            validate_manifest_bytes(pack_root=pack_root, manifest_bytes=manifest_path.read_bytes())
        except Exception as e:
            print("PACK MANIFEST VIOLATION:", file=sys.stderr)
            print(f"  - {e}", file=sys.stderr)
            failed = True

    if failed:
        print("\nFix: run `python -c \"import sys; sys.path.insert(0, '.'); from tools.build_builtin_pack import main; main()\"`", file=sys.stderr)
        return 1

    print("OK: No drift detected, pack shape valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
