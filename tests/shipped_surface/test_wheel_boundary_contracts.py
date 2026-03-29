from __future__ import annotations

import subprocess
import sys
from pathlib import Path, PurePosixPath

import pytest

from tools.wheel_boundary import (
    FORBIDDEN_MODULE_PREFIXES,
    REQUIRED_MODULE_PREFIXES,
    list_wheel_entries,
    module_prefixes,
    validate_wheel_boundary,
    wheel_listing_sha256,
)

pytestmark = pytest.mark.repo_local

REPO_ROOT = Path(__file__).resolve().parents[2]
FORBIDDEN_NESTED_SEGMENTS = frozenset({
    "tests",
    "housekeeping",
    "__pycache__",
    ".pytest_cache",
})


def _build_wheel(out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    cp = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            ".",
            "--no-build-isolation",
            "--no-deps",
            "-w",
            str(out_dir),
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    assert cp.returncode == 0, (cp.returncode, cp.stdout, cp.stderr)
    wheels = sorted(out_dir.glob("belgi-*.whl"))
    assert wheels, "expected at least one built belgi wheel"
    return wheels[-1]


def test_built_wheel_matches_publish_boundary_prefix_ssot(tmp_path: Path) -> None:
    wheel_path = _build_wheel(tmp_path / "dist")

    entries_first = list_wheel_entries(wheel_path)
    entries_second = list_wheel_entries(wheel_path)
    assert entries_first == entries_second
    assert wheel_listing_sha256(entries_first) == wheel_listing_sha256(entries_second)

    violations = validate_wheel_boundary(entries_first)
    assert violations == []

    prefixes = module_prefixes(entries_first)
    for prefix in REQUIRED_MODULE_PREFIXES:
        assert prefix in prefixes
    for prefix in FORBIDDEN_MODULE_PREFIXES:
        assert prefix not in prefixes


def test_built_wheel_excludes_forbidden_nested_repo_only_segments(tmp_path: Path) -> None:
    wheel_path = _build_wheel(tmp_path / "dist")
    entries = list_wheel_entries(wheel_path)

    unexpected_nested: list[str] = []
    for entry in entries:
        parts = PurePosixPath(entry.rstrip("/")).parts
        if len(parts) < 2:
            continue
        head = parts[0]
        if head.endswith(".dist-info") or head.endswith(".data"):
            continue
        nested = set(parts[1:])
        if nested & FORBIDDEN_NESTED_SEGMENTS:
            unexpected_nested.append(entry)

    assert unexpected_nested == []
