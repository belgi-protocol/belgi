from __future__ import annotations

from tools._shared import common as _common
from tools._sweep.managed_surface_spec import (
    MANAGED_SURFACE_EXCLUDE_PATTERNS,
    MANAGED_SURFACE_INCLUDE_PATTERNS,
    MANAGED_WORKFLOW_FILES,
)


def _tracked_repo_files(root: _common.Path) -> list[str]:
    tracked = _common._run_git(root, ["ls-files"])
    return sorted(
        _common._validate_repo_rel(raw.strip())
        for raw in tracked.splitlines()
        if raw.strip()
    )


def _resolve_repo_patterns(root: _common.Path, patterns: tuple[str, ...]) -> list[str]:
    repo_root = root.resolve()
    relpaths: set[str] = set()
    for pattern in patterns:
        for path in sorted(root.glob(pattern), key=lambda p: p.as_posix()):
            if not path.is_file():
                continue
            rel = path.resolve().relative_to(repo_root).as_posix()
            relpaths.add(_common._validate_repo_rel(rel))
    return sorted(relpaths)


def _resolve_declared_repo_paths(root: _common.Path, relpaths: tuple[str, ...]) -> list[str]:
    resolved: set[str] = set()
    for rel in relpaths:
        path = root / _common._validate_repo_rel(rel)
        if path.is_file():
            resolved.add(rel)
    return sorted(resolved)


def _sweep_managed_surface_files(root: _common.Path) -> list[str]:
    """Resolve the managed operational surface from the declarative spec owner."""

    tracked = set(_tracked_repo_files(root))
    included = set(_resolve_repo_patterns(root, MANAGED_SURFACE_INCLUDE_PATTERNS))
    included.update(_resolve_declared_repo_paths(root, MANAGED_WORKFLOW_FILES))
    excluded = set(_resolve_repo_patterns(root, MANAGED_SURFACE_EXCLUDE_PATTERNS))
    resolved = (included - excluded) & tracked
    return sorted(resolved)
