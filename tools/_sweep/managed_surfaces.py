from __future__ import annotations

from tools._shared import common as _common


def _sweep_managed_surface_files(root: _common.Path) -> list[str]:
    """Owner for sweep-managed operational surfaces."""

    tracked = _common._run_git(root, ["ls-files"])
    out: set[str] = set()
    for raw in tracked.splitlines():
        rel = raw.strip()
        if not rel:
            continue
        rel = _common._validate_repo_rel(rel)
        if "/" not in rel and rel.endswith(".md"):
            out.add(rel)
            continue
        if rel.startswith("docs/operations/") and rel.endswith(".md"):
            out.add(rel)
            continue
        if rel.startswith("belgi/canonicals/"):
            suffix = rel[len("belgi/canonicals/") :]
            if "/" not in suffix and rel.endswith(".md"):
                out.add(rel)
                continue
            if rel.startswith("belgi/canonicals/docs/operations/") and rel.endswith(".md"):
                out.add(rel)
                continue
            continue
        if rel in {
            "tools/README.md",
            "tools/canonicals_report.py",
        }:
            out.add(rel)
            continue
        if rel.startswith(".github/workflows/") and rel.endswith((".yml", ".yaml")):
            out.add(rel)
            continue
        if rel.startswith(".github/scripts/") and rel.endswith(".py"):
            out.add(rel)
            continue
        if rel.startswith("scripts/belgi_") and rel.endswith((".py", ".sh", ".ps1")):
            out.add(rel)
            continue
        if rel.startswith("templates/ci/github/") and rel.endswith((".yml", ".yaml")):
            out.add(rel)
            continue
    return sorted(out)
