from __future__ import annotations

"""Declarative owner for the managed operational surface family."""

# These patterns use repo-root glob semantics. They define the family law only;
# managed_surfaces.py resolves them against the tracked tree.
MANAGED_SURFACE_INCLUDE_PATTERNS: tuple[str, ...] = (
    "*.md",
    "docs/operations/*.md",
    "belgi/canonicals/*.md",
    "belgi/canonicals/docs/operations/*.md",
    ".github/scripts/*.py",
    "scripts/belgi_*.py",
    "scripts/belgi_*.sh",
    "scripts/belgi_*.ps1",
    "templates/ci/github/*.yml",
    "templates/ci/github/*.yaml",
    "tools/README.md",
    "tools/canonicals_report.py",
)

# Keep governed workflows explicit so synthetic or temporary local workflow
# helpers do not widen the managed surface by filename pattern alone.
MANAGED_WORKFLOW_FILES: tuple[str, ...] = (
    ".github/workflows/pinned-install-proof.yml",
    ".github/workflows/pull-request-proof.yml",
    ".github/workflows/repository-verification.yml",
)

MANAGED_SURFACE_EXCLUDE_PATTERNS: tuple[str, ...] = (
    "docs/research/*.md",
    "belgi/canonicals/docs/research/*.md",
    "tools/_shared/common.py",
    "tools/_sweep/*.py",
    "tools/_sweep/invariants/*.py",
)
