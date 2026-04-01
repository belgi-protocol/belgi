from __future__ import annotations

from tests.helpers.consistency_owner_fixtures import resolve_repo_patterns

MANAGED_SURFACE_EXPECTED_PATTERNS: tuple[str, ...] = (
    "*.md",
    "docs/operations/*.md",
    "belgi/canonicals/*.md",
    "belgi/canonicals/docs/operations/*.md",
    ".github/workflows/pinned-install-proof.yml",
    ".github/workflows/pull-request-proof.yml",
    ".github/workflows/repository-verification.yml",
    ".github/scripts/*.py",
    "scripts/belgi_*.py",
    "scripts/belgi_*.sh",
    "scripts/belgi_*.ps1",
    "templates/ci/github/*.yml",
    "templates/ci/github/*.yaml",
    "tools/README.md",
    "tools/canonicals_report.py",
)


def expected_managed_surface_relpaths() -> set[str]:
    return set(resolve_repo_patterns(MANAGED_SURFACE_EXPECTED_PATTERNS))
