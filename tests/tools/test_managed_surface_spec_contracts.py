from __future__ import annotations

from pathlib import Path

import pytest

from tools._shared import common as _common
from tools._sweep.managed_surface_spec import (
    MANAGED_SURFACE_EXCLUDE_PATTERNS,
    MANAGED_SURFACE_INCLUDE_PATTERNS,
    MANAGED_WORKFLOW_FILES,
)

pytestmark = pytest.mark.repo_local
REPO_ROOT = Path(__file__).resolve().parents[2]


def test_managed_surface_spec_keeps_expected_include_patterns() -> None:
    assert MANAGED_SURFACE_INCLUDE_PATTERNS == (
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


def test_managed_workflow_files_stay_explicit_governed_workflow_set() -> None:
    assert MANAGED_WORKFLOW_FILES == (
        ".github/workflows/pinned-install-proof.yml",
        ".github/workflows/pull-request-proof.yml",
        ".github/workflows/repository-verification.yml",
    )


def test_managed_workflow_files_exist_and_are_tracked() -> None:
    tracked = {
        line.strip()
        for line in _common._run_git(REPO_ROOT, ["ls-files", ".github/workflows"]).splitlines()
        if line.strip()
    }

    for rel in MANAGED_WORKFLOW_FILES:
        assert (REPO_ROOT / rel).is_file()
        assert rel in tracked


def test_managed_surface_spec_keeps_expected_exclude_patterns() -> None:
    assert MANAGED_SURFACE_EXCLUDE_PATTERNS == (
        "docs/research/*.md",
        "belgi/canonicals/docs/research/*.md",
        "tools/_shared/common.py",
        "tools/_sweep/*.py",
        "tools/_sweep/invariants/*.py",
    )
