from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers.consistency_owner_fixtures import resolve_repo_patterns
from tools._sweep import managed_surfaces as owner
from tools._sweep.managed_surface_spec import (
    MANAGED_SURFACE_EXCLUDE_PATTERNS,
    MANAGED_SURFACE_INCLUDE_PATTERNS,
    MANAGED_WORKFLOW_FILES,
)

pytestmark = pytest.mark.repo_local
REPO_ROOT = Path(__file__).resolve().parents[2]

def test_managed_surface_inventory_owner_matches_explicit_operational_contract() -> None:
    managed = set(owner._sweep_managed_surface_files(REPO_ROOT))
    included = set(resolve_repo_patterns(MANAGED_SURFACE_INCLUDE_PATTERNS))
    included.update(MANAGED_WORKFLOW_FILES)
    excluded = set(resolve_repo_patterns(MANAGED_SURFACE_EXCLUDE_PATTERNS))
    expected = included - excluded

    assert managed == expected
    assert "README.md" in managed
    assert "CANONICALS.md" in managed
    assert "CHANGELOG.md" in managed
    assert "docs/operations/consistency-sweep.md" in managed
    assert "belgi/canonicals/CANONICALS.md" in managed
    assert "belgi/canonicals/terminology.md" in managed
    assert "belgi/canonicals/trust-model.md" in managed
    assert "belgi/canonicals/docs/operations/consistency-sweep.md" in managed
    assert ".github/workflows/pinned-install-proof.yml" in managed
    assert ".github/workflows/pull-request-proof.yml" in managed
    assert ".github/workflows/repository-verification.yml" in managed
    assert "tools/README.md" in managed
    assert "tools/canonicals_report.py" in managed


def test_managed_surface_inventory_excludes_repo_local_research_and_internal_implementation_files() -> None:
    managed = set(owner._sweep_managed_surface_files(REPO_ROOT))

    assert (REPO_ROOT / "docs" / "research" / "README.md").is_file()
    assert (REPO_ROOT / "tools" / "_shared" / "common.py").is_file()
    assert (REPO_ROOT / "tools" / "_sweep" / "input_surface_spec.py").is_file()
    assert (REPO_ROOT / "tools" / "_sweep" / "managed_surface_spec.py").is_file()
    assert (REPO_ROOT / "tools" / "_sweep" / "inputs.py").is_file()
    assert (REPO_ROOT / "tools" / "_sweep" / "managed_surfaces.py").is_file()
    assert (REPO_ROOT / "tools" / "_sweep" / "model.py").is_file()
    assert (REPO_ROOT / "tools" / "_sweep" / "registry.py").is_file()
    assert (REPO_ROOT / "tools" / "_sweep" / "report_writer.py").is_file()
    assert (REPO_ROOT / "tools" / "_sweep" / "runner.py").is_file()
    assert (REPO_ROOT / "tools" / "_sweep" / "invariants" / "orchestration.py").is_file()
    assert (REPO_ROOT / "tools" / "_sweep" / "invariants" / "tiers.py").is_file()

    assert not any(rel.startswith("docs/research/") for rel in managed)
    assert not any(rel.startswith("belgi/canonicals/docs/research/") for rel in managed)
    assert "tools/_shared/common.py" not in managed
    assert "tools/_sweep/input_surface_spec.py" not in managed
    assert "tools/_sweep/managed_surface_spec.py" not in managed
    assert "tools/_sweep/inputs.py" not in managed
    assert "tools/_sweep/managed_surfaces.py" not in managed
    assert "tools/_sweep/model.py" not in managed
    assert "tools/_sweep/registry.py" not in managed
    assert "tools/_sweep/report_writer.py" not in managed
    assert "tools/_sweep/runner.py" not in managed
    assert "tools/_sweep/invariants/orchestration.py" not in managed
    assert "tools/_sweep/invariants/tiers.py" not in managed
