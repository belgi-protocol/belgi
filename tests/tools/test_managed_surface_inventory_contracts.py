from __future__ import annotations

from pathlib import Path

import pytest

from tests.tools.managed_surface_contract import expected_managed_surface_relpaths
from tools._sweep import managed_surfaces as owner

pytestmark = pytest.mark.repo_local
REPO_ROOT = Path(__file__).resolve().parents[2]

MANAGED_SURFACE_EXCLUSION_PATTERNS = (
    "docs/research/*.md",
    "tools/_shared/common.py",
    "tools/_sweep/inputs.py",
    "tools/_sweep/managed_surfaces.py",
    "tools/_sweep/model.py",
    "tools/_sweep/registry.py",
    "tools/_sweep/report_writer.py",
    "tools/_sweep/runner.py",
    "tools/_sweep/invariants/orchestration.py",
    "tools/_sweep/invariants/tiers.py",
)

def test_managed_surface_inventory_owner_matches_explicit_operational_contract() -> None:
    managed = set(owner._sweep_managed_surface_files(REPO_ROOT))
    expected = expected_managed_surface_relpaths()

    assert managed == expected
    assert "README.md" in managed
    assert "CANONICALS.md" in managed
    assert "CHANGELOG.md" in managed
    assert "docs/operations/consistency-sweep.md" in managed
    assert "belgi/canonicals/CANONICALS.md" in managed
    assert "belgi/canonicals/terminology.md" in managed
    assert "belgi/canonicals/trust-model.md" in managed
    assert "belgi/canonicals/docs/operations/consistency-sweep.md" in managed
    assert "tools/README.md" in managed
    assert "tools/canonicals_report.py" in managed


def test_managed_surface_inventory_excludes_repo_local_research_and_internal_implementation_files() -> None:
    managed = set(owner._sweep_managed_surface_files(REPO_ROOT))

    assert (REPO_ROOT / "docs" / "research" / "README.md").is_file()
    assert (REPO_ROOT / "tools" / "_shared" / "common.py").is_file()
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
    for rel in MANAGED_SURFACE_EXCLUSION_PATTERNS:
        assert rel not in managed
