from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers.consistency_owner_fixtures import build_repo_fixture
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


def build_managed_surface_repo(tmp_path: Path) -> Path:
    owner_relpaths = tuple(owner._sweep_managed_surface_files(REPO_ROOT))
    return build_repo_fixture(
        tmp_path,
        "managed_surfaces",
        patterns=owner_relpaths,
        extra_patterns=MANAGED_SURFACE_EXCLUSION_PATTERNS,
    )


def test_managed_surface_inventory_owner_lists_explicit_operational_surfaces(tmp_path: Path) -> None:
    root = build_managed_surface_repo(tmp_path)
    managed = owner._sweep_managed_surface_files(root)

    assert (root / "docs" / "research" / "README.md").is_file()
    assert (root / "tools" / "_shared" / "common.py").is_file()
    assert (root / "tools" / "_sweep" / "inputs.py").is_file()
    assert (root / "tools" / "_sweep" / "managed_surfaces.py").is_file()
    assert (root / "tools" / "_sweep" / "model.py").is_file()
    assert (root / "tools" / "_sweep" / "registry.py").is_file()
    assert (root / "tools" / "_sweep" / "report_writer.py").is_file()
    assert (root / "tools" / "_sweep" / "runner.py").is_file()
    assert (root / "tools" / "_sweep" / "invariants" / "orchestration.py").is_file()
    assert (root / "tools" / "_sweep" / "invariants" / "tiers.py").is_file()

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

    assert not any(rel.startswith("docs/research/") for rel in managed)
    assert not any(rel.startswith("belgi/canonicals/docs/research/") for rel in managed)
    assert "tools/_sweep/inputs.py" not in managed
    assert "tools/_sweep/managed_surfaces.py" not in managed
    assert "tools/_sweep/model.py" not in managed
    assert "tools/_sweep/registry.py" not in managed
    assert "tools/_sweep/report_writer.py" not in managed
    assert "tools/_sweep/runner.py" not in managed
    assert "tools/_sweep/invariants/orchestration.py" not in managed
    assert "tools/_sweep/invariants/tiers.py" not in managed
    assert "tools/_shared/common.py" not in managed
