from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers.consistency_owner_fixtures import build_owner_family_repo
from tools._sweep import managed_surfaces as owner

pytestmark = pytest.mark.repo_local


def test_managed_surface_inventory_owner_lists_explicit_operational_surfaces(tmp_path: Path) -> None:
    root = build_owner_family_repo(tmp_path, "orchestration")
    managed = owner._sweep_managed_surface_files(root)

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
