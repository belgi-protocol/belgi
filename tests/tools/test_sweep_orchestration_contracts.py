from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers.consistency_owner_fixtures import (
    build_repo_fixture,
    replace_text,
)
from tests.tools.managed_surface_contract import expected_managed_surface_relpaths
from tools._sweep.invariants import orchestration as owner

pytestmark = pytest.mark.repo_local
REPO_ROOT = Path(__file__).resolve().parents[2]

def test_cs_sweep_001_passes_on_repo_root_and_stays_on_governed_control_plane_inputs() -> None:
    result = owner.check_cs_sweep_001(REPO_ROOT)
    canonical_inputs = set(owner._canonical_inputs(REPO_ROOT))

    assert result.invariant_id == "CS-SWEEP-001"
    assert result.status == "PASS", result.remediation
    assert "tools/_sweep/inputs.py" in canonical_inputs
    assert "tools/_sweep/managed_surfaces.py" in canonical_inputs
    assert "tools/_sweep/registry.py" in canonical_inputs
    assert "tools/sweep.py" in canonical_inputs
    assert "tools/normalize.py" in canonical_inputs
    assert "tools/rehash.py" in canonical_inputs
    assert "tools/canonicals_report.py" in canonical_inputs
    assert "tools/_sweep/model.py" not in canonical_inputs
    assert "tools/_sweep/report_writer.py" not in canonical_inputs
    assert "tools/_sweep/runner.py" not in canonical_inputs
    assert "tools/_shared/common.py" not in canonical_inputs
    assert "tools/_sweep/invariants/canonicals.py" not in canonical_inputs
    assert "tools/_sweep/invariants/orchestration.py" not in canonical_inputs
    assert "tools/_sweep/invariants/tiers.py" not in canonical_inputs


def test_cs_sweep_002_passes_on_repo_root_and_propagates_managed_surface_owner_set() -> None:
    result = owner.check_cs_sweep_002(REPO_ROOT)
    canonical_inputs = set(owner._canonical_inputs(REPO_ROOT))
    expected_managed = expected_managed_surface_relpaths()

    assert result.invariant_id == "CS-SWEEP-002"
    assert result.status == "PASS", result.remediation
    assert expected_managed <= canonical_inputs


def test_cs_sweep_002_fails_when_managed_surface_is_missing_from_canonical_inputs() -> None:
    canonical_inputs = owner._canonical_inputs(REPO_ROOT)
    result = owner.check_cs_sweep_002(
        REPO_ROOT,
        canonical_inputs_fn=lambda _root: [rel for rel in canonical_inputs if rel != "tools/README.md"],
    )

    assert result.invariant_id == "CS-SWEEP-002"
    assert result.status == "FAIL"
    assert "tools/README.md" in result.remediation


def test_cs_protocol_identity_001_fails_when_source_becomes_identity_language(tmp_path: Path) -> None:
    root = build_repo_fixture(tmp_path, "protocol_identity", patterns=("gates/GATE_Q.md",))
    replace_text(
        root,
        "gates/GATE_Q.md",
        "`pack_id`, `manifest_sha256`, `pack_name`",
        "`pack_id`, `manifest_sha256`, `pack_name`, `source`",
    )

    result = owner.check_cs_protocol_identity_001(root, guard_files=("gates/GATE_Q.md",))
    assert result.invariant_id == "CS-PROTOCOL-IDENTITY-001"
    assert result.status == "FAIL"
    assert "gates/GATE_Q.md" in result.remediation
