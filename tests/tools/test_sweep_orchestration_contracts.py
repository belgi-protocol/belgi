from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers.consistency_owner_fixtures import (
    assert_invariants_pass,
    build_repo_fixture,
    replace_text,
)
from tools._sweep import managed_surfaces as managed_surfaces_owner
from tools._sweep.invariants import orchestration as owner

pytestmark = pytest.mark.repo_local
REPO_ROOT = Path(__file__).resolve().parents[2]

ORCHESTRATION_INTERNAL_EXTRA_PATTERNS = (
    "tools/_sweep/model.py",
    "tools/_sweep/report_writer.py",
    "tools/_sweep/runner.py",
    "tools/_sweep/invariants/canonicals.py",
    "tools/_sweep/invariants/orchestration.py",
    "tools/_sweep/invariants/tiers.py",
)


def build_orchestration_repo(tmp_path: Path, *, extra_patterns: tuple[str, ...] = ()) -> Path:
    owner_relpaths = tuple(
        sorted(
            set(owner._canonical_inputs(REPO_ROOT))
            | set(managed_surfaces_owner._sweep_managed_surface_files(REPO_ROOT))
        )
    )
    return build_repo_fixture(
        tmp_path,
        "orchestration",
        patterns=owner_relpaths,
        extra_patterns=extra_patterns,
    )


def test_orchestration_owner_invariants_pass_on_owner_derived_repo(tmp_path: Path) -> None:
    root = build_orchestration_repo(tmp_path)
    assert_invariants_pass(
        root,
        [
            ("CS-BYTE-001", owner.check_cs_byte_001),
            ("CS-FIXTURE-ZERO-001", owner.check_cs_fixture_zero_001),
            ("CS-PROTOCOL-IDENTITY-001", owner.check_cs_protocol_identity_001),
            ("CS-SWEEP-001", owner.check_cs_sweep_001),
            ("CS-SWEEP-002", owner.check_cs_sweep_002),
            ("CS-R0-ENFORCEMENT-WIRED-001", owner.check_cs_r0_enforcement_wired_001),
        ],
    )


def test_cs_sweep_001_excludes_internal_sweep_implementation_files_from_inputs(tmp_path: Path) -> None:
    root = build_orchestration_repo(tmp_path, extra_patterns=ORCHESTRATION_INTERNAL_EXTRA_PATTERNS)
    canonical_inputs = owner._canonical_inputs(root)

    assert (root / "tools" / "_sweep" / "model.py").is_file()
    assert (root / "tools" / "_sweep" / "report_writer.py").is_file()
    assert (root / "tools" / "_sweep" / "runner.py").is_file()
    assert (root / "tools" / "_sweep" / "invariants" / "canonicals.py").is_file()
    assert (root / "tools" / "_sweep" / "invariants" / "orchestration.py").is_file()
    assert (root / "tools" / "_sweep" / "invariants" / "tiers.py").is_file()

    assert "tools/_sweep/inputs.py" in canonical_inputs
    assert "tools/_sweep/managed_surfaces.py" in canonical_inputs
    assert "tools/_sweep/registry.py" in canonical_inputs
    assert "tools/sweep.py" in canonical_inputs

    assert "tools/_sweep/model.py" not in canonical_inputs
    assert "tools/_sweep/report_writer.py" not in canonical_inputs
    assert "tools/_sweep/runner.py" not in canonical_inputs
    assert "tools/_sweep/invariants/canonicals.py" not in canonical_inputs
    assert "tools/_sweep/invariants/orchestration.py" not in canonical_inputs
    assert "tools/_sweep/invariants/tiers.py" not in canonical_inputs


def test_cs_sweep_002_fails_when_managed_surface_is_missing_from_canonical_inputs(tmp_path: Path) -> None:
    root = build_orchestration_repo(tmp_path)
    canonical_inputs = owner._canonical_inputs(root)
    result = owner.check_cs_sweep_002(
        root,
        canonical_inputs_fn=lambda _root: [rel for rel in canonical_inputs if rel != "tools/README.md"],
    )

    assert result.invariant_id == "CS-SWEEP-002"
    assert result.status == "FAIL"
    assert "tools/README.md" in result.remediation


def test_cs_protocol_identity_001_fails_when_source_becomes_identity_language(tmp_path: Path) -> None:
    root = build_orchestration_repo(tmp_path)
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
