from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers.consistency_owner_fixtures import (
    assert_invariants_pass,
    build_owner_family_repo,
    replace_text,
)
from tools._sweep.invariants import orchestration as owner

pytestmark = pytest.mark.repo_local


def test_orchestration_owner_invariants_pass_on_owner_derived_repo(tmp_path: Path) -> None:
    root = build_owner_family_repo(tmp_path, "orchestration")
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


def test_cs_sweep_002_fails_when_owner_file_is_unlisted(tmp_path: Path) -> None:
    root = build_owner_family_repo(tmp_path, "orchestration")
    managed = owner._sweep_managed_surface_files(root)
    result = owner.check_cs_sweep_002(
        root,
        canonical_inputs_fn=lambda _root: [rel for rel in managed if rel != "tools/_sweep/registry.py"],
    )

    assert result.invariant_id == "CS-SWEEP-002"
    assert result.status == "FAIL"
    assert "tools/_sweep/registry.py" in result.remediation


def test_cs_protocol_identity_001_fails_when_source_becomes_identity_language(tmp_path: Path) -> None:
    root = build_owner_family_repo(tmp_path, "orchestration")
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
