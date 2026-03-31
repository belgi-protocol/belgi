from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers.consistency_owner_fixtures import (
    assert_invariants_pass,
    build_owner_family_repo,
    replace_text,
)
from tools._sweep.invariants import canonicals as owner

pytestmark = pytest.mark.repo_local


def test_canonicals_owner_invariants_pass_on_owner_derived_repo(tmp_path: Path) -> None:
    root = build_owner_family_repo(tmp_path, "canonicals")
    assert_invariants_pass(
        root,
        [
            ("CS-CAN-001", owner.check_cs_can_001),
            ("CS-CAN-004", owner.check_cs_can_004),
            ("CS-CAN-002", owner.check_cs_can_002),
            ("CS-CAN-003", owner.check_cs_can_003),
            ("CS-CAN-005", owner.check_cs_can_005),
            ("CS-TERM-001", owner.check_cs_term_001),
        ],
    )


def test_cs_can_005_fails_when_package_mirror_drifts(tmp_path: Path) -> None:
    root = build_owner_family_repo(tmp_path, "canonicals")
    replace_text(
        root,
        "belgi/canonicals/docs/operations/running-belgi.md",
        "Canonical chain:",
        "Canonical chain drift:",
    )

    result = owner.check_cs_can_005(root)
    assert result.invariant_id == "CS-CAN-005"
    assert result.status == "FAIL"
    assert "python -m tools.build_builtin_pack" in result.remediation
