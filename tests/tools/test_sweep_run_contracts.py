from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers.consistency_owner_fixtures import (
    assert_invariants_pass,
    build_owner_family_repo,
    replace_text,
)
from tools.consistency.invariants import run_contract as owner

pytestmark = pytest.mark.repo_local


def test_run_contract_owner_invariants_pass_on_owner_derived_repo(tmp_path: Path) -> None:
    root = build_owner_family_repo(tmp_path, "run_contract")
    assert_invariants_pass(
        root,
        [
            ("CS-RUN-001", owner.check_cs_run_001),
            ("CS-RUN-002", owner.check_cs_run_002),
        ],
    )


def test_cs_run_002_fails_when_non_owner_docs_reintroduce_stale_placeholder(tmp_path: Path) -> None:
    root = build_owner_family_repo(tmp_path, "run_contract")
    replace_text(
        root,
        "docs/operations/running-belgi.md",
        ".belgi/runs/<run_id>/inputs/environment/toolchain-set.json",
        ".belgi/runs/<run_id>/toolchain.json",
    )

    result = owner.check_cs_run_002(root)
    assert result.invariant_id == "CS-RUN-002"
    assert result.status == "FAIL"
    assert "pointer-bounded" in result.remediation
