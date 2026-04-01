from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers.consistency_owner_fixtures import (
    assert_invariants_pass,
    build_repo_fixture,
    replace_text,
)
from tools._sweep.invariants import run_contract as owner

pytestmark = pytest.mark.repo_local

def _run_contract_read_relpaths() -> tuple[str, ...]:
    """Exact union of files read by CS-RUN-001 and CS-RUN-002."""

    return (
        "docs/operations/cli.md",
        "docs/operations/operator-anchors.md",
        "docs/operations/running-belgi.md",
        "belgi/cli_app/parser/run.py",
        "belgi/cli_app/commands/run.py",
    )


def build_run_contract_repo(tmp_path: Path) -> Path:
    return build_repo_fixture(tmp_path, "run_contract", patterns=_run_contract_read_relpaths())


def test_run_contract_owner_invariants_pass_on_owner_derived_repo(tmp_path: Path) -> None:
    root = build_run_contract_repo(tmp_path)
    assert_invariants_pass(
        root,
        [
            ("CS-RUN-001", owner.check_cs_run_001),
            ("CS-RUN-002", owner.check_cs_run_002),
        ],
    )


def test_cs_run_002_fails_when_non_owner_docs_reintroduce_stale_placeholder(tmp_path: Path) -> None:
    root = build_run_contract_repo(tmp_path)
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
