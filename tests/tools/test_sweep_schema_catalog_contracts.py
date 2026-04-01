from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers.consistency_owner_fixtures import (
    assert_invariant_fails,
    assert_invariants_pass,
    build_repo_fixture,
    replace_text,
)
from tools._sweep.invariants import schema_catalog as owner

pytestmark = pytest.mark.repo_local

def _schema_catalog_read_relpaths() -> tuple[str, ...]:
    """Exact file set read by CS-SCHEMA-001."""

    return (
        "schemas/README.md",
        "belgi/_protocol_packs/v1/schemas/README.md",
        "chain/logic/locked_object_schema.py",
        "chain/logic/toolchain_set.py",
        "chain/logic/tolerances.py",
    )


def build_schema_catalog_repo(tmp_path: Path) -> Path:
    return build_repo_fixture(tmp_path, "schema_catalog", patterns=_schema_catalog_read_relpaths())


def test_schema_catalog_owner_invariant_passes_on_owner_derived_repo(tmp_path: Path) -> None:
    root = build_schema_catalog_repo(tmp_path)
    assert_invariants_pass(root, [("CS-SCHEMA-001", owner.check_cs_schema_001)])


def test_schema_catalog_owner_invariant_fails_when_pack_readme_drifts(tmp_path: Path) -> None:
    root = build_schema_catalog_repo(tmp_path)
    replace_text(
        root,
        "belgi/_protocol_packs/v1/schemas/README.md",
        "Gate Q / Gate R locked-object loaders validate ToolchainSet and Tolerances against these published schemas after ObjectRef hash binding.",
        "Gate Q / Gate R loaders trust these schemas without post-bind validation.",
    )
    assert_invariant_fails(root, "CS-SCHEMA-001", owner.check_cs_schema_001, "belgi/_protocol_packs/v1/schemas/README.md")
