from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers.consistency_owner_fixtures import (
    assert_invariant_fails,
    assert_invariants_pass,
    build_owner_family_repo,
    replace_text,
)
from tools.consistency.invariants import schema_catalog as owner

pytestmark = pytest.mark.repo_local


def test_schema_catalog_owner_invariant_passes_on_owner_derived_repo(tmp_path: Path) -> None:
    root = build_owner_family_repo(tmp_path, "schema_catalog")
    assert_invariants_pass(root, [("CS-SCHEMA-001", owner.check_cs_schema_001)])


def test_schema_catalog_owner_invariant_fails_when_pack_readme_drifts(tmp_path: Path) -> None:
    root = build_owner_family_repo(tmp_path, "schema_catalog")
    replace_text(
        root,
        "belgi/_protocol_packs/v1/schemas/README.md",
        "Gate Q / Gate R locked-object loaders validate ToolchainSet and Tolerances against these published schemas after ObjectRef hash binding.",
        "Gate Q / Gate R loaders trust these schemas without post-bind validation.",
    )
    assert_invariant_fails(root, "CS-SCHEMA-001", owner.check_cs_schema_001, "belgi/_protocol_packs/v1/schemas/README.md")
