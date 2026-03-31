from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers.consistency_owner_fixtures import (
    assert_invariant_fails,
    assert_invariants_pass,
    build_owner_family_repo,
    mutate_json,
    replace_text,
    replace_text_in_markdown_section,
)
from tools.consistency.invariants import intentspec as owner

pytestmark = pytest.mark.repo_local


def test_intentspec_owner_invariants_pass_on_owner_derived_repo(tmp_path: Path) -> None:
    root = build_owner_family_repo(tmp_path, "intentspec")
    assert_invariants_pass(
        root,
        [
            ("CS-IS-001", owner.check_intentspec_yaml_single_block),
            ("CS-IS-002", owner.check_cs_is_002),
            ("CS-IS-003", owner.check_cs_is_003),
            ("CS-IS-004", owner.check_cs_is_004),
            ("CS-IS-005", owner.check_cs_is_005),
        ],
    )


@pytest.mark.parametrize(
    ("invariant_id", "mutate", "check", "expected_fragment"),
    [
        (
            "CS-IS-001",
            lambda root: replace_text(root, "belgi/templates/IntentSpec.core.template.md", "```yaml", "```text"),
            owner.check_intentspec_yaml_single_block,
            "belgi/templates/IntentSpec.core.template.md",
        ),
        (
            "CS-IS-002",
            lambda root: mutate_json(
                root,
                "schemas/IntentSpec.schema.json",
                lambda payload: payload["required"].remove("doc_impact"),
            ),
            owner.check_cs_is_002,
            "schemas/IntentSpec.schema.json#/required",
        ),
        (
            "CS-IS-003",
            lambda root: replace_text_in_markdown_section(
                root,
                "gates/GATE_Q.md",
                "### Q-INTENT-003 — Deterministic mapping rules from IntentSpec → LockedSpec inputs",
                "LockedSpec.doc_impact",
                "LockedSpec.doc_scope",
            ),
            owner.check_cs_is_003,
            "gates/GATE_Q.md#q-intent-003--deterministic-mapping-rules-from-intentspec--lockedspec-inputs",
        ),
        (
            "CS-IS-004",
            lambda root: replace_text(root, "schemas/README.md", "IntentSpec.core.md", "IntentSpec.placeholder.md"),
            owner.check_cs_is_004,
            "schemas docs",
        ),
        (
            "CS-IS-005",
            lambda root: mutate_json(
                root,
                "schemas/IntentSpec.schema.json",
                lambda payload: payload["properties"]["scope"]["properties"].__setitem__("max_touched_files", {"type": "integer"}),
            ),
            owner.check_cs_is_005,
            "schemas/IntentSpec.schema.json",
        ),
    ],
)
def test_intentspec_owner_invariants_fail_closed_on_owner_derived_mutations(
    tmp_path: Path,
    invariant_id: str,
    mutate,
    check,
    expected_fragment: str,
) -> None:
    root = build_owner_family_repo(tmp_path, "intentspec")
    mutate(root)
    assert_invariant_fails(root, invariant_id, check, expected_fragment)
