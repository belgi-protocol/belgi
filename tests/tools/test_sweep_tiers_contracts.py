from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers.consistency_owner_fixtures import (
    append_text,
    assert_invariant_fails,
    assert_invariants_pass,
    build_owner_family_repo,
    mutate_json,
    replace_text,
    replace_text_in_markdown_section,
    replace_text_in_markdown_slice,
)
from tools.consistency.invariants import tiers as owner

pytestmark = pytest.mark.repo_local


def test_tiers_owner_invariants_pass_on_owner_derived_repo(tmp_path: Path) -> None:
    root = build_owner_family_repo(tmp_path, "tiers")
    assert_invariants_pass(
        root,
        [
            ("CS-TIER-001", owner.check_cs_tier_001),
            ("CS-TIER-002", owner.check_cs_tier_002),
            ("CS-TIER-003", owner.check_cs_tier_003),
            ("CS-TIER-004", owner.check_cs_tier_004),
            ("CS-TIER-005", owner.check_cs_tier_005),
        ],
    )


@pytest.mark.parametrize(
    ("invariant_id", "mutate", "check", "expected_fragment"),
    [
        (
            "CS-TIER-001",
            lambda root: append_text(root, "tiers/tier-packs.md", "\nunsupported tier token: tier-9\n"),
            owner.check_cs_tier_001,
            "tiers/tier-packs.md#1-tier-ids",
        ),
        (
            "CS-TIER-002",
            lambda root: replace_text(root, "tiers/tier-packs.md", "findings_mode: `warn`", "findings_mode: `noop`"),
            owner.check_cs_tier_002,
            "tiers/tier-packs.md#3-tier-parameter-sets",
        ),
        (
            "CS-TIER-003",
            lambda root: mutate_json(
                root,
                "schemas/EvidenceManifest.schema.json",
                lambda payload: payload["properties"]["artifacts"]["items"]["properties"]["kind"]["enum"].remove("docs_compilation_log"),
            ),
            owner.check_cs_tier_003,
            "schemas/EvidenceManifest.schema.json#/properties/artifacts/items/properties/kind/enum",
        ),
        (
            "CS-TIER-004",
            lambda root: replace_text_in_markdown_slice(
                root,
                "gates/GATE_R.md",
                start_marker="Additionally, Gate R MUST enforce the tier’s `command_log_mode` deterministically:",
                end_marker="## 5. Deterministic Checks (Executable Doc)",
                old="structured command records",
                new="structured log entries",
            ),
            owner.check_cs_tier_004,
            "gates/GATE_R.md#51-command-matching-rule-used-by-r1r5r6r7r8",
        ),
        (
            "CS-TIER-005",
            lambda root: replace_text_in_markdown_section(
                root,
                "tiers/tier-packs.md",
                "### 2.7 doc_impact_required",
                "doc_impact_required",
                "doc_impact_optional",
            ),
            owner.check_cs_tier_005,
            "tiers/tier-packs.md#27-doc_impact_required",
        ),
    ],
)
def test_tiers_owner_invariants_fail_closed_on_owner_derived_mutations(
    tmp_path: Path,
    invariant_id: str,
    mutate,
    check,
    expected_fragment: str,
) -> None:
    root = build_owner_family_repo(tmp_path, "tiers")
    mutate(root)
    assert_invariant_fails(root, invariant_id, check, expected_fragment)
