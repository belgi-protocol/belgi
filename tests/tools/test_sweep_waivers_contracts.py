from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers.consistency_owner_fixtures import (
    assert_invariant_fails,
    assert_invariants_pass,
    build_owner_family_repo,
    mutate_json,
    replace_text,
)
from tools.consistency.invariants import waivers as owner

pytestmark = pytest.mark.repo_local


def test_waivers_owner_invariants_pass_on_owner_derived_repo(tmp_path: Path) -> None:
    root = build_owner_family_repo(tmp_path, "waivers")
    assert_invariants_pass(
        root,
        [
            ("CS-WVR-001", owner.check_cs_wvr_001),
            ("CS-WVR-002", owner.check_cs_wvr_002),
            ("CS-WVR-003", owner.check_cs_wvr_003),
            ("CS-WVR-004", owner.check_cs_wvr_004),
            ("CS-WVR-005", owner.check_cs_wvr_005),
        ],
    )


@pytest.mark.parametrize(
    ("invariant_id", "mutate", "check", "expected_fragment"),
    [
        (
            "CS-WVR-001",
            lambda root: mutate_json(
                root,
                "schemas/Waiver.schema.json",
                lambda payload: payload["required"].remove("approver"),
            ),
            owner.check_cs_wvr_001,
            "schemas/Waiver.schema.json#/required",
        ),
        (
            "CS-WVR-002",
            lambda root: mutate_json(
                root,
                "schemas/Waiver.schema.json",
                lambda payload: payload["required"].remove("expires_at"),
            ),
            owner.check_cs_wvr_002,
            "schemas/Waiver.schema.json#/required",
        ),
        (
            "CS-WVR-003",
            lambda root: replace_text(
                root,
                "docs/operations/waivers.md",
                "- Tier 2: waivers allowed, max 1 active, HOTL required (policy-level)",
                "- Tier 2: waivers allowed, max 2 active, HOTL required (policy-level)",
            ),
            owner.check_cs_wvr_003,
            "docs/operations/waivers.md#51-limits-per-tier",
        ),
        (
            "CS-WVR-004",
            lambda root: replace_text(root, "docs/operations/waivers.md", "visible in sealing", "tracked externally"),
            owner.check_cs_wvr_004,
            "docs/operations/waivers.md#15-waivers-must-be-visible-in-sealing",
        ),
        (
            "CS-WVR-005",
            lambda root: replace_text(
                root,
                "gates/GATE_Q.md",
                "### Q-DOC-001 — doc_impact.required_paths format validation (if present)",
                "### Q-DOC-001 — waiver doc_impact.required_paths format validation (if present)",
            ),
            owner.check_cs_wvr_005,
            "gates/GATE_Q.md#q-doc-002--doc_impact-tier-enforcement--note-on-empty",
        ),
    ],
)
def test_waivers_owner_invariants_fail_closed_on_owner_derived_mutations(
    tmp_path: Path,
    invariant_id: str,
    mutate,
    check,
    expected_fragment: str,
) -> None:
    root = build_owner_family_repo(tmp_path, "waivers")
    mutate(root)
    assert_invariant_fails(root, invariant_id, check, expected_fragment)
