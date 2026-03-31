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
from tools._sweep.invariants import evidence as owner

pytestmark = pytest.mark.repo_local


def test_evidence_owner_invariants_pass_on_owner_derived_repo(tmp_path: Path) -> None:
    root = build_owner_family_repo(tmp_path, "evidence")
    assert_invariants_pass(
        root,
        [
            ("CS-EV-001", owner.check_cs_ev_001),
            ("CS-EV-002", owner.check_cs_ev_002),
            ("CS-EV-003", owner.check_cs_ev_003),
            ("CS-EV-004", owner.check_cs_ev_004),
            ("CS-EV-005", owner.check_cs_ev_005),
        ],
    )


@pytest.mark.parametrize(
    ("invariant_id", "mutate", "check", "expected_fragment"),
    [
        (
            "CS-EV-001",
            lambda root: mutate_json(
                root,
                "schemas/EvidenceManifest.schema.json",
                lambda payload: payload["properties"]["artifacts"]["items"]["properties"]["kind"]["enum"].remove("policy_report"),
            ),
            owner.check_cs_ev_001,
            "schemas/EvidenceManifest.schema.json#/properties/artifacts/items/properties/kind/enum",
        ),
        (
            "CS-EV-002",
            lambda root: mutate_json(
                root,
                "schemas/EvidenceManifest.schema.json",
                lambda payload: payload["properties"]["artifacts"]["items"]["properties"]["kind"]["enum"].remove("schema_validation"),
            ),
            owner.check_cs_ev_002,
            "schemas/EvidenceManifest.schema.json#/properties/artifacts/items/properties/kind/enum",
        ),
        (
            "CS-EV-003",
            lambda root: replace_text(root, "gates/GATE_R.md", "required_evidence_kinds", "required_evidence_kindz"),
            owner.check_cs_ev_003,
            "gates/GATE_R.md#4-evidence-sufficiency-rule-deterministic",
        ),
        (
            "CS-EV-004",
            lambda root: replace_text(root, "docs/operations/evidence-bundles.md", "append-only", "mutable"),
            owner.check_cs_ev_004,
            "docs/operations/evidence-bundles.md#evidence-mutability-r-snapshot-and-replay-integrity-normative",
        ),
        (
            "CS-EV-005",
            lambda root: mutate_json(
                root,
                "schemas/SealManifest.schema.json",
                lambda payload: payload["required"].remove("waivers"),
            ),
            owner.check_cs_ev_005,
            "schemas/SealManifest.schema.json#/required",
        ),
    ],
)
def test_evidence_owner_invariants_fail_closed_on_owner_derived_mutations(
    tmp_path: Path,
    invariant_id: str,
    mutate,
    check,
    expected_fragment: str,
) -> None:
    root = build_owner_family_repo(tmp_path, "evidence")
    mutate(root)
    assert_invariant_fails(root, invariant_id, check, expected_fragment)
