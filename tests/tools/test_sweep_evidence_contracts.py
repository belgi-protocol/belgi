from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers.consistency_owner_fixtures import (
    assert_invariant_fails,
    assert_invariants_pass,
    build_repo_fixture,
    mutate_json,
    replace_text,
)
from tools._sweep.invariants import evidence as owner

pytestmark = pytest.mark.repo_local

def _evidence_read_relpaths() -> tuple[str, ...]:
    """Exact union of files read by CS-EV-001..005."""

    return (
        "CANONICALS.md",
        "schemas/EvidenceManifest.schema.json",
        "schemas/SealManifest.schema.json",
        "gates/GATE_Q.md",
        "gates/GATE_R.md",
        "tiers/tier-packs.md",
        "docs/operations/cli.md",
        "docs/operations/evidence-bundles.md",
        "docs/operations/running-belgi.md",
        "belgi/templates/DocsCompiler.template.md",
    )


def build_evidence_repo(tmp_path: Path) -> Path:
    return build_repo_fixture(tmp_path, "evidence", patterns=_evidence_read_relpaths())


def test_evidence_owner_invariants_pass_on_owner_derived_repo(tmp_path: Path) -> None:
    root = build_evidence_repo(tmp_path)
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
    root = build_evidence_repo(tmp_path)
    mutate(root)
    assert_invariant_fails(root, invariant_id, check, expected_fragment)
