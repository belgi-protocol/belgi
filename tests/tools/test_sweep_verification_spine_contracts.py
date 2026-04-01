from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers.consistency_owner_fixtures import (
    assert_invariant_fails,
    assert_invariants_pass,
    build_repo_fixture,
    mutate_json,
    remove_file,
    replace_text_in_markdown_section,
)
from tools._sweep.invariants import verification_spine as owner

pytestmark = pytest.mark.repo_local

def _verification_spine_read_relpaths() -> tuple[str, ...]:
    """Exact union of files read by CS-VERIFY_BUNDLE-001, CS-GATE_R-MANDATES-VERIFY_BUNDLE-001, CS-VERIFY_BUNDLE-GATEVERDICT-BINDING-001, and CS-REF-001."""

    return (
        "schemas/LockedSpec.schema.json",
        "schemas/EvidenceManifest.schema.json",
        "schemas/GateVerdict.schema.json",
        "schemas/SealManifest.schema.json",
        "schemas/Waiver.schema.json",
        "gates/GATE_R.md",
        "chain/gate_r_verify.py",
    )


def build_verification_spine_repo(tmp_path: Path) -> Path:
    return build_repo_fixture(tmp_path, "verification_spine", patterns=_verification_spine_read_relpaths())


def test_verification_spine_owner_invariants_pass_on_owner_derived_repo(tmp_path: Path) -> None:
    root = build_verification_spine_repo(tmp_path)
    assert_invariants_pass(
        root,
        [
            ("CS-VERIFY_BUNDLE-001", owner.check_cs_verify_bundle_001),
            ("CS-GATE_R-MANDATES-VERIFY_BUNDLE-001", owner.check_cs_gate_r_mandates_verify_bundle_001),
            ("CS-VERIFY_BUNDLE-GATEVERDICT-BINDING-001", owner.check_cs_verify_bundle_gateverdict_binding_001),
            ("CS-REF-001", owner.check_cs_ref_001),
        ],
    )


@pytest.mark.parametrize(
    ("invariant_id", "mutate", "check", "expected_fragment"),
    [
        (
            "CS-VERIFY_BUNDLE-001",
            lambda root: remove_file(root, "chain/gate_r_verify.py"),
            owner.check_cs_verify_bundle_001,
            "chain/gate_r_verify.py",
        ),
        (
            "CS-GATE_R-MANDATES-VERIFY_BUNDLE-001",
            lambda root: replace_text_in_markdown_section(
                root,
                "gates/GATE_R.md",
                "### 5.2.2 Canonical deterministic verifier (MUST)",
                "chain/gate_r_verify.py",
                "chain/gate_r_verify_missing.py",
            ),
            owner.check_cs_gate_r_mandates_verify_bundle_001,
            "gates/GATE_R.md#522-canonical-deterministic-verifier-must",
        ),
        (
            "CS-VERIFY_BUNDLE-GATEVERDICT-BINDING-001",
            lambda root: replace_text_in_markdown_section(
                root,
                "gates/GATE_R.md",
                "### 5.2.2 Canonical deterministic verifier (MUST)",
                "GateVerdict.evidence_manifest_ref",
                "GateVerdict.evidence_manifest_pointer",
            ),
            owner.check_cs_verify_bundle_gateverdict_binding_001,
            "gates/GATE_R.md#522-canonical-deterministic-verifier-must",
        ),
        (
            "CS-REF-001",
            lambda root: mutate_json(
                root,
                "schemas/LockedSpec.schema.json",
                lambda payload: payload["$defs"]["ObjectRef"]["properties"]["storage_ref"].__setitem__(
                    "pattern",
                    payload["$defs"]["ObjectRef"]["properties"]["storage_ref"]["pattern"].replace("(?!.*://)", ""),
                ),
            ),
            owner.check_cs_ref_001,
            "schemas/LockedSpec.schema.json#/$defs/ObjectRef/properties/storage_ref",
        ),
    ],
)
def test_verification_spine_owner_invariants_fail_closed_on_owner_derived_mutations(
    tmp_path: Path,
    invariant_id: str,
    mutate,
    check,
    expected_fragment: str,
) -> None:
    root = build_verification_spine_repo(tmp_path)
    mutate(root)
    assert_invariant_fails(root, invariant_id, check, expected_fragment)
