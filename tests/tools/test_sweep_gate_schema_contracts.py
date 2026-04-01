from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers.consistency_owner_fixtures import (
    assert_invariant_fails,
    assert_invariants_pass,
    build_repo_fixture,
    mutate_json,
    replace_regex,
    replace_text,
)
from tools._sweep.invariants import gate_schema as owner

pytestmark = pytest.mark.repo_local

def _gate_schema_read_relpaths() -> tuple[str, ...]:
    """Exact union of files read by CS-GS-001..005, CS-GV-001, and CS-LS-001/002."""

    return (
        "schemas/GateVerdict.schema.json",
        "schemas/LockedSpec.schema.json",
        "schemas/ToolchainSet.schema.json",
        "schemas/Tolerances.schema.json",
        "gates/GATE_Q.md",
        "gates/GATE_R.md",
        "gates/failure-taxonomy.md",
        "tiers/tier-packs.md",
        "chain/compiler_c1_intent.py",
        "chain/logic/locked_object_schema.py",
        "chain/logic/toolchain_set.py",
        "chain/logic/tolerances.py",
        "chain/logic/q_checks/q4_constraints_present.py",
        "chain/logic/q_checks/q5_environment_envelope.py",
        "chain/logic/r_checks/r2_scope_budgets.py",
        "docs/operations/cli.md",
        "docs/operations/running-belgi.md",
    )


def build_gate_schema_repo(tmp_path: Path) -> Path:
    return build_repo_fixture(tmp_path, "gate_schema", patterns=_gate_schema_read_relpaths())


def test_gate_schema_owner_invariants_pass_on_owner_derived_repo(tmp_path: Path) -> None:
    root = build_gate_schema_repo(tmp_path)
    assert_invariants_pass(
        root,
        [
            ("CS-GS-001", owner.check_cs_gs_001),
            ("CS-GS-002", owner.check_cs_gs_002),
            ("CS-GS-003", owner.check_cs_gs_003),
            ("CS-GS-004", owner.check_cs_gs_004),
            ("CS-GS-005", owner.check_cs_gs_005),
            ("CS-GV-001", owner.check_cs_gv_001),
            ("CS-LS-001", owner.check_cs_ls_001),
            ("CS-LS-002", owner.check_cs_ls_002),
        ],
    )


@pytest.mark.parametrize(
    ("invariant_id", "mutate", "check", "expected_fragment"),
    [
        (
            "CS-GS-001",
            lambda root: replace_text(root, "gates/GATE_Q.md", "failure_category = null", "failure_category = maybe"),
            owner.check_cs_gs_001,
            "gates/GATE_Q.md#31-gateverdict-gate_id--q",
        ),
        (
            "CS-GS-002",
            lambda root: mutate_json(
                root,
                "schemas/GateVerdict.schema.json",
                lambda payload: payload["properties"]["remediation"]["properties"]["next_instruction"].__setitem__("pattern", "^Do nothing$"),
            ),
            owner.check_cs_gs_002,
            "schemas/GateVerdict.schema.json#/properties/remediation/properties/next_instruction/pattern",
        ),
        (
            "CS-GS-003",
            lambda root: replace_regex(
                root,
                "gates/failure-taxonomy.md",
                r"(?m)^\s*-\s*category_id:\s*`?(F[QR]-[A-Z0-9_.-]+)`?\s*$",
                "- category_id: `BROKEN-CATEGORY-ID`",
            ),
            owner.check_cs_gs_003,
            "gates/failure-taxonomy.md#1-category-ids-stable",
        ),
        (
            "CS-GS-004",
            lambda root: mutate_json(
                root,
                "schemas/LockedSpec.schema.json",
                lambda payload: payload["properties"]["doc_impact"]["properties"].pop("note_on_empty"),
            ),
            owner.check_cs_gs_004,
            "schemas/LockedSpec.schema.json#/properties/doc_impact",
        ),
        (
            "CS-GS-005",
            lambda root: mutate_json(
                root,
                "schemas/LockedSpec.schema.json",
                lambda payload: payload["properties"].pop("doc_impact"),
            ),
            owner.check_cs_gs_005,
            "schemas/LockedSpec.schema.json#/properties",
        ),
        (
            "CS-GV-001",
            lambda root: mutate_json(
                root,
                "schemas/GateVerdict.schema.json",
                lambda payload: payload["required"].remove("run_id"),
            ),
            owner.check_cs_gv_001,
            "schemas/GateVerdict.schema.json#/required",
        ),
        (
            "CS-LS-001",
            lambda root: mutate_json(
                root,
                "schemas/LockedSpec.schema.json",
                lambda payload: payload["$defs"]["RepoRelPathPrefix"].__setitem__(
                    "pattern",
                    payload["$defs"]["RepoRelPathPrefix"]["pattern"].replace("(?!.*\\*)", ""),
                ),
            ),
            owner.check_cs_ls_001,
            "schemas/LockedSpec.schema.json#/$defs/RepoRelPathPrefix",
        ),
        (
            "CS-LS-002",
            lambda root: mutate_json(
                root,
                "schemas/LockedSpec.schema.json",
                lambda payload: payload["properties"]["environment_envelope"]["properties"]["toolchain_set_ref"].__setitem__(
                    "$ref", "#/$defs/NotObjectRef"
                ),
            ),
            owner.check_cs_ls_002,
            "schemas/LockedSpec.schema.json",
        ),
    ],
)
def test_gate_schema_owner_invariants_fail_closed_on_owner_derived_mutations(
    tmp_path: Path,
    invariant_id: str,
    mutate,
    check,
    expected_fragment: str,
) -> None:
    root = build_gate_schema_repo(tmp_path)
    mutate(root)
    assert_invariant_fails(root, invariant_id, check, expected_fragment)
