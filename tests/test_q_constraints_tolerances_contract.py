from __future__ import annotations

import json
from pathlib import Path

from tests.helpers.repo_imports import reset_repo_local_imports

REPO_ROOT = Path(__file__).resolve().parents[1]
reset_repo_local_imports("chain")

from belgi.core.hash import sha256_bytes
from chain.logic.q_checks import q4_constraints_present
from chain.logic.q_checks.context import QCheckContext


def _build_ctx(
    *,
    tmp_path: Path,
    constraints: dict[str, object],
    tolerances_obj: dict[str, object],
) -> QCheckContext:
    tmp_path.mkdir(parents=True, exist_ok=True)

    tolerances_path = tmp_path / "out" / "tolerances.json"
    tolerances_path.parent.mkdir(parents=True, exist_ok=True)
    tolerances_path.write_text(
        json.dumps(tolerances_obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    tolerances_bytes = tolerances_path.read_bytes()

    locked_spec = {
        "run_id": "run-q4-001",
        "tier": {
            "tier_id": "tier-1",
            "tolerances_ref": {
                "id": "tier.tolerances",
                "hash": sha256_bytes(tolerances_bytes),
                "storage_ref": "out/tolerances.json",
            },
        },
        "constraints": constraints,
    }

    return QCheckContext(
        repo_root=tmp_path,
        run_id="run-q4-001",
        intent_spec_path=tmp_path / "IntentSpec.core.md",
        locked_spec_path=tmp_path / "LockedSpec.json",
        evidence_manifest_path=tmp_path / "EvidenceManifest.json",
        intent_spec_text="# intent\n",
        yaml_block_count=1,
        yaml_text="intent_id: test",
        intent_obj={"intent_id": "test"},
        yaml_parse_error=None,
        locked_spec=locked_spec,
        evidence_manifest={"schema_version": "1.0.0", "run_id": "run-q4-001", "artifacts": []},
        tiers_md="",
        tier_id="tier-1",
        tier_params={
            "scope_budgets.max_touched_files": 25,
            "scope_budgets.max_loc_delta": 2500,
        },
        schemas={},
    )


def test_q4_accepts_valid_locked_tolerances_object(tmp_path: Path) -> None:
    ctx = _build_ctx(
        tmp_path=tmp_path / "q4_narrow_ok",
        constraints={
            "allowed_paths": ["src/"],
            "forbidden_paths": ["secrets/"],
        },
        tolerances_obj={
            "schema_version": "1.0.0",
            "tier_id": "tier-1",
            "scope_budgets": {
                "max_touched_files": 25,
                "max_loc_delta": 2500,
            },
        },
    )

    results = q4_constraints_present.run(ctx)
    assert len(results) == 1
    assert results[0].status == "PASS"


def test_q4_accepts_locked_tolerances_object_that_tightens_selected_tier_ceilings(tmp_path: Path) -> None:
    ctx = _build_ctx(
        tmp_path=tmp_path / "q4_tighten_ok",
        constraints={
            "allowed_paths": ["src/"],
            "forbidden_paths": ["secrets/"],
        },
        tolerances_obj={
            "schema_version": "1.0.0",
            "tier_id": "tier-1",
            "scope_budgets": {
                "max_touched_files": 10,
                "max_loc_delta": 1000,
            },
        },
    )

    results = q4_constraints_present.run(ctx)
    assert len(results) == 1
    assert results[0].status == "PASS"


def test_q4_rejects_locked_tolerances_object_that_widens_selected_tier_ceilings(tmp_path: Path) -> None:
    ctx = _build_ctx(
        tmp_path=tmp_path / "q4_widen_fail",
        constraints={
            "allowed_paths": ["src/"],
            "forbidden_paths": ["secrets/"],
        },
        tolerances_obj={
            "schema_version": "1.0.0",
            "tier_id": "tier-1",
            "scope_budgets": {
                "max_touched_files": 99,
                "max_loc_delta": 9999,
            },
        },
    )

    results = q4_constraints_present.run(ctx)
    assert len(results) == 1
    assert results[0].status == "FAIL"
    assert results[0].category == "FQ-SCHEMA-LOCKEDSPEC-INVALID"
    assert "widens selected tier ceilings" in results[0].message
    assert "max_touched_files=99" in results[0].message
    assert "max_loc_delta=9999" in results[0].message
    assert "stays within the selected tier ceilings" in str(results[0].remediation_next_instruction or "")


def test_q4_rejects_locked_tolerances_object_with_mismatched_tier_id(tmp_path: Path) -> None:
    ctx = _build_ctx(
        tmp_path=tmp_path / "q4_tier_mismatch",
        constraints={
            "allowed_paths": ["src/"],
            "forbidden_paths": ["secrets/"],
        },
        tolerances_obj={
            "schema_version": "1.0.0",
            "tier_id": "tier-0",
            "scope_budgets": {
                "max_touched_files": 25,
                "max_loc_delta": 2500,
            },
        },
    )

    results = q4_constraints_present.run(ctx)
    assert len(results) == 1
    assert results[0].status == "FAIL"
    assert results[0].category == "FQ-SCHEMA-LOCKEDSPEC-INVALID"
    assert "Locked tolerances object tier mismatch" in results[0].message
