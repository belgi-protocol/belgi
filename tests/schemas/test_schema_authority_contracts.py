from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.helpers.repo_imports import reset_repo_local_imports

reset_repo_local_imports("belgi", "chain")

from belgi.core.hash import sha256_bytes
from belgi.core.schema import validate_schema
from belgi.protocol.pack import get_builtin_protocol_context
from chain.logic.tolerances import load_locked_tolerances
from chain.logic.toolchain_set import load_locked_toolchain_set


def _write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )


def _base_intent() -> dict[str, object]:
    return {
        "intent_id": "intent-001",
        "title": "Test intent",
        "goal": "Exercise schema truth.",
        "scope": {
            "allowed_dirs": ["src/"],
            "forbidden_dirs": [],
        },
        "acceptance": {
            "success_criteria": ["Criterion 1"],
        },
        "tier": {
            "tier_pack_id": "tier-0",
        },
        "doc_impact": {
            "required_paths": [],
            "note_on_empty": "No docs update required for this schema contract test.",
        },
    }


def _toolchain_locked_spec(repo_root: Path, *, toolchain_obj: dict[str, object]) -> dict[str, object]:
    declared_path = repo_root / "requirements.txt"
    declared_path.write_text("pytest\n", encoding="utf-8", errors="strict", newline="\n")
    toolchain_set_path = repo_root / "out" / "toolchain-set.json"
    _write_json(toolchain_set_path, toolchain_obj)
    return {
        "environment_envelope": {
            "toolchain_set_ref": {
                "id": "env.toolchains",
                "hash": sha256_bytes(toolchain_set_path.read_bytes()),
                "storage_ref": "out/toolchain-set.json",
            }
        }
    }


def _tolerances_locked_spec(repo_root: Path, *, tolerances_obj: dict[str, object]) -> dict[str, object]:
    tolerances_path = repo_root / "out" / "tolerances.json"
    _write_json(tolerances_path, tolerances_obj)
    return {
        "tier": {
            "tolerances_ref": {
                "id": "tier.tolerances",
                "hash": sha256_bytes(tolerances_path.read_bytes()),
                "storage_ref": "out/tolerances.json",
            }
        }
    }


def test_intentspec_schema_rejects_legacy_max_touched_files() -> None:
    schema = get_builtin_protocol_context().read_json("schemas/IntentSpec.schema.json")
    intent = _base_intent()
    scope = dict(intent["scope"])
    scope["max_touched_files"] = 5
    intent["scope"] = scope

    errors = validate_schema(intent, schema, root_schema=schema, path="IntentSpec")

    assert any(err.path == "IntentSpec.scope.max_touched_files" for err in errors)
    assert any("additionalProperties not allowed" in err.message for err in errors)


def test_intentspec_schema_rejects_legacy_max_loc_delta() -> None:
    schema = get_builtin_protocol_context().read_json("schemas/IntentSpec.schema.json")
    intent = _base_intent()
    scope = dict(intent["scope"])
    scope["max_loc_delta"] = 25
    intent["scope"] = scope

    errors = validate_schema(intent, schema, root_schema=schema, path="IntentSpec")

    assert any(err.path == "IntentSpec.scope.max_loc_delta" for err in errors)
    assert any("additionalProperties not allowed" in err.message for err in errors)


def test_toolchain_set_loader_accepts_schema_valid_locked_object(tmp_path: Path) -> None:
    locked_spec = _toolchain_locked_spec(
        tmp_path,
        toolchain_obj={
            "schema_version": "1.0.0",
            "toolchain_set_id": "env.toolchains",
            "refs": [{"id": "deps.requirements", "path": "requirements.txt", "kind": "lockfile"}],
        },
    )

    loaded = load_locked_toolchain_set(repo_root=tmp_path, locked_spec=locked_spec)

    assert loaded.toolchain_set_id == "env.toolchains"
    assert [(ref.object_id, ref.path) for ref in loaded.refs] == [("deps.requirements", "requirements.txt")]


def test_toolchain_set_loader_rejects_schema_invalid_metadata_type(tmp_path: Path) -> None:
    locked_spec = _toolchain_locked_spec(
        tmp_path,
        toolchain_obj={
            "schema_version": "1.0.0",
            "toolchain_set_id": "env.toolchains",
            "refs": [{"id": "deps.requirements", "path": "requirements.txt", "kind": 7}],
        },
    )

    with pytest.raises(ValueError, match="ToolchainSet schema validation failed"):
        load_locked_toolchain_set(repo_root=tmp_path, locked_spec=locked_spec)


def test_tolerances_loader_accepts_schema_valid_locked_object(tmp_path: Path) -> None:
    locked_spec = _tolerances_locked_spec(
        tmp_path,
        tolerances_obj={
            "schema_version": "1.0.0",
            "tier_id": "tier-0",
            "scope_budgets": {
                "max_touched_files": 50,
                "max_loc_delta": 5000,
            },
        },
    )

    loaded = load_locked_tolerances(repo_root=tmp_path, locked_spec=locked_spec)

    assert loaded.tier_id == "tier-0"
    assert loaded.max_touched_files == 50
    assert loaded.max_loc_delta == 5000


def test_tolerances_loader_rejects_schema_invalid_additional_property(tmp_path: Path) -> None:
    locked_spec = _tolerances_locked_spec(
        tmp_path,
        tolerances_obj={
            "schema_version": "1.0.0",
            "tier_id": "tier-0",
            "scope_budgets": {
                "max_touched_files": 50,
                "max_loc_delta": 5000,
            },
            "owner": "ops",
        },
    )

    with pytest.raises(ValueError, match="Tolerances schema validation failed"):
        load_locked_tolerances(repo_root=tmp_path, locked_spec=locked_spec)
