from __future__ import annotations

import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
for _k in list(sys.modules.keys()):
    if _k == "belgi" or _k.startswith("belgi."):
        del sys.modules[_k]

from belgi.core.schema import validate_schema


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8", errors="strict"))


def test_tier_packs_schema_ref_target_exists() -> None:
    tier_packs_path = REPO_ROOT / "tiers" / "tier-packs.json"
    obj = _load_json(tier_packs_path)

    schema_rel = obj.get("$schema")
    assert isinstance(schema_rel, str) and schema_rel, "tier-packs.json must declare non-empty $schema"

    schema_path = (tier_packs_path.parent / schema_rel).resolve()
    assert schema_path.is_file(), f"declared schema target does not exist: {schema_path}"
    assert schema_path == (REPO_ROOT / "schemas" / "TierPacks.schema.json").resolve()


def test_tier_packs_json_validates_against_schema() -> None:
    schema = _load_json(REPO_ROOT / "schemas" / "TierPacks.schema.json")
    obj = _load_json(REPO_ROOT / "tiers" / "tier-packs.json")
    errs = validate_schema(obj, schema, root_schema=schema, path="TierPacks")
    assert errs == [], [f"{e.path}: {e.message}" for e in errs[:10]]


def test_builtin_tier_packs_json_validates_against_builtin_schema() -> None:
    schema = _load_json(REPO_ROOT / "belgi" / "_protocol_packs" / "v1" / "schemas" / "TierPacks.schema.json")
    obj = _load_json(REPO_ROOT / "belgi" / "_protocol_packs" / "v1" / "tiers" / "tier-packs.json")
    errs = validate_schema(obj, schema, root_schema=schema, path="TierPacks")
    assert errs == [], [f"{e.path}: {e.message}" for e in errs[:10]]


def test_tier_packs_do_not_declare_test_policy_flaky_handling() -> None:
    obj = _load_json(REPO_ROOT / "tiers" / "tier-packs.json")

    test_policy_def = obj.get("parameter_definitions", {}).get("test_policy", {})
    fields = test_policy_def.get("fields", {})
    assert isinstance(fields, dict)
    assert "flaky_handling" not in fields

    tiers = obj.get("tiers", {})
    assert isinstance(tiers, dict)
    for tier_id, tier_obj in tiers.items():
        assert isinstance(tier_obj, dict)
        tp = tier_obj.get("test_policy", {})
        assert isinstance(tp, dict)
        assert "flaky_handling" not in tp, f"{tier_id} still declares test_policy.flaky_handling"

    rendered = (REPO_ROOT / "tiers" / "tier-packs.md").read_text(encoding="utf-8", errors="strict")
    assert "flaky_handling:" not in rendered


def test_gate_parameter_map_does_not_list_test_policy_flaky_handling() -> None:
    obj = _load_json(REPO_ROOT / "tiers" / "tier-packs.json")
    gate_map = obj.get("gate_parameter_map", [])
    assert isinstance(gate_map, list)

    r5_seen = False
    for idx, entry in enumerate(gate_map):
        assert isinstance(entry, dict), f"gate_parameter_map[{idx}] must be an object"
        params = entry.get("tier_params_read", [])
        assert isinstance(params, list), f"gate_parameter_map[{idx}].tier_params_read must be a list"
        assert "test_policy.flaky_handling" not in params
        if entry.get("gate_check_id") == "R5":
            r5_seen = True
            assert params == ["test_policy.required", "test_policy.allowed_skips", "command_log_mode"]

    assert r5_seen, "gate_parameter_map must include R5"


def test_gate_parameter_map_keeps_pinned_toolchain_refs_owned_by_q5() -> None:
    obj = _load_json(REPO_ROOT / "tiers" / "tier-packs.json")
    gate_map = obj.get("gate_parameter_map", [])
    assert isinstance(gate_map, list)

    q5_params = None
    r7_params = None
    for idx, entry in enumerate(gate_map):
        assert isinstance(entry, dict), f"gate_parameter_map[{idx}] must be an object"
        gate_check_id = entry.get("gate_check_id")
        params = entry.get("tier_params_read", [])
        assert isinstance(params, list), f"gate_parameter_map[{idx}].tier_params_read must be a list"
        if gate_check_id == "Q5":
            q5_params = params
        if gate_check_id == "R7":
            r7_params = params

    assert q5_params == ["envelope_policy.pinned_toolchain_refs_required"]
    assert r7_params == ["command_log_mode"]
