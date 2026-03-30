from __future__ import annotations

import json
from pathlib import Path

from tests.helpers.repo_imports import REPO_ROOT, reset_repo_local_imports

reset_repo_local_imports("belgi")

from belgi.core.schema import validate_schema
from chain.logic.tier_packs import (
    load_tier_admission_policy,
    load_tier_params,
    supported_tier_ids,
    tier_requires_hotl,
)


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8", errors="strict"))


def _synthetic_tier_packs_json(
    *,
    waiver_allowed: bool,
    waiver_max_active_waivers: int,
    waiver_requires_hotl: bool,
    adversarial_findings_mode: str = "warn",
    envelope_requires_attestation: bool = True,
    envelope_attestation_signature_required: bool | None = False,
    envelope_pinned_toolchain_refs_required: bool | None = True,
) -> str:
    envelope_policy: dict[str, object] = {
        "requires_attestation": envelope_requires_attestation,
    }
    if envelope_attestation_signature_required is not None:
        envelope_policy["attestation_signature_required"] = envelope_attestation_signature_required
    if envelope_pinned_toolchain_refs_required is not None:
        envelope_policy["pinned_toolchain_refs_required"] = envelope_pinned_toolchain_refs_required

    return json.dumps(
        {
            "schema_version": "1.0.0",
            "tier_ids": ["tier-x"],
            "tiers": {
                "tier-x": {
                    "required_evidence_kinds": [],
                    "required_evidence_kinds_q": [],
                    "doc_impact_required": False,
                    "command_log_mode": "strings",
                    "scope_budgets": {
                        "max_touched_files": 1,
                        "max_loc_delta": 2,
                        "forbidden_paths_enforcement": "strict",
                    },
                    "test_policy": {
                        "required": True,
                        "allowed_skips": False,
                    },
                    "waiver_policy": {
                        "allowed": waiver_allowed,
                        "max_active_waivers": waiver_max_active_waivers,
                        "requires_HOTL": waiver_requires_hotl,
                    },
                    "adversarial_policy": {"findings_mode": adversarial_findings_mode},
                    "envelope_policy": envelope_policy,
                }
            },
        },
        indent=2,
        sort_keys=True,
    )


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

    q4_params = None
    q5_params = None
    r2_params = None
    r7_params = None
    for idx, entry in enumerate(gate_map):
        assert isinstance(entry, dict), f"gate_parameter_map[{idx}] must be an object"
        gate_check_id = entry.get("gate_check_id")
        params = entry.get("tier_params_read", [])
        assert isinstance(params, list), f"gate_parameter_map[{idx}].tier_params_read must be a list"
        if gate_check_id == "Q4":
            q4_params = params
        if gate_check_id == "Q5":
            q5_params = params
        if gate_check_id == "R2":
            r2_params = params
        if gate_check_id == "R7":
            r7_params = params

    assert q4_params == ["scope_budgets.max_touched_files", "scope_budgets.max_loc_delta"]
    assert q5_params == ["envelope_policy.pinned_toolchain_refs_required"]
    assert r2_params == []
    assert r7_params == ["command_log_mode"]


def test_waiver_policy_note_keeps_hotl_separate() -> None:
    obj = _load_json(REPO_ROOT / "tiers" / "tier-packs.json")
    waiver_note = obj["parameter_definitions"]["waiver_policy"]["v1_enforcement_note"]
    assert isinstance(waiver_note, str)
    assert "`Waiver` remains the sole waiver authorization artifact." in waiver_note
    assert "HOTL is a separate control artifact." in waiver_note
    assert "`hotl_approval` artifact in `EvidenceManifest.artifacts[]`." in waiver_note


def test_tier_params_loader_maps_waiver_policy_from_json_ssot() -> None:
    loaded = load_tier_params(
        _synthetic_tier_packs_json(
            waiver_allowed=False,
            waiver_max_active_waivers=0,
            waiver_requires_hotl=True,
        ),
        "tier-x",
    )
    assert loaded.params is not None, loaded.parse_error
    assert loaded.params.waiver_policy_allowed is False
    assert loaded.params.waiver_policy_max_active_waivers == 0
    assert loaded.params.waiver_policy_requires_hotl == "yes"


def test_supported_tier_ids_use_canonical_json_ssot() -> None:
    canonical_json = (REPO_ROOT / "tiers" / "tier-packs.json").read_text(encoding="utf-8", errors="strict")
    assert supported_tier_ids(canonical_json) == ("tier-0", "tier-1", "tier-2", "tier-3")


def test_tier_admission_policy_rejects_generated_markdown_view() -> None:
    tiers_md = (REPO_ROOT / "tiers" / "tier-packs.md").read_text(encoding="utf-8", errors="strict")
    loaded = load_tier_admission_policy(tiers_md)
    assert loaded.tier_ids is None
    assert loaded.hotl_required_tier_ids is None
    assert isinstance(loaded.parse_error, str)
    assert "canonical JSON SSOT" in loaded.parse_error


def test_hotl_requirement_is_loaded_from_json_policy() -> None:
    canonical_json = (REPO_ROOT / "tiers" / "tier-packs.json").read_text(encoding="utf-8", errors="strict")
    assert tier_requires_hotl(canonical_json, "tier-0") is False
    assert tier_requires_hotl(canonical_json, "tier-1") is False
    assert tier_requires_hotl(canonical_json, "tier-2") is True
    assert tier_requires_hotl(canonical_json, "tier-3") is True


def test_tier_params_loader_rejects_generated_markdown_view() -> None:
    tiers_md = (REPO_ROOT / "tiers" / "tier-packs.md").read_text(encoding="utf-8", errors="strict")

    loaded = load_tier_params(tiers_md, "tier-0")
    assert loaded.params is None
    assert isinstance(loaded.parse_error, str)
    assert (
        "tier params require canonical JSON SSOT "
        "(tiers/tier-packs.json); markdown generated view is not runtime authority"
    ) in loaded.parse_error
    assert "input is not valid JSON:" in loaded.parse_error


def test_tier_params_loader_maps_findings_mode_from_json_ssot() -> None:
    loaded = load_tier_params(
        _synthetic_tier_packs_json(
            waiver_allowed=False,
            waiver_max_active_waivers=0,
            waiver_requires_hotl=True,
            adversarial_findings_mode="fail",
        ),
        "tier-x",
    )
    assert loaded.params is not None, loaded.parse_error
    assert loaded.params.adversarial_policy_findings_mode == "fail"


def test_tier_params_loader_fails_closed_when_findings_mode_is_missing_in_json_ssot() -> None:
    obj = json.loads(
        _synthetic_tier_packs_json(
            waiver_allowed=False,
            waiver_max_active_waivers=0,
            waiver_requires_hotl=True,
        )
    )
    tier_obj = obj["tiers"]["tier-x"]
    adversarial_policy = tier_obj["adversarial_policy"]
    assert isinstance(adversarial_policy, dict)
    adversarial_policy.pop("findings_mode")

    loaded = load_tier_params(json.dumps(obj, indent=2, sort_keys=True), "tier-x")
    assert loaded.params is None
    assert loaded.parse_error == "adversarial_policy.findings_mode missing/invalid"


def test_tier_params_loader_maps_explicit_envelope_policy_from_json_ssot() -> None:
    loaded = load_tier_params(
        _synthetic_tier_packs_json(
            waiver_allowed=False,
            waiver_max_active_waivers=0,
            waiver_requires_hotl=True,
            envelope_requires_attestation=True,
            envelope_attestation_signature_required=True,
            envelope_pinned_toolchain_refs_required=True,
        ),
        "tier-x",
    )
    assert loaded.params is not None, loaded.parse_error
    assert loaded.params.envelope_policy_requires_attestation == "yes"
    assert loaded.params.envelope_policy_attestation_signature_required == "yes"
    assert loaded.params.envelope_policy_pinned_toolchain_refs_required == "yes"


def test_tier_params_loader_preserves_optional_envelope_policy_defaults_from_json_ssot() -> None:
    loaded = load_tier_params(
        _synthetic_tier_packs_json(
            waiver_allowed=False,
            waiver_max_active_waivers=0,
            waiver_requires_hotl=True,
            envelope_requires_attestation=True,
            envelope_attestation_signature_required=None,
            envelope_pinned_toolchain_refs_required=None,
        ),
        "tier-x",
    )
    assert loaded.params is not None, loaded.parse_error
    assert loaded.params.envelope_policy_requires_attestation == "yes"
    assert loaded.params.envelope_policy_attestation_signature_required == "no"
    assert loaded.params.envelope_policy_pinned_toolchain_refs_required == "yes"
