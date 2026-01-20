from __future__ import annotations

from typing import Any

from chain.logic.base import CheckResult
from .context import QCheckContext


def _expect_scope_string(intent_obj: dict[str, Any]) -> str:
    scope = intent_obj.get("scope")
    if not isinstance(scope, dict):
        return "allowed_dirs: []; forbidden_dirs: []; max_touched_files: null; max_loc_delta: null"

    allowed = scope.get("allowed_dirs")
    forbidden = scope.get("forbidden_dirs")
    max_touched_files = scope.get("max_touched_files")
    max_loc_delta = scope.get("max_loc_delta")

    def fmt_list(v: Any) -> str:
        if not isinstance(v, list):
            return "[]"
        if any(not isinstance(x, str) for x in v):
            # Schema should prevent this, but fail deterministically if drift occurs.
            return "[INVALID]"
        parts = [x for x in v]
        return "[" + ", ".join(parts) + "]"

    mtf = max_touched_files if isinstance(max_touched_files, int) and not isinstance(max_touched_files, bool) else None
    mld = max_loc_delta if isinstance(max_loc_delta, int) and not isinstance(max_loc_delta, bool) else None

    mtf_s = str(mtf) if mtf is not None else "null"
    mld_s = str(mld) if mld is not None else "null"

    return (
        f"allowed_dirs: {fmt_list(allowed)}; forbidden_dirs: {fmt_list(forbidden)}; "
        f"max_touched_files: {mtf_s}; max_loc_delta: {mld_s}"
    )


def _expect_success_criteria(intent_obj: dict[str, Any]) -> str:
    acceptance = intent_obj.get("acceptance")
    if not isinstance(acceptance, dict):
        return ""
    sc = acceptance.get("success_criteria")
    if not isinstance(sc, list):
        return ""
    if any(not isinstance(x, str) for x in sc):
        return "[INVALID]"
    lines = [f"- {x}" for x in sc if isinstance(x, str)]
    return "\n".join(lines)


def run(ctx: QCheckContext) -> list[CheckResult]:
    if ctx.intent_obj is None or not isinstance(ctx.intent_obj, dict):
        return [
            CheckResult(
                check_id="Q-INTENT-003",
                status="FAIL",
                message="IntentSpec object missing/invalid; cannot apply deterministic mapping rules.",
                pointers=[str(ctx.intent_spec_path)],
                category="FQ-INTENT-INSUFFICIENT",
                remediation_next_instruction="Do fix C1 compilation so LockedSpec fields match the deterministic IntentSpec mapping rules then re-run Q.",
            )
        ]

    if ctx.locked_spec is None or not isinstance(ctx.locked_spec, dict):
        return [
            CheckResult(
                check_id="Q-INTENT-003",
                status="FAIL",
                message="LockedSpec missing/invalid; cannot verify mapping.",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-SCHEMA-LOCKEDSPEC-INVALID",
                remediation_next_instruction="Do fix C1 compilation so LockedSpec fields match the deterministic IntentSpec mapping rules then re-run Q.",
            )
        ]

    locked_intent = ctx.locked_spec.get("intent")
    if not isinstance(locked_intent, dict):
        return [
            CheckResult(
                check_id="Q-INTENT-003",
                status="FAIL",
                message="LockedSpec.intent missing/invalid.",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-SCHEMA-LOCKEDSPEC-INVALID",
                remediation_next_instruction="Do fix C1 compilation so LockedSpec fields match the deterministic IntentSpec mapping rules then re-run Q.",
            )
        ]

    mismatches: list[str] = []

    # 0) Non-authoritative field enforcement (tiers 1-3).
    tier_id = ctx.tier_id
    if tier_id in ("tier-1", "tier-2", "tier-3"):
        proj_ext = ctx.intent_obj.get("project_extension")
        if isinstance(proj_ext, str) and proj_ext.strip():
            return [
                CheckResult(
                    check_id="Q-INTENT-003",
                    status="FAIL",
                    message="IntentSpec.project_extension must be empty for tier-1..3.",
                    pointers=[str(ctx.intent_spec_path)],
                    category="FQ-INTENT-INSUFFICIENT",
                    remediation_next_instruction="Do amend intent to make scope and success criteria unambiguous then re-run Q.",
                )
            ]
        waivers_requested = ctx.intent_obj.get("waivers_requested")
        if isinstance(waivers_requested, list) and len(waivers_requested) > 0:
            return [
                CheckResult(
                    check_id="Q-INTENT-003",
                    status="FAIL",
                    message="IntentSpec.waivers_requested must be empty for tier-1..3.",
                    pointers=[str(ctx.intent_spec_path)],
                    category="FQ-INTENT-INSUFFICIENT",
                    remediation_next_instruction="Do amend intent to make scope and success criteria unambiguous then re-run Q.",
                )
            ]

    # 1) intent field mapping
    if locked_intent.get("intent_id") != ctx.intent_obj.get("intent_id"):
        mismatches.append("LockedSpec.intent.intent_id")
    if locked_intent.get("title") != ctx.intent_obj.get("title"):
        mismatches.append("LockedSpec.intent.title")
    if locked_intent.get("narrative") != ctx.intent_obj.get("goal"):
        mismatches.append("LockedSpec.intent.narrative")

    expected_sc = _expect_success_criteria(ctx.intent_obj)
    if locked_intent.get("success_criteria") != expected_sc:
        mismatches.append("LockedSpec.intent.success_criteria")

    expected_scope = _expect_scope_string(ctx.intent_obj)
    if locked_intent.get("scope") != expected_scope:
        mismatches.append("LockedSpec.intent.scope")

    # 2) constraints mapping
    locked_constraints = ctx.locked_spec.get("constraints")
    if not isinstance(locked_constraints, dict):
        mismatches.append("LockedSpec.constraints")
    else:
        scope = ctx.intent_obj.get("scope")
        if isinstance(scope, dict):
            if locked_constraints.get("allowed_paths") != scope.get("allowed_dirs"):
                mismatches.append("LockedSpec.constraints.allowed_paths")
            if locked_constraints.get("forbidden_paths") != scope.get("forbidden_dirs"):
                mismatches.append("LockedSpec.constraints.forbidden_paths")

            if "max_touched_files" in scope:
                if locked_constraints.get("max_touched_files") != scope.get("max_touched_files"):
                    mismatches.append("LockedSpec.constraints.max_touched_files")
            if "max_loc_delta" in scope:
                if locked_constraints.get("max_loc_delta") != scope.get("max_loc_delta"):
                    mismatches.append("LockedSpec.constraints.max_loc_delta")

    # 3) tier mapping
    locked_tier = ctx.locked_spec.get("tier")
    tier_obj = ctx.intent_obj.get("tier")
    if not isinstance(locked_tier, dict) or not isinstance(tier_obj, dict) or locked_tier.get("tier_id") != tier_obj.get("tier_pack_id"):
        mismatches.append("LockedSpec.tier.tier_id")

    # 4) doc_impact semantics alignment.
    locked_doc = ctx.locked_spec.get("doc_impact")
    intent_doc = ctx.intent_obj.get("doc_impact")
    doc_required = ctx.tier_params.get("doc_impact_required")
    if doc_required is True:
        if locked_doc is None:
            mismatches.append("LockedSpec.doc_impact")
    if locked_doc is not None:
        if locked_doc != intent_doc:
            mismatches.append("LockedSpec.doc_impact")
        if isinstance(locked_doc, dict):
            rp = locked_doc.get("required_paths")
            if isinstance(rp, list) and len(rp) == 0:
                note = locked_doc.get("note_on_empty")
                if not isinstance(note, str) or not note.strip():
                    mismatches.append("LockedSpec.doc_impact.note_on_empty")

    # 4b) publication_intent semantics alignment.
    locked_pub = ctx.locked_spec.get("publication_intent")
    intent_pub = ctx.intent_obj.get("publication_intent")
    if tier_id in ("tier-2", "tier-3") and locked_pub is None:
        mismatches.append("LockedSpec.publication_intent")
    if locked_pub is not None and locked_pub != intent_pub:
        mismatches.append("LockedSpec.publication_intent")

    if mismatches:
        return [
            CheckResult(
                check_id="Q-INTENT-003",
                status="FAIL",
                message=f"LockedSpec does not match deterministic IntentSpec mapping rules: {sorted(mismatches)}",
                pointers=[str(ctx.locked_spec_path), str(ctx.intent_spec_path)],
                category="FQ-SCHEMA-LOCKEDSPEC-INVALID",
                remediation_next_instruction="Do fix C1 compilation so LockedSpec fields match the deterministic IntentSpec mapping rules then re-run Q.",
            )
        ]

    return [
        CheckResult(
            check_id="Q-INTENT-003",
            status="PASS",
            message="LockedSpec fields match deterministic IntentSpec mapping rules.",
            pointers=[str(ctx.locked_spec_path), str(ctx.intent_spec_path)],
        )
    ]
