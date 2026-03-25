from __future__ import annotations

from chain.logic.base import CheckResult
from chain.logic.tolerances import (
    find_scope_budget_widening_against_selected_tier,
    load_locked_tolerances,
)

from .context import QCheckContext


def run(ctx: QCheckContext) -> list[CheckResult]:
    """Q4 — Constraints present (paths + budgets)."""

    if ctx.locked_spec is None:
        return [
            CheckResult(
                check_id="Q4",
                status="FAIL",
                message="LockedSpec missing/invalid; cannot validate constraints.",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-CONSTRAINTS-MISSING",
                remediation_next_instruction="Do add required constraints (missing_field) to LockedSpec then re-run Q.",
            )
        ]

    constraints = ctx.locked_spec.get("constraints")
    if not isinstance(constraints, dict):
        return [
            CheckResult(
                check_id="Q4",
                status="FAIL",
                message="LockedSpec.constraints missing/invalid.",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-CONSTRAINTS-MISSING",
                remediation_next_instruction="Do add required constraints (missing_field) to LockedSpec then re-run Q.",
            )
        ]

    allowed = constraints.get("allowed_paths")
    forbidden_present = "forbidden_paths" in constraints

    missing: list[str] = []
    if not isinstance(allowed, list) or len(allowed) == 0:
        missing.append("allowed_paths")
    if not forbidden_present:
        missing.append("forbidden_paths")

    if missing:
        return [
            CheckResult(
                check_id="Q4",
                status="FAIL",
                message="Constraints missing: " + ", ".join(missing),
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-CONSTRAINTS-MISSING",
                remediation_next_instruction="Do add required constraints (missing_field) to LockedSpec then re-run Q.",
            )
        ]

    try:
        locked_tolerances = load_locked_tolerances(
            repo_root=ctx.repo_root,
            locked_spec=ctx.locked_spec,
            schema=ctx.schemas.get("Tolerances"),
        )
    except ValueError as e:
        return [
            CheckResult(
                check_id="Q4",
                status="FAIL",
                message=f"Locked tolerances object invalid: {e}",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-SCHEMA-LOCKEDSPEC-INVALID",
                remediation_next_instruction=(
                    "Do lock a valid tier.tolerances_ref object for the selected tier that stays within the "
                    "selected tier ceilings, then re-run Q."
                ),
            )
        ]

    tier_obj = ctx.locked_spec.get("tier")
    locked_tier_id = str(tier_obj.get("tier_id") or "") if isinstance(tier_obj, dict) else ""
    if not locked_tier_id or locked_tolerances.tier_id != locked_tier_id:
        return [
            CheckResult(
                check_id="Q4",
                status="FAIL",
                message=(
                    "Locked tolerances object tier mismatch: "
                    f"LockedSpec.tier.tier_id={locked_tier_id or '<missing>'} "
                    f"but tolerances tier_id={locked_tolerances.tier_id}"
                ),
                pointers=[str(ctx.locked_spec_path), locked_tolerances.storage_ref],
                category="FQ-SCHEMA-LOCKEDSPEC-INVALID",
                remediation_next_instruction=(
                    "Do lock a valid tier.tolerances_ref object for the selected tier that stays within the "
                    "selected tier ceilings, then re-run Q."
                ),
            )
        ]

    tier_ceiling_errors = find_scope_budget_widening_against_selected_tier(
        locked_tolerances=locked_tolerances,
        tier_params=ctx.tier_params,
    )
    if tier_ceiling_errors:
        return [
            CheckResult(
                check_id="Q4",
                status="FAIL",
                message="Locked tolerances object widens selected tier ceilings: " + "; ".join(tier_ceiling_errors),
                pointers=[str(ctx.locked_spec_path), locked_tolerances.storage_ref],
                category="FQ-SCHEMA-LOCKEDSPEC-INVALID",
                remediation_next_instruction=(
                    "Do lock a valid tier.tolerances_ref object for the selected tier that stays within the "
                    "selected tier ceilings, then re-run Q."
                ),
            )
        ]

    return [
        CheckResult(
            check_id="Q4",
            status="PASS",
            message=(
                "Q4 satisfied: path constraints are present and the locked tolerances object is valid "
                "for the selected tier ceilings."
            ),
            pointers=[str(ctx.locked_spec_path), locked_tolerances.storage_ref],
        )
    ]
