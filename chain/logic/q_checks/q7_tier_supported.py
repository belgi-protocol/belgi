from __future__ import annotations

from chain.logic.base import CheckResult

from .context import QCheckContext


def run(ctx: QCheckContext) -> list[CheckResult]:
    """Q7 — Tier ID supported."""

    tier_id = ctx.tier_id
    if tier_id not in ("tier-0", "tier-1", "tier-2", "tier-3"):
        return [
            CheckResult(
                check_id="Q7",
                status="FAIL",
                message=f"Unsupported tier_id: {tier_id}",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-TIER-UNKNOWN",
                remediation_next_instruction=f"Do select a supported tier_id ({tier_id}) then re-run Q.",
            )
        ]

    return [
        CheckResult(
            check_id="Q7",
            status="PASS",
            message="Q7 satisfied: tier_id supported.",
            pointers=[str(ctx.locked_spec_path)],
        )
    ]
