from __future__ import annotations

from chain.logic.base import CheckResult
from chain.logic.tier_packs import supported_tier_ids

from .context import QCheckContext


def run(ctx: QCheckContext) -> list[CheckResult]:
    """Q7 — Tier ID supported."""

    tier_id = ctx.tier_id
    try:
        known_tier_ids = supported_tier_ids(ctx.tiers_md)
    except Exception as e:
        return [
            CheckResult(
                check_id="Q7",
                status="FAIL",
                message=f"Cannot resolve supported tier IDs from active tier policy: {e}",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-TIER-UNKNOWN",
                remediation_next_instruction="Do restore a valid tier-packs policy then re-run Q.",
            )
        ]

    if tier_id not in known_tier_ids:
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
