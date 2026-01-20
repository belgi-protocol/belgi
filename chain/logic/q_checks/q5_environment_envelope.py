from __future__ import annotations

from chain.logic.base import CheckResult

from .context import QCheckContext


def run(ctx: QCheckContext) -> list[CheckResult]:
    """Q5 — Environment Envelope declared and lockable."""

    if ctx.locked_spec is None:
        return [
            CheckResult(
                check_id="Q5",
                status="FAIL",
                message="LockedSpec missing/invalid; cannot validate environment_envelope.",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-ENVELOPE-MISSING",
                remediation_next_instruction="Do declare a complete environment_envelope (including pinned_toolchain_refs) then re-run Q.",
            )
        ]

    env = ctx.locked_spec.get("environment_envelope")
    if not isinstance(env, dict):
        return [
            CheckResult(
                check_id="Q5",
                status="FAIL",
                message="LockedSpec.environment_envelope missing/invalid.",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-ENVELOPE-MISSING",
                remediation_next_instruction="Do declare a complete environment_envelope (including pinned_toolchain_refs) then re-run Q.",
            )
        ]

    missing = [k for k in ("id", "description", "expected_runner") if not isinstance(env.get(k), str) or not str(env.get(k)).strip()]
    if missing:
        return [
            CheckResult(
                check_id="Q5",
                status="FAIL",
                message="environment_envelope missing required field(s): " + ", ".join(missing),
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-ENVELOPE-MISSING",
                remediation_next_instruction="Do declare a complete environment_envelope (including pinned_toolchain_refs) then re-run Q.",
            )
        ]

    pinned_required = ctx.tier_params.get("envelope_policy.pinned_toolchain_refs_required")
    pinned = env.get("pinned_toolchain_refs")

    if pinned_required == "yes":
        if not isinstance(pinned, list) or len(pinned) == 0:
            return [
                CheckResult(
                    check_id="Q5",
                    status="FAIL",
                    message="pinned_toolchain_refs required by tier but missing/empty.",
                    pointers=[str(ctx.locked_spec_path)],
                    category="FQ-ENVELOPE-MISSING",
                    remediation_next_instruction="Do declare a complete environment_envelope (including pinned_toolchain_refs) then re-run Q.",
                )
            ]

    return [
        CheckResult(
            check_id="Q5",
            status="PASS",
            message="Q5 satisfied: environment_envelope declared and lockable.",
            pointers=[str(ctx.locked_spec_path)],
        )
    ]
