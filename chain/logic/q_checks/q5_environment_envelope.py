from __future__ import annotations

from chain.logic.base import CheckResult
from chain.logic.toolchain_set import load_locked_toolchain_set

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
                remediation_next_instruction="Do declare a complete environment_envelope (including toolchain_set_ref and pinned_toolchain_refs) then re-run Q.",
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
                remediation_next_instruction="Do declare a complete environment_envelope (including toolchain_set_ref and pinned_toolchain_refs) then re-run Q.",
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
                remediation_next_instruction="Do declare a complete environment_envelope (including toolchain_set_ref and pinned_toolchain_refs) then re-run Q.",
            )
        ]

    try:
        locked_toolchain_set = load_locked_toolchain_set(
            repo_root=ctx.repo_root,
            locked_spec=ctx.locked_spec,
            schema=ctx.schemas.get("ToolchainSet"),
        )
    except ValueError as e:
        return [
            CheckResult(
                check_id="Q5",
                status="FAIL",
                message=f"Locked ToolchainSet invalid: {e}",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-ENVELOPE-MISSING",
                remediation_next_instruction=(
                    "Do declare a valid ToolchainSet object and a complete environment_envelope "
                    "(including toolchain_set_ref and pinned_toolchain_refs) then re-run Q."
                ),
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
                    remediation_next_instruction=(
                        "Do declare a valid ToolchainSet object and a complete environment_envelope "
                        "(including toolchain_set_ref and pinned_toolchain_refs) then re-run Q."
                    ),
                )
            ]

    if not isinstance(pinned, list):
        return [
            CheckResult(
                check_id="Q5",
                status="FAIL",
                message="pinned_toolchain_refs missing/invalid.",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-ENVELOPE-MISSING",
                remediation_next_instruction=(
                    "Do declare a valid ToolchainSet object and a complete environment_envelope "
                    "(including toolchain_set_ref and pinned_toolchain_refs) then re-run Q."
                ),
            )
        ]

    expected_ids = ["toolchain.main", *[ref.object_id for ref in locked_toolchain_set.refs]]
    actual_ids: list[str] = []
    actual_operator_pairs: list[tuple[str, str]] = []
    for idx, entry in enumerate(pinned):
        if not isinstance(entry, dict):
            return [
                CheckResult(
                    check_id="Q5",
                    status="FAIL",
                    message=f"pinned_toolchain_refs[{idx}] missing/invalid.",
                    pointers=[str(ctx.locked_spec_path)],
                    category="FQ-ENVELOPE-MISSING",
                    remediation_next_instruction=(
                        "Do declare a valid ToolchainSet object and a complete environment_envelope "
                        "(including toolchain_set_ref and pinned_toolchain_refs) then re-run Q."
                    ),
                )
            ]
        ref_id = entry.get("id")
        if not isinstance(ref_id, str) or not ref_id.strip():
            return [
                CheckResult(
                    check_id="Q5",
                    status="FAIL",
                    message=f"pinned_toolchain_refs[{idx}].id missing/invalid.",
                    pointers=[str(ctx.locked_spec_path)],
                    category="FQ-ENVELOPE-MISSING",
                    remediation_next_instruction=(
                        "Do declare a valid ToolchainSet object and a complete environment_envelope "
                        "(including toolchain_set_ref and pinned_toolchain_refs) then re-run Q."
                    ),
                )
            ]
        actual_ids.append(ref_id.strip())
        if idx > 0:
            storage_ref = entry.get("storage_ref")
            if not isinstance(storage_ref, str) or not storage_ref.strip():
                return [
                    CheckResult(
                        check_id="Q5",
                        status="FAIL",
                        message=f"pinned_toolchain_refs[{idx}].storage_ref missing/invalid.",
                        pointers=[str(ctx.locked_spec_path)],
                        category="FQ-ENVELOPE-MISSING",
                        remediation_next_instruction=(
                            "Do declare a valid ToolchainSet object and a complete environment_envelope "
                            "(including toolchain_set_ref and pinned_toolchain_refs) then re-run Q."
                        ),
                    )
                ]
            actual_operator_pairs.append((ref_id.strip(), storage_ref.strip()))

    if actual_ids != expected_ids:
        return [
            CheckResult(
                check_id="Q5",
                status="FAIL",
                message=(
                    "pinned_toolchain_refs does not match locked ToolchainSet authority "
                    f"(expected ids {expected_ids}, got {actual_ids})."
                ),
                pointers=[str(ctx.locked_spec_path), locked_toolchain_set.storage_ref],
                category="FQ-ENVELOPE-MISSING",
                remediation_next_instruction=(
                    "Do rebuild pinned_toolchain_refs from toolchain_set_ref plus built-in toolchain.main, then re-run Q."
                ),
            )
        ]

    expected_operator_pairs = [(ref.object_id, ref.path) for ref in locked_toolchain_set.refs]
    if actual_operator_pairs != expected_operator_pairs:
        return [
            CheckResult(
                check_id="Q5",
                status="FAIL",
                message=(
                    "pinned_toolchain_refs operator refs do not match locked ToolchainSet paths "
                    f"(expected {expected_operator_pairs}, got {actual_operator_pairs})."
                ),
                pointers=[str(ctx.locked_spec_path), locked_toolchain_set.storage_ref],
                category="FQ-ENVELOPE-MISSING",
                remediation_next_instruction=(
                    "Do rebuild pinned_toolchain_refs from toolchain_set_ref plus built-in toolchain.main, then re-run Q."
                ),
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
