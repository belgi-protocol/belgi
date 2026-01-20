from __future__ import annotations

from chain.logic.base import CheckResult

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

    return [
        CheckResult(
            check_id="Q4",
            status="PASS",
            message="Q4 satisfied: constraints include allowed_paths and forbidden_paths.",
            pointers=[str(ctx.locked_spec_path)],
        )
    ]
