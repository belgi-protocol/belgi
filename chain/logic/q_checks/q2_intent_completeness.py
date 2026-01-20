from __future__ import annotations

from chain.logic.base import CheckResult

from .context import QCheckContext


def run(ctx: QCheckContext) -> list[CheckResult]:
    """Q2 — Intent completeness (reject vague P at Q)."""

    if ctx.locked_spec is None:
        return [
            CheckResult(
                check_id="Q2",
                status="FAIL",
                message="LockedSpec missing/invalid; cannot evaluate intent completeness.",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-INTENT-INSUFFICIENT",
                remediation_next_instruction="Do amend intent to make scope and success criteria unambiguous then re-run Q.",
            )
        ]

    intent = ctx.locked_spec.get("intent")
    if not isinstance(intent, dict):
        intent = {}

    required_fields = ["intent_id", "title", "narrative", "scope", "success_criteria"]
    empty = [k for k in required_fields if not isinstance(intent.get(k), str) or not str(intent.get(k)).strip()]

    constraints = ctx.locked_spec.get("constraints")
    if not isinstance(constraints, dict):
        constraints = {}

    allowed_paths = constraints.get("allowed_paths")
    invariants = ctx.locked_spec.get("invariants")

    problems: list[str] = []
    if empty:
        problems.append("empty intent fields: " + ", ".join(empty))
    if not isinstance(allowed_paths, list) or len(allowed_paths) == 0:
        problems.append("constraints.allowed_paths is empty")
    if not isinstance(invariants, list) or len(invariants) == 0:
        problems.append("invariants is empty")

    if problems:
        return [
            CheckResult(
                check_id="Q2",
                status="FAIL",
                message="; ".join(problems),
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-INTENT-INSUFFICIENT",
                remediation_next_instruction="Do amend intent to make scope and success criteria unambiguous then re-run Q.",
            )
        ]

    return [
        CheckResult(
            check_id="Q2",
            status="PASS",
            message="Q2 satisfied: intent fields present, constraints.allowed_paths non-empty, invariants non-empty.",
            pointers=[str(ctx.locked_spec_path)],
        )
    ]
