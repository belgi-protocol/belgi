from __future__ import annotations

from chain.logic.base import CheckResult

from .context import QCheckContext


def run(ctx: QCheckContext) -> list[CheckResult]:
    """Q3 — Invariants compiled and structurally usable."""

    if ctx.locked_spec is None:
        return [
            CheckResult(
                check_id="Q3",
                status="FAIL",
                message="LockedSpec missing/invalid; cannot evaluate invariants.",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-INVARIANTS-EMPTY",
                remediation_next_instruction="Do update C1 compilation so invariants are non-empty and specific then re-run Q.",
            )
        ]

    invs = ctx.locked_spec.get("invariants")
    if not isinstance(invs, list) or len(invs) == 0:
        return [
            CheckResult(
                check_id="Q3",
                status="FAIL",
                message="LockedSpec.invariants is missing/empty.",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-INVARIANTS-EMPTY",
                remediation_next_instruction="Do update C1 compilation so invariants are non-empty and specific then re-run Q.",
            )
        ]

    ids: list[str] = []
    bad = False
    for inv in invs:
        if not isinstance(inv, dict):
            bad = True
            continue

        inv_id = inv.get("id")
        desc = inv.get("description")
        sev = inv.get("severity")

        if not isinstance(inv_id, str) or not inv_id.strip():
            bad = True
        if not isinstance(desc, str) or not desc.strip():
            bad = True
        if not isinstance(sev, str) or not sev.strip():
            bad = True

        if isinstance(inv_id, str):
            ids.append(inv_id)

    if bad or len(set(ids)) != len(ids):
        return [
            CheckResult(
                check_id="Q3",
                status="FAIL",
                message="Invariants missing/invalid or invariant IDs are not unique.",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-INVARIANTS-EMPTY",
                remediation_next_instruction="Do update C1 compilation so invariants are non-empty and specific then re-run Q.",
            )
        ]

    return [
        CheckResult(
            check_id="Q3",
            status="PASS",
            message="Q3 satisfied: invariants are present and structurally valid with unique ids.",
            pointers=[str(ctx.locked_spec_path)],
        )
    ]
