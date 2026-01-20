from __future__ import annotations

from chain.logic.base import CheckResult

from .context import QCheckContext


def run(ctx: QCheckContext) -> list[CheckResult]:
    """Q-DOC-002 — doc_impact tier enforcement (presence + note-on-empty)."""

    doc_required = ctx.tier_params.get("doc_impact_required")
    if doc_required is None:
        return [
            CheckResult(
                check_id="Q-DOC-002",
                status="FAIL",
                message="Tier doc_impact_required missing; cannot enforce doc_impact contract deterministically.",
                pointers=["tiers/tier-packs.md"],
                category="FQ-SCHEMA-LOCKEDSPEC-INVALID",
                remediation_next_instruction="Do add required doc_impact (including note_on_empty when required_paths is empty) then re-run Q.",
            )
        ]

    if doc_required is False:
        return [
            CheckResult(
                check_id="Q-DOC-002",
                status="PASS",
                message="Q-DOC-002 satisfied: tier does not require doc_impact.",
                pointers=[str(ctx.locked_spec_path)],
            )
        ]

    # doc_required == True
    if ctx.locked_spec is None:
        return [
            CheckResult(
                check_id="Q-DOC-002",
                status="FAIL",
                message="LockedSpec missing/invalid; cannot enforce doc_impact.",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-SCHEMA-LOCKEDSPEC-INVALID",
                remediation_next_instruction="Do add required doc_impact (including note_on_empty when required_paths is empty) then re-run Q.",
            )
        ]

    doc_impact = ctx.locked_spec.get("doc_impact")
    if doc_impact is None:
        return [
            CheckResult(
                check_id="Q-DOC-002",
                status="FAIL",
                message="Tier requires doc_impact but LockedSpec.doc_impact is missing/null.",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-SCHEMA-LOCKEDSPEC-INVALID",
                remediation_next_instruction="Do add required doc_impact (including note_on_empty when required_paths is empty) then re-run Q.",
            )
        ]

    if not isinstance(doc_impact, dict):
        return [
            CheckResult(
                check_id="Q-DOC-002",
                status="FAIL",
                message="LockedSpec.doc_impact must be an object when present.",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-SCHEMA-LOCKEDSPEC-INVALID",
                remediation_next_instruction="Do add required doc_impact (including note_on_empty when required_paths is empty) then re-run Q.",
            )
        ]

    required_paths = doc_impact.get("required_paths")
    if not isinstance(required_paths, list):
        return [
            CheckResult(
                check_id="Q-DOC-002",
                status="FAIL",
                message="doc_impact.required_paths missing/invalid.",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-SCHEMA-LOCKEDSPEC-INVALID",
                remediation_next_instruction="Do add required doc_impact (including note_on_empty when required_paths is empty) then re-run Q.",
            )
        ]

    if len(required_paths) == 0:
        note = doc_impact.get("note_on_empty")
        if not isinstance(note, str) or not note.strip():
            return [
                CheckResult(
                    check_id="Q-DOC-002",
                    status="FAIL",
                    message="doc_impact.required_paths is empty but note_on_empty is missing/empty.",
                    pointers=[str(ctx.locked_spec_path)],
                    category="FQ-SCHEMA-LOCKEDSPEC-INVALID",
                    remediation_next_instruction="Do add required doc_impact (including note_on_empty when required_paths is empty) then re-run Q.",
                )
            ]

    return [
        CheckResult(
            check_id="Q-DOC-002",
            status="PASS",
            message="Q-DOC-002 satisfied: doc_impact present and note_on_empty provided when required_paths empty.",
            pointers=[str(ctx.locked_spec_path)],
        )
    ]
