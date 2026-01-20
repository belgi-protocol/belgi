from __future__ import annotations

from belgi.core.schema import validate_schema
from chain.logic.base import CheckResult

from .context import QCheckContext


def run(ctx: QCheckContext) -> list[CheckResult]:
    """Q-DOC-001 — doc_impact.required_paths format validation (if present)."""

    if ctx.locked_spec is None:
        return [
            CheckResult(
                check_id="Q-DOC-001",
                status="FAIL",
                message="LockedSpec missing/invalid; cannot validate doc_impact.",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-SCHEMA-LOCKEDSPEC-INVALID",
                remediation_next_instruction="Do fix doc_impact.required_paths to be repo-relative and wildcard-free then re-run Q.",
            )
        ]

    doc_impact = ctx.locked_spec.get("doc_impact")
    if doc_impact is None:
        return [
            CheckResult(
                check_id="Q-DOC-001",
                status="PASS",
                message="Q-DOC-001 satisfied: doc_impact absent.",
                pointers=[str(ctx.locked_spec_path)],
            )
        ]

    if not isinstance(doc_impact, dict):
        return [
            CheckResult(
                check_id="Q-DOC-001",
                status="FAIL",
                message="LockedSpec.doc_impact must be an object when present.",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-SCHEMA-LOCKEDSPEC-INVALID",
                remediation_next_instruction="Do fix doc_impact.required_paths to be repo-relative and wildcard-free then re-run Q.",
            )
        ]

    required_paths = doc_impact.get("required_paths")
    if not isinstance(required_paths, list):
        return [
            CheckResult(
                check_id="Q-DOC-001",
                status="FAIL",
                message="doc_impact.required_paths missing/invalid.",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-SCHEMA-LOCKEDSPEC-INVALID",
                remediation_next_instruction="Do fix doc_impact.required_paths to be repo-relative and wildcard-free then re-run Q.",
            )
        ]

    locked_schema = ctx.schemas.get("LockedSpec")
    defs = locked_schema.get("$defs") if isinstance(locked_schema, dict) else None
    prefix_schema = defs.get("RepoRelPathPrefix") if isinstance(defs, dict) else None
    if not isinstance(prefix_schema, dict) or not isinstance(locked_schema, dict):
        return [
            CheckResult(
                check_id="Q-DOC-001",
                status="FAIL",
                message="Missing LockedSpec RepoRelPathPrefix schema; cannot validate doc_impact.required_paths deterministically.",
                pointers=["schemas/LockedSpec.schema.json"],
                category="FQ-SCHEMA-LOCKEDSPEC-INVALID",
                remediation_next_instruction="Do fix doc_impact.required_paths to be repo-relative and wildcard-free then re-run Q.",
            )
        ]

    bad: list[str] = []
    for i, raw in enumerate(required_paths):
        if not isinstance(raw, str) or not raw:
            bad.append(f"required_paths[{i}]")
            continue
        if validate_schema(raw, prefix_schema, root_schema=locked_schema, path="RepoRelPathPrefix"):
            bad.append(f"required_paths[{i}]")

    if bad:
        return [
            CheckResult(
                check_id="Q-DOC-001",
                status="FAIL",
                message="doc_impact.required_paths contains invalid path(s): " + ", ".join(bad),
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-SCHEMA-LOCKEDSPEC-INVALID",
                remediation_next_instruction="Do fix doc_impact.required_paths to be repo-relative and wildcard-free then re-run Q.",
            )
        ]

    return [
        CheckResult(
            check_id="Q-DOC-001",
            status="PASS",
            message="Q-DOC-001 satisfied: doc_impact.required_paths are normalized.",
            pointers=[str(ctx.locked_spec_path)],
        )
    ]
