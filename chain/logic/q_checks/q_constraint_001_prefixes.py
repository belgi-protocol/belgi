from __future__ import annotations

from belgi.core.schema import validate_schema
from chain.logic.base import CheckResult

from .context import QCheckContext


def _bad_prefix(prefix: object) -> bool:
    return not isinstance(prefix, str) or not prefix


def run(ctx: QCheckContext) -> list[CheckResult]:
    """Q-CONSTRAINT-001 — Constraints path prefixes are normalized (repo-relative)."""

    if ctx.locked_spec is None:
        return [
            CheckResult(
                check_id="Q-CONSTRAINT-001",
                status="FAIL",
                message="LockedSpec missing/invalid; cannot validate constraint prefixes.",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-SCHEMA-LOCKEDSPEC-INVALID",
                remediation_next_instruction="Do normalize LockedSpec.constraints path prefixes to repo-relative POSIX form then re-run Q.",
            )
        ]

    constraints = ctx.locked_spec.get("constraints")
    if not isinstance(constraints, dict):
        return [
            CheckResult(
                check_id="Q-CONSTRAINT-001",
                status="FAIL",
                message="LockedSpec.constraints missing/invalid.",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-SCHEMA-LOCKEDSPEC-INVALID",
                remediation_next_instruction="Do normalize LockedSpec.constraints path prefixes to repo-relative POSIX form then re-run Q.",
            )
        ]

    locked_schema = ctx.schemas.get("LockedSpec")
    defs = locked_schema.get("$defs") if isinstance(locked_schema, dict) else None
    prefix_schema = defs.get("RepoRelPathPrefix") if isinstance(defs, dict) else None
    if not isinstance(prefix_schema, dict) or not isinstance(locked_schema, dict):
        return [
            CheckResult(
                check_id="Q-CONSTRAINT-001",
                status="FAIL",
                message="Missing LockedSpec RepoRelPathPrefix schema; cannot validate prefixes deterministically.",
                pointers=["schemas/LockedSpec.schema.json"],
                category="FQ-SCHEMA-LOCKEDSPEC-INVALID",
                remediation_next_instruction="Do normalize LockedSpec.constraints path prefixes to repo-relative POSIX form then re-run Q.",
            )
        ]

    allowed = constraints.get("allowed_paths")
    forbidden = constraints.get("forbidden_paths")

    bad: list[str] = []

    if isinstance(allowed, list):
        for i, p in enumerate(allowed):
            if _bad_prefix(p) or validate_schema(p, prefix_schema, root_schema=locked_schema, path="RepoRelPathPrefix"):
                bad.append(f"allowed_paths[{i}]")
    else:
        bad.append("allowed_paths")

    if isinstance(forbidden, list):
        for i, p in enumerate(forbidden):
            if _bad_prefix(p) or validate_schema(p, prefix_schema, root_schema=locked_schema, path="RepoRelPathPrefix"):
                bad.append(f"forbidden_paths[{i}]")
    else:
        bad.append("forbidden_paths")

    if bad:
        return [
            CheckResult(
                check_id="Q-CONSTRAINT-001",
                status="FAIL",
                message="Constraint path prefixes are non-normalized or invalid: " + ", ".join(bad),
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-SCHEMA-LOCKEDSPEC-INVALID",
                remediation_next_instruction="Do normalize LockedSpec.constraints path prefixes to repo-relative POSIX form then re-run Q.",
            )
        ]

    return [
        CheckResult(
            check_id="Q-CONSTRAINT-001",
            status="PASS",
            message="Q-CONSTRAINT-001 satisfied: constraints path prefixes are normalized.",
            pointers=[str(ctx.locked_spec_path)],
        )
    ]
