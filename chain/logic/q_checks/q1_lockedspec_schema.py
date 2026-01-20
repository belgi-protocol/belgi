from __future__ import annotations

from belgi.core.schema import validate_schema
from chain.logic.base import CheckResult
from .context import QCheckContext


def run(ctx: QCheckContext) -> list[CheckResult]:
    if ctx.locked_spec is None or not isinstance(ctx.locked_spec, dict):
        return [
            CheckResult(
                check_id="Q1",
                status="FAIL",
                message="LockedSpec missing/invalid; cannot validate schema.",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-SCHEMA-LOCKEDSPEC-INVALID",
                remediation_next_instruction="Do fix LockedSpec schema validation errors for missing_field then re-run Q.",
            )
        ]

    schema = ctx.schemas.get("LockedSpec")
    if not isinstance(schema, dict):
        return [
            CheckResult(
                check_id="Q1",
                status="FAIL",
                message="Missing LockedSpec schema; cannot validate deterministically.",
                pointers=["schemas/LockedSpec.schema.json"],
                category="FQ-SCHEMA-LOCKEDSPEC-INVALID",
                remediation_next_instruction="Do fix LockedSpec schema validation errors for missing_field then re-run Q.",
            )
        ]

    errs = validate_schema(ctx.locked_spec, schema, root_schema=schema, path="LockedSpec")
    if errs:
        first = errs[0]
        return [
            CheckResult(
                check_id="Q1",
                status="FAIL",
                message=f"LockedSpec schema invalid at {first.path}: {first.message}",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-SCHEMA-LOCKEDSPEC-INVALID",
                remediation_next_instruction="Do fix LockedSpec schema validation errors for missing_field then re-run Q.",
            )
        ]

    return [
        CheckResult(
            check_id="Q1",
            status="PASS",
            message="LockedSpec validates against schema.",
            pointers=[str(ctx.locked_spec_path)],
        )
    ]
