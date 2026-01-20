from __future__ import annotations

from belgi.core.schema import validate_schema
from chain.logic.base import CheckResult
from .context import QCheckContext


def run(ctx: QCheckContext) -> list[CheckResult]:
    if ctx.intent_obj is None or not isinstance(ctx.intent_obj, dict):
        return [
            CheckResult(
                check_id="Q-INTENT-002",
                status="FAIL",
                message="IntentSpec object missing/invalid; cannot validate schema.",
                pointers=[str(ctx.intent_spec_path)],
                category="FQ-INTENT-INSUFFICIENT",
                remediation_next_instruction="Do fix IntentSpec schema validation errors for intent_spec then re-run Q.",
            )
        ]

    schema = ctx.schemas.get("IntentSpec")
    if not isinstance(schema, dict):
        return [
            CheckResult(
                check_id="Q-INTENT-002",
                status="FAIL",
                message="Missing IntentSpec schema; cannot validate deterministically.",
                pointers=["schemas/IntentSpec.schema.json"],
                category="FQ-INTENT-INSUFFICIENT",
                remediation_next_instruction="Do fix IntentSpec schema validation errors for missing_field then re-run Q.",
            )
        ]

    errs = validate_schema(ctx.intent_obj, schema, root_schema=schema, path="IntentSpec")
    if errs:
        first = errs[0]
        return [
            CheckResult(
                check_id="Q-INTENT-002",
                status="FAIL",
                message=f"IntentSpec schema invalid at {first.path}: {first.message}",
                pointers=[str(ctx.intent_spec_path)],
                category="FQ-INTENT-INSUFFICIENT",
                remediation_next_instruction="Do fix IntentSpec schema validation errors for missing_field then re-run Q.",
            )
        ]

    return [
        CheckResult(
            check_id="Q-INTENT-002",
            status="PASS",
            message="IntentSpec validates against schema.",
            pointers=[str(ctx.intent_spec_path)],
        )
    ]
