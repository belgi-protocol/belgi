from __future__ import annotations

from chain.logic.base import CheckResult
from .context import QCheckContext


def run(ctx: QCheckContext) -> list[CheckResult]:
    if ctx.yaml_block_count != 1:
        return [
            CheckResult(
                check_id="Q-INTENT-001",
                status="FAIL",
                message="IntentSpec.core.md must contain exactly one fenced YAML block (```yaml ... ```).",
                pointers=[str(ctx.intent_spec_path)],
                category="FQ-INTENT-INSUFFICIENT",
                remediation_next_instruction="Do fix IntentSpec.core.md so it contains exactly one parseable YAML block then re-run Q.",
            )
        ]

    if ctx.yaml_parse_error:
        return [
            CheckResult(
                check_id="Q-INTENT-001",
                status="FAIL",
                message=f"IntentSpec YAML block is not parseable: {ctx.yaml_parse_error}",
                pointers=[str(ctx.intent_spec_path)],
                category="FQ-INTENT-INSUFFICIENT",
                remediation_next_instruction="Do fix IntentSpec.core.md so it contains exactly one parseable YAML block then re-run Q.",
            )
        ]

    if ctx.intent_obj is None or not isinstance(ctx.intent_obj, dict):
        return [
            CheckResult(
                check_id="Q-INTENT-001",
                status="FAIL",
                message="IntentSpec YAML did not produce an object mapping.",
                pointers=[str(ctx.intent_spec_path)],
                category="FQ-INTENT-INSUFFICIENT",
                remediation_next_instruction="Do fix IntentSpec.core.md so it contains exactly one parseable YAML block then re-run Q.",
            )
        ]

    return [
        CheckResult(
            check_id="Q-INTENT-001",
            status="PASS",
            message="IntentSpec.core.md YAML block present and parseable.",
            pointers=[str(ctx.intent_spec_path)],
        )
    ]
