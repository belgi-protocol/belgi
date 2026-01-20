from __future__ import annotations

from belgi.core.schema import validate_schema
from chain.logic.base import CheckResult
from .context import QCheckContext


def run(ctx: QCheckContext) -> list[CheckResult]:
    if ctx.evidence_manifest is None or not isinstance(ctx.evidence_manifest, dict):
        return [
            CheckResult(
                check_id="Q-EVIDENCE-001",
                status="FAIL",
                message="EvidenceManifest missing/invalid; cannot validate schema.",
                pointers=[str(ctx.evidence_manifest_path)],
                category="FQ-SCHEMA-EVIDENCEMANIFEST-INVALID",
                remediation_next_instruction="Do fix EvidenceManifest schema validation errors for missing_field then re-run Q.",
            )
        ]

    schema = ctx.schemas.get("EvidenceManifest")
    if not isinstance(schema, dict):
        return [
            CheckResult(
                check_id="Q-EVIDENCE-001",
                status="FAIL",
                message="Missing EvidenceManifest schema; cannot validate deterministically.",
                pointers=["schemas/EvidenceManifest.schema.json"],
                category="FQ-SCHEMA-EVIDENCEMANIFEST-INVALID",
                remediation_next_instruction="Do fix EvidenceManifest schema validation errors for missing_field then re-run Q.",
            )
        ]

    errs = validate_schema(ctx.evidence_manifest, schema, root_schema=schema, path="EvidenceManifest")
    if errs:
        first = errs[0]
        return [
            CheckResult(
                check_id="Q-EVIDENCE-001",
                status="FAIL",
                message=f"EvidenceManifest schema invalid at {first.path}: {first.message}",
                pointers=[str(ctx.evidence_manifest_path)],
                category="FQ-SCHEMA-EVIDENCEMANIFEST-INVALID",
                remediation_next_instruction="Do fix EvidenceManifest schema validation errors for missing_field then re-run Q.",
            )
        ]

    return [
        CheckResult(
            check_id="Q-EVIDENCE-001",
            status="PASS",
            message="EvidenceManifest validates against schema.",
            pointers=[str(ctx.evidence_manifest_path)],
        )
    ]
