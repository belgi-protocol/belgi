from __future__ import annotations

import json
from typing import Any

from belgi.core.hash import sha256_bytes
from belgi.core.schema import validate_schema
from belgi.core.jail import resolve_storage_ref
from chain.logic.base import CheckResult, command_satisfied, find_artifacts_by_kind_id
from .context import RCheckContext


def _command_ok(ctx: RCheckContext, subcommand: str) -> bool:
    mode = ctx.tier_params.get("command_log_mode")
    commands = ctx.evidence_manifest.get("commands_executed")
    return command_satisfied(commands, mode=str(mode), subcommand=subcommand)


def _has_policy_report_artifact(ctx: RCheckContext, report_id: str) -> bool:
    artifacts = ctx.evidence_manifest.get("artifacts")
    if not isinstance(artifacts, list):
        return False
    return any(isinstance(a, dict) and a.get("kind") == "policy_report" and a.get("id") == report_id for a in artifacts)


def _load_policy_report(ctx: RCheckContext, report_id: str) -> tuple[dict[str, Any] | None, str]:
    arts = find_artifacts_by_kind_id(ctx.evidence_manifest.get("artifacts"), kind="policy_report", artifact_id=report_id)
    if len(arts) != 1:
        return None, f"Required policy_report artifact must match exactly one entry: id=={report_id} (count={len(arts)})"

    art = arts[0]
    storage_ref = art.get("storage_ref")
    declared_hash = art.get("hash")
    if not isinstance(storage_ref, str) or not storage_ref:
        return None, "policy_report storage_ref missing/invalid"
    if not isinstance(declared_hash, str) or not declared_hash:
        return None, "policy_report hash missing/invalid"

    try:
        p = resolve_storage_ref(ctx.repo_root, storage_ref)
        data = p.read_bytes()
    except Exception as e:
        return None, f"Cannot read policy_report bytes: {e}"

    if sha256_bytes(data) != declared_hash:
        return None, "policy_report sha256(bytes) mismatch"

    try:
        obj = json.loads(data.decode("utf-8", errors="strict"))
    except Exception as e:
        return None, f"policy_report is not valid UTF-8 JSON: {e}"

    if not isinstance(obj, dict):
        return None, "policy_report payload must be a JSON object"

    schema_errs = validate_schema(obj, ctx.policy_payload_schema, root_schema=ctx.policy_payload_schema, path=f"policy_report[{report_id}]")
    if schema_errs:
        first = schema_errs[0]
        return None, f"policy_report payload schema invalid at {first.path}: {first.message}"

    return obj, ""


def run(ctx: RCheckContext) -> list[CheckResult]:
    """R8 — Adversarial diff scan (category-level)."""

    if not _command_ok(ctx, "adversarial-scan"):
        return [
            CheckResult(
                check_id="R8",
                status="FAIL",
                category="FR-COMMAND-FAILED",
                message="Required command missing/failed: belgi adversarial-scan.",
                pointers=[],
                remediation_next_instruction="Do ensure required command record belgi adversarial-scan exists with exit_code 0 in EvidenceManifest.commands_executed then re-run R.",
            )
        ]

    if not _has_policy_report_artifact(ctx, "policy.adversarial_scan"):
        return [
            CheckResult(
                check_id="R8",
                status="FAIL",
                category="FR-ADVERSARIAL-SCAN-MISSING",
                message="Required policy_report artifact missing: id==policy.adversarial_scan.",
                pointers=[],
                remediation_next_instruction="Do produce required evidence kind policy_report under the declared envelope then re-run R.",
            )
        ]

    payload, err = _load_policy_report(ctx, "policy.adversarial_scan")
    if payload is None:
        return [
            CheckResult(
                check_id="R8",
                status="FAIL",
                category="FR-SCHEMA-ARTIFACT-INVALID",
                message=err,
                pointers=[],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    # §5.2.1 semantic sufficiency: checks[] non-empty.
    checks = payload.get("checks")
    if not isinstance(checks, list) or len(checks) == 0:
        return [
            CheckResult(
                check_id="R8",
                status="FAIL",
                category="FR-SCHEMA-ARTIFACT-INVALID",
                message="Required policy_report payload must include non-empty checks[].",
                pointers=[],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    summary = payload.get("summary")
    failed = (summary or {}).get("failed") if isinstance(summary, dict) else None
    if not isinstance(failed, int) or isinstance(failed, bool):
        return [
            CheckResult(
                check_id="R8",
                status="FAIL",
                category="FR-SCHEMA-ARTIFACT-INVALID",
                message="policy.adversarial_scan summary.failed missing/invalid.",
                pointers=[],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    if failed != 0:
        return [
            CheckResult(
                check_id="R8",
                status="FAIL",
                category="FR-ADVERSARIAL-DIFF-SUSPECT",
                message=f"policy.adversarial_scan indicates failures (summary.failed={failed}).",
                pointers=[],
                remediation_next_instruction="Do remediate adversarial scan failures in policy.adversarial_scan then re-run R.",
            )
        ]

    return [
        CheckResult(
            check_id="R8",
            status="PASS",
            category=None,
            message="R8 satisfied: belgi adversarial-scan recorded and policy.adversarial_scan report indicates no failures.",
            pointers=[],
        )
    ]
