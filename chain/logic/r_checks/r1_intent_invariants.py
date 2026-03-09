from __future__ import annotations

import json
from typing import Any

from belgi.core.hash import sha256_bytes
from belgi.core.schema import validate_schema
from belgi.core.jail import resolve_storage_ref
from chain.logic.base import CheckResult, command_satisfied, find_artifacts_by_kind_id
from .context import RCheckContext


def _find_required_command_strings(commands: Any, target: str) -> bool:
    if not isinstance(commands, list):
        return False
    return any(isinstance(entry, str) and entry == target for entry in commands)


def _find_required_command_structured(commands: Any, subcommand: str) -> bool:
    if not isinstance(commands, list):
        return False

    for entry in commands:
        if not isinstance(entry, dict):
            continue
        argv = entry.get("argv")
        if not isinstance(argv, list) or len(argv) < 2 or not all(isinstance(x, str) and x for x in argv):
            continue
        if argv[0] != "belgi" or argv[1] != subcommand:
            continue
        exit_code = entry.get("exit_code")
        if isinstance(exit_code, int) and not isinstance(exit_code, bool) and exit_code == 0:
            return True

    return False


def _command_ok(ctx: RCheckContext, subcommand: str) -> bool:
    mode = ctx.tier_params.get("command_log_mode")
    commands = ctx.evidence_manifest.get("commands_executed")
    return command_satisfied(commands, mode=str(mode), subcommand=subcommand)


def _load_and_validate_policy_report(ctx: RCheckContext, report_id: str) -> tuple[dict[str, Any] | None, str]:
    """Load and validate a policy_report per §5.2.1.

    Returns (payload, "") on success, or (None, error_message) on failure.
    """
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
        return None, f"policy_report payload schema validation failed at {first.path}: {first.message}"

    return obj, ""


def run(ctx: RCheckContext) -> list[CheckResult]:
    """R1 — Intent invariants satisfied.

    Implements Gate R §R1 deterministically:
    1) Require LockedSpec.invariants non-empty.
    2) Require command evidence: belgi invariant-eval.
    3) Require policy_report artifact: id==policy.invariant_eval.
    4) Apply §5.2.1: uniqueness, hash verification, payload schema, semantic sufficiency.
       - If invalid => FR-SCHEMA-ARTIFACT-INVALID.
       - If valid but summary.failed != 0 => FR-INVARIANT-FAILED.
    """

    # Defense-in-depth: invariants non-empty (LockedSpec schema should enforce).
    invs = ctx.locked_spec.get("invariants")
    if not isinstance(invs, list) or len(invs) == 0:
        return [
            CheckResult(
                check_id="R1",
                status="FAIL",
                category="FR-INVARIANT-FAILED",
                message="LockedSpec.invariants is missing/empty.",
                pointers=[],
                remediation_next_instruction="Do update C1 compilation so invariants are non-empty and specific then re-run R.",
            )
        ]

    if not _command_ok(ctx, "invariant-eval"):
        return [
            CheckResult(
                check_id="R1",
                status="FAIL",
                category="FR-COMMAND-FAILED",
                message="Required command missing/failed: belgi invariant-eval.",
                pointers=[],
                remediation_next_instruction="Do ensure required command record belgi invariant-eval exists with exit_code 0 in EvidenceManifest.commands_executed then re-run R.",
            )
        ]

    # Check artifact presence (for correct category mapping).
    arts = find_artifacts_by_kind_id(ctx.evidence_manifest.get("artifacts"), kind="policy_report", artifact_id="policy.invariant_eval")
    if len(arts) == 0:
        return [
            CheckResult(
                check_id="R1",
                status="FAIL",
                category="FR-INVARIANT-EVAL-MISSING",
                message="Required policy_report artifact missing: id==policy.invariant_eval.",
                pointers=[],
                remediation_next_instruction="Do run belgi invariant-eval and record policy report policy.invariant_eval then re-run R.",
            )
        ]

    # Apply §5.2.1: load, validate uniqueness/hash/schema.
    payload, err = _load_and_validate_policy_report(ctx, "policy.invariant_eval")
    if payload is None:
        return [
            CheckResult(
                check_id="R1",
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
                check_id="R1",
                status="FAIL",
                category="FR-SCHEMA-ARTIFACT-INVALID",
                message="Required policy_report payload must include non-empty checks[].",
                pointers=[],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    # §5.2.1 semantic sufficiency: summary.failed integer (non-boolean).
    summary = payload.get("summary")
    failed = (summary or {}).get("failed") if isinstance(summary, dict) else None
    if not isinstance(failed, int) or isinstance(failed, bool):
        return [
            CheckResult(
                check_id="R1",
                status="FAIL",
                category="FR-SCHEMA-ARTIFACT-INVALID",
                message="Required policy_report payload summary.failed missing/invalid.",
                pointers=[],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    # §5.2.1 deterministic interpretation: summary.failed != 0 => FR-INVARIANT-FAILED.
    if failed != 0:
        first_failed_check_id = "missing_field"
        for c in checks:
            if not isinstance(c, dict):
                continue
            cid = c.get("check_id")
            passed = c.get("passed")
            if isinstance(cid, str) and cid and passed is False:
                first_failed_check_id = cid
                break
        return [
            CheckResult(
                check_id="R1",
                status="FAIL",
                category="FR-INVARIANT-FAILED",
                message=f"policy.invariant_eval indicates failures (summary.failed={failed}).",
                pointers=[],
                remediation_next_instruction=f"Do modify the change so invariant {first_failed_check_id} is satisfied then re-run R.",
            )
        ]

    return [
        CheckResult(
            check_id="R1",
            status="PASS",
            category=None,
            message="R1 satisfied: belgi invariant-eval command + policy.invariant_eval artifact valid with no failures.",
            pointers=[],
        )
    ]
