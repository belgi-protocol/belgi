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


def _load_and_validate_test_report(ctx: RCheckContext, artifact_id: str) -> tuple[dict[str, Any] | None, str]:
    """Load and validate required test_report per Gate R §5.2.1.

    Returns (payload, "") on success, or (None, error_message) on failure.
    """

    arts = find_artifacts_by_kind_id(ctx.evidence_manifest.get("artifacts"), kind="test_report", artifact_id=artifact_id)
    if len(arts) != 1:
        return None, f"Required test_report artifact must match exactly one entry: id=={artifact_id} (count={len(arts)})"

    art = arts[0]
    storage_ref = art.get("storage_ref")
    declared_hash = art.get("hash")
    if not isinstance(storage_ref, str) or not storage_ref:
        return None, "test_report storage_ref missing/invalid"
    if not isinstance(declared_hash, str) or not declared_hash:
        return None, "test_report hash missing/invalid"

    try:
        p = resolve_storage_ref(ctx.repo_root, storage_ref)
        data = p.read_bytes()
    except Exception as e:
        return None, f"Cannot read test_report bytes: {e}"

    if sha256_bytes(data) != declared_hash:
        return None, "test_report sha256(bytes) mismatch"

    try:
        obj = json.loads(data.decode("utf-8", errors="strict"))
    except Exception as e:
        return None, f"test_report is not valid UTF-8 JSON: {e}"

    if not isinstance(obj, dict):
        return None, "test_report payload must be a JSON object"

    schema_errs = validate_schema(obj, ctx.test_payload_schema, root_schema=ctx.test_payload_schema, path=f"test_report[{artifact_id}]")
    if schema_errs:
        first = schema_errs[0]
        return None, f"test_report payload schema validation failed at {first.path}: {first.message}"

    # §5.2.1 sufficiency: summary.failed is integer (non-boolean). (Pass/fail semantics are in R5.)
    summary = obj.get("summary")
    failed = (summary or {}).get("failed") if isinstance(summary, dict) else None
    if not isinstance(failed, int) or isinstance(failed, bool):
        return None, "test_report payload summary.failed missing/invalid"

    return obj, ""


def run(ctx: RCheckContext) -> list[CheckResult]:
    """R5 — Tests policy satisfied."""

    required = ctx.tier_params.get("test_policy.required")
    if required not in ("yes", "no"):
        return [
            CheckResult(
                check_id="R5",
                status="FAIL",
                category="FR-TESTS-POLICY-FAILED",
                message="Tier test_policy.required missing/invalid.",
                pointers=[],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    if required == "no":
        # Tier doesn't require tests; if a test_report exists and indicates failures, this is NO-GO.
        arts = find_artifacts_by_kind_id(ctx.evidence_manifest.get("artifacts"), kind="test_report", artifact_id=ctx.required_test_report_id)
        if len(arts) == 1:
            payload, err = _load_and_validate_test_report(ctx, ctx.required_test_report_id)
            if payload is None:
                return [
                    CheckResult(
                        check_id="R5",
                        status="FAIL",
                        category="FR-TESTS-POLICY-FAILED",
                        message=err,
                        pointers=[],
                        remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
                    )
                ]
            summary = payload.get("summary")
            failed = (summary or {}).get("failed") if isinstance(summary, dict) else None
            if isinstance(failed, int) and not isinstance(failed, bool) and failed > 0:
                return [
                    CheckResult(
                        check_id="R5",
                        status="FAIL",
                        category="FR-TESTS-POLICY-FAILED",
                        message=f"Tier does not require tests, but test_report.summary.failed={failed}.",
                        pointers=[],
                        remediation_next_instruction="Do run required tests and resolve failures then re-run R.",
                    )
                ]
        return [
            CheckResult(
                check_id="R5",
                status="PASS",
                category=None,
                message="R5 satisfied: tier does not require tests.",
                pointers=[],
            )
        ]

    # required == yes
    payload, err = _load_and_validate_test_report(ctx, ctx.required_test_report_id)
    if payload is None:
        return [
            CheckResult(
                check_id="R5",
                status="FAIL",
                category="FR-TESTS-POLICY-FAILED",
                message=err,
                pointers=[],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    summary = payload.get("summary")
    failed = (summary or {}).get("failed") if isinstance(summary, dict) else None
    skipped = (summary or {}).get("skipped") if isinstance(summary, dict) else None

    if isinstance(failed, int) and not isinstance(failed, bool) and failed != 0:
        return [
            CheckResult(
                check_id="R5",
                status="FAIL",
                category="FR-TESTS-POLICY-FAILED",
                message=f"test_report.summary.failed={failed} (expected 0).",
                pointers=[],
                remediation_next_instruction="Do run required tests and resolve failures then re-run R.",
            )
        ]

    if ctx.tier_params.get("test_policy.allowed_skips") == "no":
        if isinstance(skipped, int) and not isinstance(skipped, bool) and skipped != 0:
            return [
                CheckResult(
                    check_id="R5",
                    status="FAIL",
                    category="FR-TESTS-POLICY-FAILED",
                    message=f"test_report.summary.skipped={skipped} (forbidden by tier).",
                    pointers=[],
                    remediation_next_instruction="Do run required tests and resolve failures then re-run R.",
                )
            ]

    if not _command_ok(ctx, "run-tests"):
        return [
            CheckResult(
                check_id="R5",
                status="FAIL",
                category="FR-COMMAND-FAILED",
                message="Required command missing/failed: belgi run-tests.",
                pointers=[],
                remediation_next_instruction="Do ensure required command record belgi run-tests exists with exit_code 0 in EvidenceManifest.commands_executed then re-run R.",
            )
        ]

    return [
        CheckResult(
            check_id="R5",
            status="PASS",
            category=None,
            message="R5 satisfied: required test_report present, test policy satisfied, and belgi run-tests recorded.",
            pointers=[],
        )
    ]
