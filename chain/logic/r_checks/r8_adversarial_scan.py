from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from belgi.core.hash import sha256_bytes
from belgi.core.jail import normalize_repo_rel_path, resolve_storage_ref
from belgi.core.schema import parse_rfc3339, validate_schema
from chain.logic.base import CheckResult, find_artifacts_by_kind_id, stable_unique
from .context import RCheckContext

_FINDINGS_MODE_VALUES = ("warn", "fail")
_EVALUATED_AT_FALLBACK = "1970-01-01T00:00:00Z"


def _rfc3339_to_dt(value: str) -> datetime:
    parse_rfc3339(value)
    s = value
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        raise ValueError("missing timezone offset")
    return dt.astimezone(timezone.utc)


def _command_ok(ctx: RCheckContext, subcommand: str) -> bool:
    mode = ctx.tier_params.get("command_log_mode")
    commands = ctx.evidence_manifest.get("commands_executed")
    if mode == "strings":
        if not isinstance(commands, list):
            return False
        target = f"belgi {subcommand}"
        return any(isinstance(entry, str) and entry == target for entry in commands)

    if mode == "structured":
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
            if isinstance(exit_code, int) and not isinstance(exit_code, bool) and exit_code in (0, 2):
                # rc=2 is deterministic "findings present" for adversarial-scan, not command execution failure.
                return True
        return False

    return False


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


def _extract_findings(payload: dict[str, Any]) -> tuple[list[dict[str, Any]] | None, str]:
    raw = payload.get("findings")
    if raw is None:
        return [], ""
    if not isinstance(raw, list):
        return None, "policy.adversarial_scan findings missing/invalid."

    out: list[dict[str, Any]] = []
    for idx, row in enumerate(raw):
        if not isinstance(row, dict):
            return None, f"policy.adversarial_scan findings[{idx}] must be an object."
        rule_id = row.get("rule_id")
        path = row.get("path")
        lineno = row.get("lineno")
        if not isinstance(rule_id, str) or not rule_id.strip():
            return None, f"policy.adversarial_scan findings[{idx}].rule_id missing/invalid."
        if not isinstance(path, str) or not path.strip():
            return None, f"policy.adversarial_scan findings[{idx}].path missing/invalid."
        if not isinstance(lineno, int) or isinstance(lineno, bool) or lineno <= 0:
            return None, f"policy.adversarial_scan findings[{idx}].lineno missing/invalid."
        try:
            norm_path = normalize_repo_rel_path(path.strip())
        except Exception as e:
            return None, f"policy.adversarial_scan findings[{idx}].path invalid: {e}"
        out.append(
            {
                "rule_id": rule_id.strip(),
                "path": norm_path,
                "lineno": lineno,
            }
        )

    out.sort(key=lambda f: (str(f["path"]), int(f["lineno"]), str(f["rule_id"])))
    return out, ""


def _resolve_findings_mode(ctx: RCheckContext) -> tuple[str | None, str]:
    mode = ctx.tier_params.get("adversarial_policy.findings_mode")
    if isinstance(mode, str) and mode in _FINDINGS_MODE_VALUES:
        return mode, ""
    return None, "tier adversarial_policy.findings_mode missing/invalid."


def _finding_pointer(finding: dict[str, Any]) -> str:
    return f"finding:{finding['path']}:{finding['lineno']}:{finding['rule_id']}"


def _load_waiver_records(
    *,
    ctx: RCheckContext,
    findings: list[dict[str, Any]],
    evaluated_at: datetime,
) -> tuple[list[dict[str, str]] | None, str]:
    raw = ctx.locked_spec.get("waivers_applied")
    if raw is None:
        return [], ""
    if not isinstance(raw, list):
        return None, "LockedSpec.waivers_applied missing/invalid."

    records: list[dict[str, str]] = []
    normalized_findings = {
        (str(f["rule_id"]), str(f["path"]))
        for f in findings
    }
    for idx, waiver_rel in enumerate(raw):
        if not isinstance(waiver_rel, str) or not waiver_rel.strip():
            return None, f"waivers_applied[{idx}] missing/invalid."
        waiver_ref = waiver_rel.strip()
        try:
            waiver_path = resolve_storage_ref(ctx.repo_root, waiver_ref)
            waiver_obj = json.loads(waiver_path.read_text(encoding="utf-8", errors="strict"))
        except Exception as e:
            return None, f"Cannot read waiver '{waiver_ref}': {e}"
        if not isinstance(waiver_obj, dict):
            return None, f"Waiver '{waiver_ref}' must be a JSON object."

        if waiver_obj.get("gate_id") != "R":
            return None, f"Waiver '{waiver_ref}' gate_id must be 'R'."
        if waiver_obj.get("status") != "active":
            return None, f"Waiver '{waiver_ref}' status must be 'active'."

        rule_id = waiver_obj.get("rule_id")
        if not isinstance(rule_id, str) or not rule_id.strip():
            return None, f"Waiver '{waiver_ref}' rule_id missing/invalid."

        scope = waiver_obj.get("scope")
        if not isinstance(scope, str) or not scope.startswith("path:"):
            return None, f"Waiver '{waiver_ref}' scope must use path:<repo-rel-path>."
        scope_raw = scope[len("path:") :].strip()
        if not scope_raw:
            return None, f"Waiver '{waiver_ref}' scope path missing/invalid."
        try:
            scope_path = normalize_repo_rel_path(scope_raw)
        except Exception as e:
            return None, f"Waiver '{waiver_ref}' scope path invalid: {e}"

        justification = waiver_obj.get("justification")
        if not isinstance(justification, str) or not justification.strip():
            return None, f"Waiver '{waiver_ref}' justification missing/invalid."
        mitigation = waiver_obj.get("mitigation")
        if not isinstance(mitigation, str) or not mitigation.strip():
            return None, f"Waiver '{waiver_ref}' mitigation missing/invalid."

        expires_at = waiver_obj.get("expires_at")
        if not isinstance(expires_at, str) or not expires_at.strip():
            return None, f"Waiver '{waiver_ref}' expires_at missing/invalid."
        try:
            expires_dt = _rfc3339_to_dt(expires_at)
        except Exception as e:
            return None, f"Waiver '{waiver_ref}' expires_at invalid: {e}"
        if not (expires_dt > evaluated_at):
            return None, f"Waiver '{waiver_ref}' is expired."

        # Fail-closed on too-broad/non-matching waivers: path+rule must match at least one finding exactly.
        if (rule_id.strip(), scope_path) not in normalized_findings:
            return None, f"Waiver '{waiver_ref}' does not match any finding by rule_id+path."

        records.append(
            {
                "storage_ref": waiver_ref,
                "rule_id": rule_id.strip(),
                "path": scope_path,
            }
        )

    records.sort(key=lambda r: (r["storage_ref"], r["rule_id"], r["path"]))
    return records, ""


def _split_waived_findings(
    *,
    findings: list[dict[str, Any]],
    waivers: list[dict[str, str]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    waiver_keys = {(w["rule_id"], w["path"]) for w in waivers}
    waived: list[dict[str, Any]] = []
    unwaived: list[dict[str, Any]] = []
    for finding in findings:
        key = (str(finding["rule_id"]), str(finding["path"]))
        if key in waiver_keys:
            waived.append(finding)
        else:
            unwaived.append(finding)
    return waived, unwaived


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

    findings_mode, mode_err = _resolve_findings_mode(ctx)
    if findings_mode is None:
        return [
            CheckResult(
                check_id="R8",
                status="FAIL",
                category="FR-SCHEMA-ARTIFACT-INVALID",
                message=mode_err,
                pointers=[],
                remediation_next_instruction="Do fix tier policy parameters then re-run R.",
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

    findings, findings_err = _extract_findings(payload)
    if findings is None:
        return [
            CheckResult(
                check_id="R8",
                status="FAIL",
                category="FR-SCHEMA-ARTIFACT-INVALID",
                message=findings_err,
                pointers=[],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    findings_count = len(findings)
    findings_present = findings_count > 0
    if (failed == 0 and findings_present) or (failed != 0 and not findings_present):
        return [
            CheckResult(
                check_id="R8",
                status="FAIL",
                category="FR-SCHEMA-ARTIFACT-INVALID",
                message="policy.adversarial_scan summary.failed inconsistent with findings payload.",
                pointers=[],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]
    try:
        evaluated_at_raw = payload.get("generated_at")
        evaluated_at = _rfc3339_to_dt(evaluated_at_raw) if isinstance(evaluated_at_raw, str) else _rfc3339_to_dt(_EVALUATED_AT_FALLBACK)
    except Exception:
        evaluated_at = _rfc3339_to_dt(_EVALUATED_AT_FALLBACK)

    waivers, waiver_err = _load_waiver_records(ctx=ctx, findings=findings, evaluated_at=evaluated_at)
    if waivers is None:
        return [
            CheckResult(
                check_id="R8",
                status="FAIL",
                category="FR-SCHEMA-ARTIFACT-INVALID",
                message=waiver_err,
                pointers=[],
                remediation_next_instruction="Do fix or remove waiver and ensure strict rule_id+path matching, then re-run R.",
            )
        ]

    waiver_allowed = ctx.tier_params.get("waiver_policy.allowed")
    if not isinstance(waiver_allowed, bool):
        return [
            CheckResult(
                check_id="R8",
                status="FAIL",
                category="FR-SCHEMA-ARTIFACT-INVALID",
                message="tier waiver_policy.allowed missing/invalid.",
                pointers=[],
                remediation_next_instruction="Do fix tier policy parameters then re-run R.",
            )
        ]
    if not waiver_allowed and len(waivers) > 0:
        return [
            CheckResult(
                check_id="R8",
                status="FAIL",
                category="FR-SCHEMA-ARTIFACT-INVALID",
                message="waivers are not allowed for selected tier.",
                pointers=[f"waiver:{w['storage_ref']}" for w in waivers[:5]],
                remediation_next_instruction="Do remove waivers_applied for this tier then re-run R.",
            )
        ]

    waived_findings, unwaived_findings = _split_waived_findings(findings=findings, waivers=waivers)

    if findings_mode == "warn":
        msg = (
            "R8 satisfied (tier policy warn): "
            f"findings_present={str(findings_present).lower()} "
            f"findings_count={findings_count} "
            f"waived_findings={len(waived_findings)}."
        )
        pointers = [_finding_pointer(f) for f in findings[:5]]
        pointers.extend(f"waiver:{w['storage_ref']}" for w in waivers[:5])
        return [
            CheckResult(
                check_id="R8",
                status="PASS",
                category=None,
                message=msg,
                pointers=pointers,
            )
        ]

    if failed != 0 and len(unwaived_findings) > 0:
        rule_ids = stable_unique([str(f["rule_id"]) for f in unwaived_findings])
        return [
            CheckResult(
                check_id="R8",
                status="FAIL",
                category="FR-ADVERSARIAL-DIFF-SUSPECT",
                message=(
                    "policy.adversarial_scan indicates unwaived failures "
                    f"(summary.failed={failed}, findings={len(unwaived_findings)}, rules={rule_ids})."
                ),
                pointers=[_finding_pointer(f) for f in unwaived_findings[:5]],
                remediation_next_instruction=(
                    "Do remediate findings or apply a strict, active waiver that matches finding rule_id+path "
                    "with justification, mitigation, and valid expiry, then re-run R."
                ),
            )
        ]

    if failed != 0 and len(unwaived_findings) == 0:
        return [
            CheckResult(
                check_id="R8",
                status="PASS",
                category=None,
                message=(
                    "R8 satisfied via waiver policy: "
                    f"all findings waived (count={len(waived_findings)})."
                ),
                pointers=[f"waiver:{w['storage_ref']}" for w in waivers[:5]],
            )
        ]

    return [
        CheckResult(
            check_id="R8",
            status="PASS",
            category=None,
            message=(
                "R8 satisfied: belgi adversarial-scan recorded and policy.adversarial_scan report indicates no failures "
                f"(findings_present={str(findings_present).lower()}, findings_count={findings_count})."
            ),
            pointers=[f"waiver:{w['storage_ref']}" for w in waivers[:5]],
        )
    ]
