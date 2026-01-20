from __future__ import annotations

from typing import Any

from belgi.core.jail import safe_relpath
from chain.logic.base import CheckResult

from .context import RCheckContext


def _artifact_kinds(evidence_manifest: dict[str, Any]) -> set[str]:
    kinds: set[str] = set()
    artifacts = evidence_manifest.get("artifacts")
    if not isinstance(artifacts, list):
        return kinds
    for a in artifacts:
        if not isinstance(a, dict):
            continue
        k = a.get("kind")
        if isinstance(k, str) and k:
            kinds.add(k)
    return kinds


def _check_tier_parse(ctx: RCheckContext) -> CheckResult:
    tier_id = (ctx.locked_spec.get("tier") or {}).get("tier_id")
    tier_ptr = f"{safe_relpath(ctx.repo_root, ctx.locked_spec_path)}#/tier/tier_id"

    tier_token = tier_id.strip() if isinstance(tier_id, str) and tier_id.strip() else "missing_field"

    if not isinstance(tier_id, str) or not tier_id.strip():
        return CheckResult(
            check_id="R0.tier_parse",
            status="FAIL",
            category="FR-SCHEMA-ARTIFACT-INVALID",
            message="LockedSpec.tier.tier_id missing/invalid; cannot load tier defaults deterministically.",
            pointers=[tier_ptr],
            remediation_next_instruction=f"Do select a supported tier_id ({tier_token}) then re-run R.",
        )

    parse_err = ctx.tier_params.get("_tier_parse_error")
    if isinstance(parse_err, str) and parse_err:
        return CheckResult(
            check_id="R0.tier_parse",
            status="FAIL",
            category="FR-SCHEMA-ARTIFACT-INVALID",
            message=f"Tier parsing failed deterministically: {parse_err}",
            pointers=[tier_ptr],
            remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
        )

    return CheckResult(
        check_id="R0.tier_parse",
        status="PASS",
        category=None,
        message="Tier parsed deterministically.",
        pointers=[tier_ptr],
    )


def _check_required_evidence_kinds(ctx: RCheckContext) -> CheckResult:
    req = ctx.tier_params.get("required_evidence_kinds")
    em_ptr = f"{safe_relpath(ctx.repo_root, ctx.evidence_manifest_path)}#/artifacts"

    if not isinstance(req, list):
        return CheckResult(
            check_id="R0.evidence_sufficiency",
            status="FAIL",
            category="FR-SCHEMA-ARTIFACT-INVALID",
            message="Tier required_evidence_kinds missing/invalid; tier parsing may be incomplete.",
            pointers=[em_ptr],
            remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
        )

    # Determinism: preserve tier-declared order; ignore empty/non-string entries; de-dup stably.
    required: list[str] = []
    seen: set[str] = set()
    for x in req:
        if not isinstance(x, str) or not x:
            continue
        if x in seen:
            continue
        seen.add(x)
        required.append(x)
    present = _artifact_kinds(ctx.evidence_manifest)
    missing = [k for k in required if k not in present]
    if missing:
        missing_kind = missing[0]
        return CheckResult(
            check_id="R0.evidence_sufficiency",
            status="FAIL",
            category="FR-EVIDENCE-MISSING",
            message=f"Required evidence kinds missing from EvidenceManifest.artifacts[].kind: {missing}",
            pointers=[em_ptr],
            remediation_next_instruction=f"Do produce required evidence kind {missing_kind} under the declared envelope then re-run R.",
        )

    return CheckResult(
        check_id="R0.evidence_sufficiency",
        status="PASS",
        category=None,
        message="All required evidence kinds are present.",
        pointers=[em_ptr],
    )


def _is_structured_command_record(obj: Any) -> bool:
    if not isinstance(obj, dict):
        return False
    argv = obj.get("argv")
    exit_code = obj.get("exit_code")
    started_at = obj.get("started_at")
    finished_at = obj.get("finished_at")
    if not isinstance(argv, list) or not all(isinstance(x, str) for x in argv):
        return False
    if not isinstance(exit_code, int) or isinstance(exit_code, bool):
        return False
    if not isinstance(started_at, str) or not started_at:
        return False
    if not isinstance(finished_at, str) or not finished_at:
        return False
    return True


def _check_command_log_mode(ctx: RCheckContext) -> CheckResult:
    mode = ctx.tier_params.get("command_log_mode")
    em_ptr = f"{safe_relpath(ctx.repo_root, ctx.evidence_manifest_path)}#/commands_executed"

    commands = ctx.evidence_manifest.get("commands_executed")
    if not isinstance(commands, list):
        return CheckResult(
            check_id="R0.command_log_mode",
            status="FAIL",
            category="FR-COMMAND-FAILED",
            message="EvidenceManifest.commands_executed must be a list.",
            pointers=[em_ptr],
            remediation_next_instruction="Do ensure EvidenceManifest.commands_executed satisfies tier command_log_mode then re-run R.",
        )

    if mode == "structured":
        bad = [i for i, x in enumerate(commands) if not _is_structured_command_record(x)]
        if bad:
            return CheckResult(
                check_id="R0.command_log_mode",
                status="FAIL",
                category="FR-COMMAND-FAILED",
                message=f"command_log_mode structured requires structured command records; invalid element indexes: {bad}",
                pointers=[em_ptr],
                remediation_next_instruction="Do ensure EvidenceManifest.commands_executed satisfies tier command_log_mode then re-run R.",
            )
        return CheckResult(
            check_id="R0.command_log_mode",
            status="PASS",
            category=None,
            message="command_log_mode structured satisfied by commands_executed shape.",
            pointers=[em_ptr],
        )

    if mode == "strings":
        bad = [i for i, x in enumerate(commands) if not isinstance(x, str)]
        if bad:
            return CheckResult(
                check_id="R0.command_log_mode",
                status="FAIL",
                category="FR-COMMAND-FAILED",
                message=f"command_log_mode strings requires list of strings; non-string element indexes: {bad}",
                pointers=[em_ptr],
                remediation_next_instruction="Do ensure EvidenceManifest.commands_executed satisfies tier command_log_mode then re-run R.",
            )
        return CheckResult(
            check_id="R0.command_log_mode",
            status="PASS",
            category=None,
            message="command_log_mode strings satisfied by commands_executed shape.",
            pointers=[em_ptr],
        )

    return CheckResult(
        check_id="R0.command_log_mode",
        status="FAIL",
        category="FR-COMMAND-FAILED",
        message="Tier command_log_mode missing/invalid; tier parsing may be incomplete.",
        pointers=[em_ptr],
        remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
    )


def _check_attestation_presence(ctx: RCheckContext) -> CheckResult:
    requires = ctx.tier_params.get("envelope_policy.requires_attestation")
    em_ptr = f"{safe_relpath(ctx.repo_root, ctx.evidence_manifest_path)}#/envelope_attestation"
    if requires is None:
        return CheckResult(
            check_id="R0.attestation_presence",
            status="FAIL",
            category="FR-EVIDENCE-ATTESTATION-MISSING",
            message="Tier parameter 'envelope_policy.requires_attestation' missing; cannot verify R0.",
            pointers=[em_ptr],
            remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
        )
    if requires != "yes":
        return CheckResult(
            check_id="R0.attestation_presence",
            status="PASS",
            category=None,
            message="Tier does not require envelope attestation.",
            pointers=[em_ptr],
        )

    if ctx.evidence_manifest.get("envelope_attestation") is None:
        return CheckResult(
            check_id="R0.attestation_presence",
            status="FAIL",
            category="FR-EVIDENCE-ATTESTATION-MISSING",
            message="Tier requires attestation but EvidenceManifest.envelope_attestation is null.",
            pointers=[em_ptr],
            remediation_next_instruction="Do produce envelope attestation evidence under the declared envelope then re-run R.",
        )

    # Additional deterministic presence requirement: env_attestation artifact kind exists.
    kinds = _artifact_kinds(ctx.evidence_manifest)
    if "env_attestation" not in kinds:
        return CheckResult(
            check_id="R0.attestation_presence",
            status="FAIL",
            category="FR-EVIDENCE-ATTESTATION-MISSING",
            message="Tier requires attestation but no EvidenceManifest.artifacts entry with kind 'env_attestation' exists.",
            pointers=[f"{safe_relpath(ctx.repo_root, ctx.evidence_manifest_path)}#/artifacts"],
            remediation_next_instruction="Do produce envelope attestation evidence under the declared envelope then re-run R.",
        )

    return CheckResult(
        check_id="R0.attestation_presence",
        status="PASS",
        category=None,
        message="Tier requires attestation and required attestation fields are present.",
        pointers=[em_ptr],
    )


def run(ctx: RCheckContext) -> list[CheckResult]:
    # Gate R §4: Evidence Sufficiency Rule (Deterministic)
    # Implemented as fixed, deterministic R0 checks.
    results: list[CheckResult] = []

    tier_parse = _check_tier_parse(ctx)
    results.append(tier_parse)

    # If we cannot parse tier deterministically, do not attempt to enforce derived obligations.
    if tier_parse.status == "FAIL":
        return results

    results.append(_check_required_evidence_kinds(ctx))
    results.append(_check_command_log_mode(ctx))
    results.append(_check_attestation_presence(ctx))
    return results
