from __future__ import annotations

from typing import Any

from belgi.core.hash import sha256_bytes
from belgi.core.jail import safe_relpath
from belgi.core.jail import resolve_storage_ref
from chain.logic.base import CheckResult, find_artifacts_by_kind

from .context import RCheckContext
from .git_ops import git_changed_paths


def _get_doc_impact_required(ctx: RCheckContext) -> bool | None:
    v = ctx.tier_params.get("doc_impact_required")
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    return None


def run(ctx: RCheckContext) -> list[CheckResult]:
    """R-DOC-001 — doc_impact required docs touched (contract compliance)."""

    locked_ptr = safe_relpath(ctx.repo_root, ctx.locked_spec_path)
    doc_ptr = f"{locked_ptr}#/doc_impact"

    doc_impact_required = _get_doc_impact_required(ctx)
    if doc_impact_required is None:
        return [
            CheckResult(
                check_id="R-DOC-001",
                status="FAIL",
                category="FR-INVARIANT-FAILED",
                message="Tier parameter doc_impact_required missing/invalid; cannot enforce R-DOC-001 deterministically.",
                pointers=[locked_ptr + "#/tier/tier_id"],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    doc_impact = ctx.locked_spec.get("doc_impact")

    if doc_impact_required is True:
        if doc_impact is None:
            return [
                CheckResult(
                    check_id="R-DOC-001",
                    status="FAIL",
                    category="FR-INVARIANT-FAILED",
                    message="Tier requires doc_impact but LockedSpec.doc_impact is missing/null.",
                    pointers=[doc_ptr],
                    remediation_next_instruction="Do modify the change so invariant R-DOC-001 is satisfied then re-run R.",
                )
            ]

    # If doc_impact is absent and tier does not require it, pass.
    if doc_impact is None:
        return [
            CheckResult(
                check_id="R-DOC-001",
                status="PASS",
                category=None,
                message="doc_impact not present and tier does not require it.",
                pointers=[doc_ptr],
            )
        ]

    if not isinstance(doc_impact, dict):
        return [
            CheckResult(
                check_id="R-DOC-001",
                status="FAIL",
                category="FR-INVARIANT-FAILED",
                message="LockedSpec.doc_impact must be an object when present.",
                pointers=[doc_ptr],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    required_paths = doc_impact.get("required_paths")
    if not isinstance(required_paths, list):
        return [
            CheckResult(
                check_id="R-DOC-001",
                status="FAIL",
                category="FR-INVARIANT-FAILED",
                message="LockedSpec.doc_impact.required_paths missing/invalid.",
                pointers=[doc_ptr + "/required_paths"],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    if len(required_paths) == 0:
        note = doc_impact.get("note_on_empty")
        if not isinstance(note, str) or not note.strip():
            return [
                CheckResult(
                    check_id="R-DOC-001",
                    status="FAIL",
                    category="FR-INVARIANT-FAILED",
                    message="doc_impact.required_paths is empty but note_on_empty is missing/empty.",
                    pointers=[doc_ptr + "/note_on_empty"],
                    remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
                )
            ]
        return [
            CheckResult(
                check_id="R-DOC-001",
                status="PASS",
                category=None,
                message="doc_impact.required_paths is empty and note_on_empty is present.",
                pointers=[doc_ptr],
            )
        ]

    # For non-empty required_paths, enforce that at least one required path is touched in diff.
    diff_arts = find_artifacts_by_kind(ctx.evidence_manifest.get("artifacts"), kind="diff")
    if len(diff_arts) != 1:
        em_ptr = f"{safe_relpath(ctx.repo_root, ctx.evidence_manifest_path)}#/artifacts"
        return [
            CheckResult(
                check_id="R-DOC-001",
                status="FAIL",
                category="FR-INVARIANT-FAILED",
                message="EvidenceManifest must contain exactly one diff artifact for deterministic doc_impact enforcement.",
                pointers=[em_ptr],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    storage_ref = diff_arts[0].get("storage_ref")
    declared_hash = diff_arts[0].get("hash")
    if not isinstance(storage_ref, str) or not storage_ref:
        return [
            CheckResult(
                check_id="R-DOC-001",
                status="FAIL",
                category="FR-INVARIANT-FAILED",
                message="diff artifact storage_ref missing/empty.",
                pointers=[f"{safe_relpath(ctx.repo_root, ctx.evidence_manifest_path)}#/artifacts"],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]
    if not isinstance(declared_hash, str) or not declared_hash:
        return [
            CheckResult(
                check_id="R-DOC-001",
                status="FAIL",
                category="FR-INVARIANT-FAILED",
                message="diff artifact hash missing/empty.",
                pointers=[f"{safe_relpath(ctx.repo_root, ctx.evidence_manifest_path)}#/artifacts"],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    try:
        diff_path = resolve_storage_ref(ctx.repo_root, storage_ref)
        diff_bytes = diff_path.read_bytes()
    except Exception as e:
        return [
            CheckResult(
                check_id="R-DOC-001",
                status="FAIL",
                category="FR-INVARIANT-FAILED",
                message=f"Cannot read diff bytes: {e}",
                pointers=[storage_ref],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    if sha256_bytes(diff_bytes) != declared_hash:
        return [
            CheckResult(
                check_id="R-DOC-001",
                status="FAIL",
                category="FR-INVARIANT-FAILED",
                message="diff artifact sha256(bytes) mismatch (declared != actual).",
                pointers=[storage_ref],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    # Canonical semantics: match required_paths against repo diff (upstream base -> evaluated revision).
    try:
        changed_files = set(git_changed_paths(ctx.repo_root, ctx.upstream_commit_sha, ctx.evaluated_revision))
    except Exception as e:
        return [
            CheckResult(
                check_id="R-DOC-001",
                status="FAIL",
                category="FR-INVARIANT-FAILED",
                message=f"Cannot compute changed files from git diff {ctx.upstream_commit_sha}..{ctx.evaluated_revision}: {e}",
                pointers=[storage_ref],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    req = [x for x in required_paths if isinstance(x, str) and x]
    matched = [p for p in req if p in changed_files]
    if not matched:
        return [
            CheckResult(
                check_id="R-DOC-001",
                status="FAIL",
                category="FR-INVARIANT-FAILED",
                message="doc_impact.required_paths does not match any changed file path in diff.",
                pointers=[storage_ref] + req[:8],
                remediation_next_instruction="Do modify the change so invariant R-DOC-001 is satisfied then re-run R.",
            )
        ]

    return [
        CheckResult(
            check_id="R-DOC-001",
            status="PASS",
            category=None,
            message="doc_impact.required_paths matches at least one changed file.",
            pointers=[storage_ref] + matched[:3],
        )
    ]
