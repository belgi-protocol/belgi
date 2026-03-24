from __future__ import annotations

from belgi.core.hash import sha256_bytes
from belgi.core.jail import resolve_storage_ref, safe_relpath
from chain.logic.base import CheckResult, find_artifacts_by_kind
from chain.logic.tolerances import load_locked_tolerances

from .context import RCheckContext
from .git_ops import (
    git_changed_paths,
    git_loc_delta,
)


def run(ctx: RCheckContext) -> list[CheckResult]:
    """R2 — Scope / Blast Radius within tier budgets.

    Uses the single required diff artifact to compute:
    - touched_files = count of unique changed paths
    - loc_delta = insertions + deletions (best-effort from unified diff)

    Enforces effective limits from the locked Tolerances object only.
    Null means "no limit" for that dimension.
    """

    # Resolve the single diff artifact (required evidence) and verify bytes->hash.
    diff_arts = find_artifacts_by_kind(ctx.evidence_manifest.get("artifacts"), kind="diff")
    if len(diff_arts) != 1:
        em_ptr = f"{safe_relpath(ctx.repo_root, ctx.evidence_manifest_path)}#/artifacts"
        msg = "EvidenceManifest must contain exactly one diff artifact for deterministic scope budget enforcement."
        return [
            CheckResult(
                check_id="R2",
                status="FAIL",
                category="FR-SCOPE-BUDGET-EXCEEDED",
                message=msg,
                pointers=[em_ptr],
                remediation_next_instruction=(
                    "Do reduce scope to within the locked tolerances ceilings or change the locked "
                    "Tolerances object / selected tier and re-run Q, then re-run R."
                ),
            )
        ]

    storage_ref = diff_arts[0].get("storage_ref")
    declared_hash = diff_arts[0].get("hash")
    if not isinstance(storage_ref, str) or not storage_ref:
        return [
            CheckResult(
                check_id="R2",
                status="FAIL",
                category="FR-SCOPE-BUDGET-EXCEEDED",
                message="diff artifact storage_ref missing/empty.",
                pointers=[f"{safe_relpath(ctx.repo_root, ctx.evidence_manifest_path)}#/artifacts"],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]
    if not isinstance(declared_hash, str) or not declared_hash:
        return [
            CheckResult(
                check_id="R2",
                status="FAIL",
                category="FR-SCOPE-BUDGET-EXCEEDED",
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
                check_id="R2",
                status="FAIL",
                category="FR-SCOPE-BUDGET-EXCEEDED",
                message=f"Cannot read diff bytes: {e}",
                pointers=[storage_ref],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    if sha256_bytes(diff_bytes) != declared_hash:
        return [
            CheckResult(
                check_id="R2",
                status="FAIL",
                category="FR-SCOPE-BUDGET-EXCEEDED",
                message="diff artifact sha256(bytes) mismatch (declared != actual).",
                pointers=[storage_ref],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    # Canonical semantics: compute from repo diff (upstream base -> evaluated revision).
    try:
        changed_paths = git_changed_paths(ctx.repo_root, ctx.upstream_commit_sha, ctx.evaluated_revision)
        added, removed = git_loc_delta(ctx.repo_root, ctx.upstream_commit_sha, ctx.evaluated_revision)
    except Exception as e:
        return [
            CheckResult(
                check_id="R2",
                status="FAIL",
                category="FR-SCOPE-BUDGET-EXCEEDED",
                message=(
                    f"Cannot compute deterministic scope metrics from git diff {ctx.upstream_commit_sha}..{ctx.evaluated_revision}: {e}"
                ),
                pointers=[storage_ref],
                remediation_next_instruction=(
                    "Do reduce scope to within the locked tolerances ceilings or change the locked "
                    "Tolerances object / selected tier and re-run Q, then re-run R."
                ),
            )
        ]

    touched_files = len(sorted(set(changed_paths)))
    loc_delta = int(added + removed)
    try:
        locked_tolerances = load_locked_tolerances(
            repo_root=ctx.repo_root,
            locked_spec=ctx.locked_spec,
            protocol=ctx.protocol,
        )
    except ValueError as e:
        return [
            CheckResult(
                check_id="R2",
                status="FAIL",
                category="FR-SCHEMA-ARTIFACT-INVALID",
                message=f"Locked tolerances object invalid for R2: {e}",
                pointers=[safe_relpath(ctx.repo_root, ctx.locked_spec_path)],
                remediation_next_instruction="Do fix the locked tolerances object so it matches the selected tier ceilings, then re-run R.",
            )
        ]

    max_touched_files_ceiling = locked_tolerances.max_touched_files
    max_loc_delta_ceiling = locked_tolerances.max_loc_delta
    max_touched_files = max_touched_files_ceiling
    max_loc_delta = max_loc_delta_ceiling

    # Deterministic primary cause: touched_files first, then loc_delta.
    if max_touched_files is not None and touched_files > max_touched_files:
        return [
            CheckResult(
                check_id="R2",
                status="FAIL",
                category="FR-SCOPE-BUDGET-EXCEEDED",
                message=f"Scope budget exceeded: touched_files={touched_files} > max_touched_files={max_touched_files}",
                pointers=[storage_ref],
                remediation_next_instruction=(
                    "Do reduce scope to within the locked tolerances ceilings or change the locked "
                    "Tolerances object / selected tier and re-run Q, then re-run R."
                ),
            )
        ]

    if max_loc_delta is not None and loc_delta > max_loc_delta:
        return [
            CheckResult(
                check_id="R2",
                status="FAIL",
                category="FR-SCOPE-BUDGET-EXCEEDED",
                message=f"Scope budget exceeded: loc_delta={loc_delta} > max_loc_delta={max_loc_delta}",
                pointers=[storage_ref],
                remediation_next_instruction=(
                    "Do reduce scope to within the locked tolerances ceilings or change the locked "
                    "Tolerances object / selected tier and re-run Q, then re-run R."
                ),
            )
        ]

    return [
        CheckResult(
            check_id="R2",
            status="PASS",
            category=None,
            message=(
                "R2 satisfied: scope within budgets "
                f"(touched_files={touched_files}, max_touched_files={max_touched_files}; "
                f"loc_delta={loc_delta}, max_loc_delta={max_loc_delta})."
            ),
            pointers=[storage_ref],
        )
    ]
