from __future__ import annotations

from typing import Any

from belgi.core.hash import sha256_bytes
from belgi.core.jail import safe_relpath
from belgi.core.jail import resolve_storage_ref
from chain.logic.base import CheckResult, find_artifacts_by_kind

from .context import RCheckContext
from .git_ops import (
    git_changed_paths,
    git_loc_delta,
    is_fixture_context,
    parse_unified_diff_loc_delta,
    parse_unified_diff_paths,
)


def _effective_limit(locked_constraints: dict[str, Any], tier_params: dict[str, Any], key: str) -> int | None:
    """Resolve an optional limit from LockedSpec first, then tier defaults."""

    if isinstance(locked_constraints.get(key), int) and not isinstance(locked_constraints.get(key), bool):
        return int(locked_constraints.get(key))

    tier_key = f"scope_budgets.{key}"
    v = tier_params.get(tier_key)
    if v is None:
        return None
    if isinstance(v, int) and not isinstance(v, bool):
        return int(v)
    return None


def run(ctx: RCheckContext) -> list[CheckResult]:
    """R2 — Scope / Blast Radius within tier budgets.

    Uses the single required diff artifact to compute:
    - touched_files = count of unique changed paths
    - loc_delta = insertions + deletions (best-effort from unified diff)

    Enforces effective limits:
    - LockedSpec.constraints.max_* overrides tier default when present
    - Null means "no limit" for that dimension
    """

    locked_constraints = ctx.locked_spec.get("constraints")
    if not isinstance(locked_constraints, dict):
        locked_constraints = {}

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
                remediation_next_instruction="Do reduce scope to within limits (tier scope budgets) or adjust tier/constraints with HOTL then re-run R.",
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
        if is_fixture_context(ctx.repo_root, ctx.locked_spec_path, ctx.evidence_manifest_path):
            try:
                if diff_bytes.strip() == b"":
                    changed_paths = []
                    added, removed = 0, 0
                else:
                    changed_paths = parse_unified_diff_paths(diff_bytes)
                    if not changed_paths:
                        return [
                            CheckResult(
                                check_id="R2",
                                status="FAIL",
                                category="FR-SCHEMA-ARTIFACT-INVALID",
                                message="diff artifact is non-empty but contains no parseable file paths (malformed unified diff)",
                                pointers=[storage_ref],
                                remediation_next_instruction="Do provide a valid unified diff in the diff artifact (or make it empty for no changes), then re-run R.",
                            )
                        ]
                    added, removed = parse_unified_diff_loc_delta(diff_bytes)
            except Exception as e2:
                return [
                    CheckResult(
                        check_id="R2",
                        status="FAIL",
                        category="FR-SCOPE-BUDGET-EXCEEDED",
                        message=f"Cannot compute deterministic scope metrics from diff artifact bytes (fixture fallback): {e2}",
                        pointers=[storage_ref],
                        remediation_next_instruction="Do reduce scope to within limits (tier scope budgets) or adjust tier/constraints with HOTL then re-run R.",
                    )
                ]
        else:
            return [
                CheckResult(
                    check_id="R2",
                    status="FAIL",
                    category="FR-SCOPE-BUDGET-EXCEEDED",
                    message=(
                        f"Cannot compute deterministic scope metrics from git diff {ctx.upstream_commit_sha}..{ctx.evaluated_revision}: {e}"
                    ),
                    pointers=[storage_ref],
                    remediation_next_instruction="Do reduce scope to within limits (tier scope budgets) or adjust tier/constraints with HOTL then re-run R.",
                )
            ]

    touched_files = len(sorted(set(changed_paths)))
    loc_delta = int(added + removed)

    max_touched_files = _effective_limit(locked_constraints, ctx.tier_params, "max_touched_files")
    max_loc_delta = _effective_limit(locked_constraints, ctx.tier_params, "max_loc_delta")

    # Fail closed if tier params are missing for budgets and LockedSpec didn't override.
    tier_missing: list[str] = []
    if ("max_touched_files" not in locked_constraints) and (ctx.tier_params.get("scope_budgets.max_touched_files") is None):
        tier_missing.append("scope_budgets.max_touched_files")
    if ("max_loc_delta" not in locked_constraints) and (ctx.tier_params.get("scope_budgets.max_loc_delta") is None):
        tier_missing.append("scope_budgets.max_loc_delta")

    if tier_missing:
        return [
            CheckResult(
                check_id="R2",
                status="FAIL",
                category="FR-SCOPE-BUDGET-EXCEEDED",
                message=f"Tier scope_budgets missing; cannot enforce R2 deterministically: {tier_missing}",
                pointers=[safe_relpath(ctx.repo_root, ctx.locked_spec_path) + "#/tier/tier_id"],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    # Deterministic primary cause: touched_files first, then loc_delta.
    if max_touched_files is not None and touched_files > max_touched_files:
        return [
            CheckResult(
                check_id="R2",
                status="FAIL",
                category="FR-SCOPE-BUDGET-EXCEEDED",
                message=f"Scope budget exceeded: touched_files={touched_files} > max_touched_files={max_touched_files}",
                pointers=[storage_ref],
                remediation_next_instruction="Do reduce scope to within limits (tier scope budgets) or adjust tier/constraints with HOTL then re-run R.",
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
                remediation_next_instruction="Do reduce scope to within limits (tier scope budgets) or adjust tier/constraints with HOTL then re-run R.",
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
