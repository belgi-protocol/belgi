from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from belgi.core.hash import sha256_bytes
from belgi.core.jail import is_under_prefix, normalize_repo_rel_path, resolve_storage_ref, safe_relpath
from belgi.core.schema import validate_schema
from chain.logic.base import (
    CheckResult,
    find_artifacts_by_kind,
)

from .context import RCheckContext
from .git_ops import git_changed_paths, is_fixture_context, parse_unified_diff_paths


class UnsafeWaiverStorageRef(Exception):
    def __init__(self, idx: int, storage_ref: str) -> None:
        self.idx = idx
        self.storage_ref = storage_ref
        super().__init__()

    def __str__(self) -> str:
        return f"idx={self.idx} storage_ref={self.storage_ref}"


class InvalidWaiverDocument(Exception):
    def __init__(self, idx: int, storage_ref: str, reason: str) -> None:
        self.idx = idx
        self.storage_ref = storage_ref
        self.reason = reason
        super().__init__()

    def __str__(self) -> str:
        return f"idx={self.idx} storage_ref={self.storage_ref} reason={self.reason}"


def _tier_str(ctx: RCheckContext, key: str) -> str | None:
    v = ctx.tier_params.get(key)
    return v if isinstance(v, str) and v else None


def _tier_bool(ctx: RCheckContext, key: str) -> bool | None:
    v = ctx.tier_params.get(key)
    return v if isinstance(v, bool) else None


def _load_waiver_schema(ctx: RCheckContext) -> dict[str, Any] | None:
    try:
        obj = ctx.protocol.read_json("schemas/Waiver.schema.json")
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def _waiver_allows_path(ctx: RCheckContext, offending_path: str) -> bool:
    """Check if any active waiver covers the offending path.

    Deterministic v1 scope match (GATE_R.md R3):
    - gate_id == "R"
    - rule_id == "R3.forbidden_paths"
    - status == "active"
    - waiver_doc.scope MUST be a normalized repo-rel prefix and MUST cover offending_path by canonical prefix match
    """
    waivers = ctx.locked_spec.get("waivers_applied")
    if not isinstance(waivers, list) or not waivers:
        return False

    waiver_schema = _load_waiver_schema(ctx)
    if waiver_schema is None:
        # Fail closed at R3 if we cannot validate waiver documents deterministically.
        return False

    for idx, w in enumerate(waivers):
        if not isinstance(w, str) or not w.strip():
            continue
        # Use resolve_storage_ref for jail-safe path resolution (consistent with Q6).
        try:
            waiver_path = resolve_storage_ref(ctx.repo_root, w.strip())
        except ValueError:
            # Unsafe path (jail violation) — fail closed.
            raise UnsafeWaiverStorageRef(idx, w.strip())

        try:
            raw = waiver_path.read_text(encoding="utf-8", errors="strict")
        except OSError:
            raise InvalidWaiverDocument(idx, w.strip(), "read error")
        except UnicodeDecodeError:
            raise InvalidWaiverDocument(idx, w.strip(), "unicode decode")

        try:
            waiver_doc = json.loads(raw)
        except json.JSONDecodeError:
            raise InvalidWaiverDocument(idx, w.strip(), "json decode")

        if not isinstance(waiver_doc, dict):
            raise InvalidWaiverDocument(idx, w.strip(), "waiver json is not an object")

        errs = validate_schema(waiver_doc, waiver_schema, root_schema=waiver_schema, path="Waiver")
        if errs:
            continue

        if waiver_doc.get("status") != "active":
            continue
        if waiver_doc.get("gate_id") != "R":
            continue
        if waiver_doc.get("rule_id") != "R3.forbidden_paths":
            continue

        scope = waiver_doc.get("scope")
        if not isinstance(scope, str) or not scope:
            continue

        try:
            scope_norm = normalize_repo_rel_path(scope)
            offending_norm = normalize_repo_rel_path(offending_path)
        except Exception:
            continue

        if is_under_prefix(offending_norm, scope_norm):
            return True

    return False


def run(ctx: RCheckContext) -> list[CheckResult]:
    """R3 — Policy invariants satisfied (paths + constraints)."""

    locked_ptr = safe_relpath(ctx.repo_root, ctx.locked_spec_path)

    constraints = ctx.locked_spec.get("constraints")
    if not isinstance(constraints, dict):
        return [
            CheckResult(
                check_id="R3",
                status="FAIL",
                category="FR-POLICY-FORBIDDEN-PATH",
                message="LockedSpec.constraints missing/invalid.",
                pointers=[locked_ptr + "#/constraints"],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    allowed_paths = constraints.get("allowed_paths")
    forbidden_paths = constraints.get("forbidden_paths")

    if not isinstance(allowed_paths, list) or not allowed_paths:
        return [
            CheckResult(
                check_id="R3",
                status="FAIL",
                category="FR-POLICY-FORBIDDEN-PATH",
                message="LockedSpec.constraints.allowed_paths missing/empty.",
                pointers=[locked_ptr + "#/constraints/allowed_paths"],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    if not isinstance(forbidden_paths, list):
        forbidden_paths = []

    enforcement = _tier_str(ctx, "scope_budgets.forbidden_paths_enforcement")
    if enforcement not in ("strict", "relaxed"):
        return [
            CheckResult(
                check_id="R3",
                status="FAIL",
                category="FR-POLICY-FORBIDDEN-PATH",
                message="Tier scope_budgets.forbidden_paths_enforcement missing/invalid.",
                pointers=[locked_ptr + "#/tier/tier_id"],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    waiver_allowed = _tier_bool(ctx, "waiver_policy.allowed")
    if waiver_allowed is None:
        return [
            CheckResult(
                check_id="R3",
                status="FAIL",
                category="FR-POLICY-FORBIDDEN-PATH",
                message="Tier waiver_policy.allowed missing/invalid.",
                pointers=[locked_ptr + "#/tier/tier_id"],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    diff_arts = find_artifacts_by_kind(ctx.evidence_manifest.get("artifacts"), kind="diff")
    if len(diff_arts) != 1:
        em_ptr = f"{safe_relpath(ctx.repo_root, ctx.evidence_manifest_path)}#/artifacts"
        return [
            CheckResult(
                check_id="R3",
                status="FAIL",
                category="FR-POLICY-FORBIDDEN-PATH",
                message="EvidenceManifest must contain exactly one diff artifact.",
                pointers=[em_ptr],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    storage_ref = diff_arts[0].get("storage_ref")
    declared_hash = diff_arts[0].get("hash")
    if not isinstance(storage_ref, str) or not storage_ref:
        return [
            CheckResult(
                check_id="R3",
                status="FAIL",
                category="FR-POLICY-FORBIDDEN-PATH",
                message="diff artifact storage_ref missing/empty.",
                pointers=[f"{safe_relpath(ctx.repo_root, ctx.evidence_manifest_path)}#/artifacts"],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]
    if not isinstance(declared_hash, str) or not declared_hash:
        return [
            CheckResult(
                check_id="R3",
                status="FAIL",
                category="FR-POLICY-FORBIDDEN-PATH",
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
                check_id="R3",
                status="FAIL",
                category="FR-POLICY-FORBIDDEN-PATH",
                message=f"Cannot read diff bytes: {e}",
                pointers=[storage_ref],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    if sha256_bytes(diff_bytes) != declared_hash:
        return [
            CheckResult(
                check_id="R3",
                status="FAIL",
                category="FR-POLICY-FORBIDDEN-PATH",
                message="diff artifact sha256(bytes) mismatch (declared != actual).",
                pointers=[storage_ref],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    # Canonical semantics: compute changed paths from repo diff (upstream base -> evaluated revision).
    fixture_ctx = bool(ctx.fixture_context)
    if fixture_ctx and not ctx.evaluated_revision_is_commit:
        try:
            if diff_bytes.strip() == b"":
                changed_paths = []
            else:
                changed_paths = parse_unified_diff_paths(diff_bytes)
                if not changed_paths:
                    return [
                        CheckResult(
                            check_id="R3",
                            status="FAIL",
                            category="FR-SCHEMA-ARTIFACT-INVALID",
                            message="diff artifact is non-empty but contains no parseable file paths (malformed unified diff)",
                            pointers=[storage_ref],
                            remediation_next_instruction="Do provide a valid unified diff in the diff artifact (or make it empty for no changes), then re-run R.",
                        )
                    ]
        except Exception as e2:
            return [
                CheckResult(
                    check_id="R3",
                    status="FAIL",
                    category="FR-POLICY-FORBIDDEN-PATH",
                    message=f"Cannot compute changed paths from diff artifact bytes (fixture fallback): {e2}",
                    pointers=[storage_ref],
                    remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
                )
            ]
    else:
        try:
            changed_paths = git_changed_paths(ctx.repo_root, ctx.upstream_commit_sha, ctx.evaluated_revision)
        except Exception as e:
            if fixture_ctx:
                try:
                    if diff_bytes.strip() == b"":
                        changed_paths = []
                    else:
                        changed_paths = parse_unified_diff_paths(diff_bytes)
                        if not changed_paths:
                            return [
                                CheckResult(
                                    check_id="R3",
                                    status="FAIL",
                                    category="FR-SCHEMA-ARTIFACT-INVALID",
                                    message="diff artifact is non-empty but contains no parseable file paths (malformed unified diff)",
                                    pointers=[storage_ref],
                                    remediation_next_instruction="Do provide a valid unified diff in the diff artifact (or make it empty for no changes), then re-run R.",
                                )
                            ]
                except Exception as e2:
                    return [
                        CheckResult(
                            check_id="R3",
                            status="FAIL",
                            category="FR-POLICY-FORBIDDEN-PATH",
                            message=f"Cannot compute changed paths from diff artifact bytes (fixture fallback): {e2}",
                            pointers=[storage_ref],
                            remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
                        )
                    ]
            else:
                return [
                    CheckResult(
                        check_id="R3",
                        status="FAIL",
                        category="FR-POLICY-FORBIDDEN-PATH",
                        message=f"Cannot compute changed paths from git diff {ctx.upstream_commit_sha}..{ctx.evaluated_revision}: {e}",
                        pointers=[storage_ref],
                        remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
                    )
                ]

    for p in changed_paths:
        try:
            norm = normalize_repo_rel_path(p)
        except Exception:
            return [
                CheckResult(
                    check_id="R3",
                    status="FAIL",
                    category="FR-POLICY-FORBIDDEN-PATH",
                    message=f"Changed path is not normalized repo-rel path: {p}",
                    pointers=[storage_ref],
                    remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
                )
            ]

        if norm != p:
            return [
                CheckResult(
                    check_id="R3",
                    status="FAIL",
                    category="FR-POLICY-FORBIDDEN-PATH",
                    message=f"Changed path must be already-normalized (normalize_repo_rel_path(p) != p): {p}",
                    pointers=[storage_ref],
                    remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
                )
            ]

        # Must be under at least one allowed prefix.
        ok_allowed = any(isinstance(pref, str) and is_under_prefix(p, pref) for pref in allowed_paths)
        if not ok_allowed:
            return [
                CheckResult(
                    check_id="R3",
                    status="FAIL",
                    category="FR-POLICY-FORBIDDEN-PATH",
                    message=f"Changed path is not under any allowed_paths prefix: {p}",
                    pointers=[storage_ref, locked_ptr + "#/constraints/allowed_paths"],
                    remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
                )
            ]

        # Must not be under any forbidden prefix.
        for pref in forbidden_paths:
            if not isinstance(pref, str):
                continue
            if is_under_prefix(p, pref):
                if enforcement == "strict":
                    return [
                        CheckResult(
                            check_id="R3",
                            status="FAIL",
                            category="FR-POLICY-FORBIDDEN-PATH",
                            message=f"Forbidden path touched under strict enforcement: {p}",
                            pointers=[storage_ref, locked_ptr + "#/constraints/forbidden_paths"],
                                    remediation_next_instruction=f"Do revert changes to forbidden path {p} then re-run R.",
                        )
                    ]

                # relaxed
                if not waiver_allowed:
                    return [
                        CheckResult(
                            check_id="R3",
                            status="FAIL",
                            category="FR-POLICY-FORBIDDEN-PATH",
                            message=f"Forbidden path touched but waivers are not allowed: {p}",
                            pointers=[storage_ref],
                                    remediation_next_instruction=f"Do revert changes to forbidden path {p} then re-run R.",
                        )
                    ]

                try:
                    waiver_ok = _waiver_allows_path(ctx, p)
                except UnsafeWaiverStorageRef as e:
                    return [
                        CheckResult(
                            check_id="R3",
                            status="FAIL",
                            category="FR-POLICY-FORBIDDEN-PATH",
                            message=f"Unsafe waiver storage_ref present in LockedSpec.waivers_applied ({e}).",
                            pointers=[locked_ptr + f"#/waivers_applied/{e.idx}"],
                            remediation_next_instruction="Do remove/replace unsafe waiver path(s) in LockedSpec.waivers_applied then re-run R.",
                        )
                    ]
                except InvalidWaiverDocument as e:
                    return [
                        CheckResult(
                            check_id="R3",
                            status="FAIL",
                            category="FR-POLICY-FORBIDDEN-PATH",
                            message=f"Invalid waiver document: {e.reason} (storage_ref={e.storage_ref}).",
                            pointers=[locked_ptr + f"#/waivers_applied/{e.idx}"],
                            remediation_next_instruction="Do fix/replace the invalid waiver document referenced by LockedSpec.waivers_applied then re-run R.",
                        )
                    ]

                if not waiver_ok:
                    return [
                        CheckResult(
                            check_id="R3",
                            status="FAIL",
                            category="FR-POLICY-FORBIDDEN-PATH",
                            message=f"Forbidden path touched and no active waiver matches scope: {p}",
                            pointers=[storage_ref],
                                    remediation_next_instruction=f"Do revert changes to forbidden path {p} then re-run R.",
                        )
                    ]

    return [
        CheckResult(
            check_id="R3",
            status="PASS",
            category=None,
            message="R3 satisfied: all changed paths are normalized, under allowed_paths, and not under forbidden_paths (or waived).",
            pointers=[storage_ref],
        )
    ]
