#!/usr/bin/env python3
"""Deterministic Gate R verifier (canonical post-proposal verifier).

This entrypoint is the canonical executable for Gate R in the "chain/" layout.
It evaluates a LockedSpec + EvidenceManifest using the modular check registry:
  chain/logic/r_checks/registry.py

Determinism posture:
- Stable check order (registry)
- Stable JSON serialization (sort_keys=True, LF newline)

Exit codes:
- 0: GO (all PASS)
- 2: NO-GO (any FAIL)
- 3: tool usage/internal errors
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import os
from pathlib import Path
from typing import Any

from chain.logic.tier_packs import parse_tier_params
from belgi.core.jail import resolve_repo_rel_path
from belgi.core.hash import sha256_bytes
from belgi.core.jail import safe_relpath
from belgi.core.jail import normalize_repo_rel_path
from belgi.core.schema import validate_schema
from chain.logic.base import CheckResult, load_json, verify_protocol_identity
from chain.logic.r_checks.context import RCheckContext
from chain.logic.r_checks.git_ops import git_resolve_commit
from chain.logic.r_checks.registry import get_checks

from belgi.protocol.pack import (
    ProtocolContext,
    get_builtin_protocol_context,
    load_protocol_context_from_dir,
    DevOverrideNotAllowedError,
)


EVALUATED_AT = "1970-01-01T00:00:00Z"
EVALUATOR = "chain/gate_r_verify.py"

_TAXO_IDS_CACHE_BY_PACK: dict[str, set[str]] = {}


# Compiler C3 hard-requires that the Gate R "R-snapshot" EvidenceManifest indexes:
# - the exact --locked-spec input
# - the exact --gate-q-verdict input
# by (artifact.storage_ref, artifact.hash) with exactly one matching artifact per storage_ref.


def _load_taxonomy_ids(protocol: ProtocolContext) -> set[str]:
    key = protocol.pack_id
    cached = _TAXO_IDS_CACHE_BY_PACK.get(key)
    if cached is not None:
        return cached

    text = protocol.read_text("gates/failure-taxonomy.md")
    ids = set(re.findall(r"category_id:\s*`([^`]+)`", text))
    if not ids:
        raise ValueError("Failed to parse taxonomy category_id tokens from gates/failure-taxonomy.md")
    _TAXO_IDS_CACHE_BY_PACK[key] = ids
    return ids


# Safety net only: if a FAIL CheckResult is missing category, we may map a subset
# of check_id values that have a single deterministic taxonomy category.
_CATEGORY_MAP: dict[str, str] = {
    "R0.tier_parse": "FR-SCHEMA-ARTIFACT-INVALID",
    "R0.command_log_mode": "FR-COMMAND-FAILED",
    "R0.attestation_presence": "FR-EVIDENCE-ATTESTATION-MISSING",
    "R2": "FR-SCOPE-BUDGET-EXCEEDED",
    "R3": "FR-POLICY-FORBIDDEN-PATH",
    "R-DOC-001": "FR-INVARIANT-FAILED",
    "R4": "FR-SCHEMA-ARTIFACT-INVALID",
    "R5": "FR-TESTS-POLICY-FAILED",
}


def _select_failure_category(protocol: ProtocolContext, *, gate_id: str, first: CheckResult) -> str:
    category = first.category.strip() if isinstance(first.category, str) and first.category.strip() else ""
    if not category:
        category = _CATEGORY_MAP.get(first.check_id, "")
    if not category:
        raise ValueError(
            f"INTERNAL ERROR: Gate {gate_id} missing/invalid category mapping for primary check_id={first.check_id!r}"
        )
    taxo_ids = _load_taxonomy_ids(protocol)
    if category not in taxo_ids:
        raise ValueError(
            f"INTERNAL ERROR: Gate {gate_id} category_id not in taxonomy: {category!r} (check_id={first.check_id!r})"
        )
    return category


def _require_dev_mode(flag_name: str) -> None:
    """Local dev guard for non-protocol-pack dev flags (--tiers, --policy-payload-schema, etc.)."""
    if os.environ.get("CI"):
        raise ValueError(f"{flag_name} is not allowed in CI")
    if os.environ.get("BELGI_DEV") != "1":
        raise ValueError(f"{flag_name} requires BELGI_DEV=1")


def _load_protocol_context(*, repo_root: Path, args: argparse.Namespace) -> ProtocolContext:
    if isinstance(getattr(args, "protocol_pack", None), str) and args.protocol_pack:
        pack_root = _resolve_repo_rel_path(repo_root, str(args.protocol_pack), must_exist=True, must_be_file=None)
        if not pack_root.is_dir():
            raise ValueError("--protocol-pack must point to a directory containing ProtocolPackManifest.json")
        return load_protocol_context_from_dir(pack_root=pack_root, source="override")

    if isinstance(getattr(args, "dev_protocol_pack", None), str) and args.dev_protocol_pack:
        # Dev-override guard is centralized in load_protocol_context_from_dir; it will
        # raise DevOverrideNotAllowedError if BELGI_DEV!=1 or CI is set.
        print("DEV MODE: protocol pack override enabled", file=sys.stderr)
        pack_root = Path(str(args.dev_protocol_pack)).resolve()
        if not pack_root.exists() or not pack_root.is_dir():
            raise ValueError("--dev-protocol-pack must point to an existing directory")
        try:
            return load_protocol_context_from_dir(pack_root=pack_root, source="dev-override")
        except DevOverrideNotAllowedError as e:
            raise ValueError(str(e)) from e

    return get_builtin_protocol_context()


def _resolve_repo_rel_path(repo_root: Path, rel: str, *, must_exist: bool, must_be_file: bool | None = None) -> Path:
    return resolve_repo_rel_path(
        repo_root,
        rel,
        must_exist=must_exist,
        must_be_file=must_be_file,
        allow_backslashes=False,
        forbid_symlinks=True,
    )


def _load_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="strict")


def _write_json_deterministic(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    with path.open("w", encoding="utf-8", errors="strict", newline="\n") as f:
        f.write(data)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Gate R deterministic verifier (chain)")
    ap.add_argument("--repo", required=True, help="Repo root")
    ap.add_argument("--locked-spec", required=True, help="Path to LockedSpec.json")
    ap.add_argument("--gate-q-verdict", required=True, help="Path to GateVerdict(Q).json")
    ap.add_argument("--evidence-manifest", required=True, help="Path to EvidenceManifest.json")
    ap.add_argument(
        "--r-snapshot-manifest-out",
        default=None,
        help=(
            "Optional output path for the R-snapshot EvidenceManifest (defaults to overwriting --evidence-manifest)."
        ),
    )
    ap.add_argument("--out", required=True, help="Output path for verify_report.json")

    ap.add_argument(
        "--protocol-pack",
        default=None,
        help="Repo-relative path to a protocol pack root directory (must contain ProtocolPackManifest.json)",
    )
    ap.add_argument(
        "--dev-protocol-pack",
        default=None,
        help="DEV ONLY (requires BELGI_DEV=1, forbidden in CI): absolute path to a protocol pack root directory",
    )
    ap.add_argument(
        "--tiers",
        default=None,
        help=(
            "DEV ONLY: repo-relative path to tiers/tier-packs.json (canonical; default: from active protocol pack). "
            "For legacy debugging you may also point to tiers/tier-packs.md."
        ),
    )

    ap.add_argument("--evaluated-revision", required=True, help="Git revision (commit-ish) being evaluated")

    ap.add_argument(
        "--gate-verdict-out",
        default=None,
        help="Optional output path for GateVerdict.json (defaults to alongside --out)",
    )

    # Optional binding input (defense-in-depth).
    ap.add_argument("--gate-verdict", default=None, help="Optional path to GateVerdict.json")

    # Compatibility knobs for fixtures.
    ap.add_argument(
        "--policy-payload-schema",
        default=None,
        help="DEV ONLY: repo-relative path to PolicyReportPayload schema (default: from active protocol pack)",
    )
    ap.add_argument(
        "--test-payload-schema",
        default=None,
        help="DEV ONLY: repo-relative path to TestReportPayload schema (default: from active protocol pack)",
    )
    ap.add_argument("--required-policy-report-ids", default="policy.invariant_eval,policy.supplychain,policy.adversarial_scan")
    ap.add_argument("--required-test-report-id", default="tests.report")

    return ap.parse_args(argv)


def _normalize_required_ids(s: str) -> list[str]:
    parts = [p.strip() for p in (s or "").split(",")]
    return [p for p in parts if p]


def _flatten(results: list[list[CheckResult]]) -> list[dict[str, Any]]:
    flat: list[dict[str, Any]] = []
    for group in results:
        for r in group:
            flat.append(
                {
                    "check_id": r.check_id,
                    "status": r.status,
                    "category": r.category,
                    "message": r.message,
                    "pointers": r.pointers,
                    "remediation_next_instruction": r.remediation_next_instruction,
                }
            )
    return flat


def _make_report(*, run_id: str, repo_revision: str, results: list[dict[str, Any]]) -> dict[str, Any]:
    passed = sum(1 for r in results if r.get("status") == "PASS")
    failed = sum(1 for r in results if r.get("status") == "FAIL")
    return {
        "schema_version": "1.0.0",
        "run_id": run_id,
        "repo_revision": repo_revision,
        "summary": {"total": len(results), "passed": passed, "failed": failed},
        "results": results,
        "evaluated_at": EVALUATED_AT,
        "evaluator": EVALUATOR,
    }


def _exit_code_from_results(results: list[dict[str, Any]]) -> int:
    for r in results:
        if isinstance(r, dict) and r.get("status") == "FAIL":
            return 2
    return 0


def _first_fail(results: list[CheckResult]) -> CheckResult | None:
    for r in results:
        if r.status == "FAIL":
            return r
    return None


def _make_object_ref(repo_root: Path, path: Path, *, object_id: str) -> dict[str, str]:
    b = path.read_bytes()
    return {"id": object_id, "hash": sha256_bytes(b), "storage_ref": safe_relpath(repo_root, path)}


def _stable_failure_id(gate_id: str, rule_id: str, ordinal: int = 1) -> str:
    return f"{gate_id}-{rule_id}-{ordinal:03d}"


def _artifact_by_storage_ref(artifacts: list[object], storage_ref: str) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for a in artifacts:
        if isinstance(a, dict) and a.get("storage_ref") == storage_ref:
            matches.append(a)
    return matches


def _inject_or_verify_snapshot_indexes(
    *,
    repo_root: Path,
    manifest: dict[str, Any],
    locked_spec_path: Path,
    gate_q_verdict_path: Path,
) -> tuple[dict[str, Any], list[CheckResult]]:
    """Ensure required R-snapshot indexing entries exist and match bytes.

    Missing entries are injected. Hash mismatches / duplicates are FAIL (fail-closed).
    """

    failures: list[CheckResult] = []

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        return (
            manifest,
            [
                CheckResult(
                    check_id="R-SNAPSHOT-INDEX-001",
                    status="FAIL",
                    category="FR-INVARIANT-FAILED",
                    message="EvidenceManifest.artifacts missing/invalid; cannot enforce R-snapshot indexing invariant.",
                    pointers=["#/artifacts"],
                    remediation_next_instruction="Do fix the EvidenceManifest structure then re-run R.",
                )
            ],
        )

    try:
        locked_sr = normalize_repo_rel_path(safe_relpath(repo_root, locked_spec_path))
        q_sr = normalize_repo_rel_path(safe_relpath(repo_root, gate_q_verdict_path))
        locked_hash = sha256_bytes(locked_spec_path.read_bytes())
        q_hash = sha256_bytes(gate_q_verdict_path.read_bytes())
    except Exception as e:
        return (
            manifest,
            [
                CheckResult(
                    check_id="R-SNAPSHOT-INDEX-001",
                    status="FAIL",
                    category="FR-INVARIANT-FAILED",
                    message=f"Failed to compute snapshot indexing hashes/paths: {e}",
                    pointers=[],
                    remediation_next_instruction="Do fix the input paths/files so they can be read and normalized, then re-run R.",
                )
            ],
        )

    required = [
        ("LockedSpec", locked_sr, locked_hash, "locked_spec"),
        ("GateVerdict(Q)", q_sr, q_hash, "gate_q_verdict"),
    ]

    for label, storage_ref, computed_hash, art_id in required:
        matches = _artifact_by_storage_ref(artifacts, storage_ref)
        if len(matches) == 0:
            artifacts.append(
                {
                    "kind": "schema_validation",
                    "id": art_id,
                    "hash": computed_hash,
                    "media_type": "application/json",
                    "storage_ref": storage_ref,
                    "produced_by": "R",
                }
            )
            continue

        if len(matches) != 1:
            failures.append(
                CheckResult(
                    check_id="R-SNAPSHOT-INDEX-001",
                    status="FAIL",
                    category="FR-INVARIANT-FAILED",
                    message=(
                        f"EvidenceManifest must contain exactly 1 artifact with storage_ref={storage_ref!r} for {label} "
                        f"(found {len(matches)})."
                    ),
                    pointers=["#/artifacts"],
                    remediation_next_instruction="Do remove duplicate/conflicting artifacts then re-run R.",
                )
            )
            continue

        declared = matches[0].get("hash")
        if not isinstance(declared, str) or not declared:
            failures.append(
                CheckResult(
                    check_id="R-SNAPSHOT-INDEX-001",
                    status="FAIL",
                    category="FR-INVARIANT-FAILED",
                    message=f"EvidenceManifest artifact.hash missing/invalid for {label} storage_ref={storage_ref!r}.",
                    pointers=["#/artifacts"],
                    remediation_next_instruction="Do fix the EvidenceManifest hash field then re-run R.",
                )
            )
            continue

        if declared.lower() != computed_hash.lower():
            failures.append(
                CheckResult(
                    check_id="R-SNAPSHOT-INDEX-001",
                    status="FAIL",
                    category="FR-INVARIANT-FAILED",
                    message=(
                        f"EvidenceManifest hash mismatch for {label}: storage_ref={storage_ref} "
                        f"declared={declared} computed={computed_hash}"
                    ),
                    pointers=["#/artifacts"],
                    remediation_next_instruction="Do regenerate the EvidenceManifest so hashes match bytes then re-run R.",
                )
            )

    # Deterministic ordering (required by repo determinism posture).
    artifacts.sort(
        key=lambda a: (
            str(a.get("kind", "")),
            str(a.get("storage_ref", "")),
        )
        if isinstance(a, dict)
        else ("", "")
    )
    manifest["artifacts"] = artifacts
    return manifest, failures


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parse_args(argv)

        repo_root = Path(args.repo).resolve()

        protocol = _load_protocol_context(repo_root=repo_root, args=args)

        locked_spec_path = _resolve_repo_rel_path(repo_root, str(args.locked_spec), must_exist=True, must_be_file=True)
        gate_q_verdict_path = _resolve_repo_rel_path(repo_root, str(args.gate_q_verdict), must_exist=True, must_be_file=True)
        evidence_manifest_path = _resolve_repo_rel_path(
            repo_root, str(args.evidence_manifest), must_exist=True, must_be_file=True
        )

        if isinstance(args.r_snapshot_manifest_out, str) and args.r_snapshot_manifest_out.strip():
            r_snapshot_manifest_path = _resolve_repo_rel_path(
                repo_root,
                str(args.r_snapshot_manifest_out).strip(),
                must_exist=False,
                must_be_file=True,
            )
        else:
            r_snapshot_manifest_path = evidence_manifest_path
        out_path = _resolve_repo_rel_path(repo_root, str(args.out), must_exist=False)

        tiers_text: str
        if isinstance(args.tiers, str) and args.tiers:
            _require_dev_mode("--tiers")
            tiers_path = _resolve_repo_rel_path(repo_root, str(args.tiers), must_exist=True, must_be_file=True)
            tiers_text = _load_text(tiers_path)
        else:
            tiers_text = protocol.read_text("tiers/tier-packs.json")

        gate_verdict_path = None
        if isinstance(args.gate_verdict, str) and args.gate_verdict:
            gate_verdict_path = _resolve_repo_rel_path(repo_root, str(args.gate_verdict), must_exist=True, must_be_file=True)

        gate_verdict_out_path = None
        if isinstance(args.gate_verdict_out, str) and args.gate_verdict_out:
            gate_verdict_out_path = _resolve_repo_rel_path(repo_root, str(args.gate_verdict_out), must_exist=False)
        else:
            gate_verdict_out_path = out_path.parent / "GateVerdict.json"

        locked = load_json(locked_spec_path)
        evidence = load_json(evidence_manifest_path)

        if not isinstance(locked, dict):
            raise ValueError("LockedSpec must be a JSON object")
        if not isinstance(evidence, dict):
            raise ValueError("EvidenceManifest must be a JSON object")

        # Enforce/inject required snapshot indexing before running checks.
        preflight_fails: list[CheckResult] = []
        evidence, preflight_fails = _inject_or_verify_snapshot_indexes(
            repo_root=repo_root,
            manifest=evidence,
            locked_spec_path=locked_spec_path,
            gate_q_verdict_path=gate_q_verdict_path,
        )
        snapshot_written_ok = False
        try:
            _write_json_deterministic(r_snapshot_manifest_path, evidence)
            snapshot_written_ok = True
        except Exception as e:
            preflight_fails.append(
                CheckResult(
                    check_id="R-SNAPSHOT-INDEX-001",
                    status="FAIL",
                    category="FR-INVARIANT-FAILED",
                    message=f"Failed to write R-snapshot EvidenceManifest: {e}",
                    pointers=[],
                    remediation_next_instruction=(
                        "Do fix filesystem permissions/paths so Gate R can write the R-snapshot manifest, then re-run R."
                    ),
                )
            )

        # Bind GateVerdict(R).evidence_manifest_ref to the snapshot manifest only if write succeeded.
        if snapshot_written_ok:
            evidence_manifest_path = r_snapshot_manifest_path

        run_id = locked.get("run_id")
        if not isinstance(run_id, str) or not run_id.strip():
            raise ValueError("LockedSpec.run_id missing/invalid")
        run_id = run_id.strip()

        tier_id = None
        tier = locked.get("tier")
        if isinstance(tier, dict):
            tier_id = tier.get("tier_id")
        if not isinstance(tier_id, str) or not tier_id.strip():
            raise ValueError("LockedSpec.tier.tier_id missing/invalid")
        tier_id = tier_id.strip()

        tier_params = parse_tier_params(tiers_text, tier_id)

        if isinstance(args.policy_payload_schema, str) and args.policy_payload_schema:
            _require_dev_mode("--policy-payload-schema")
            policy_schema_path = _resolve_repo_rel_path(
                repo_root, str(args.policy_payload_schema), must_exist=True, must_be_file=True
            )
            policy_payload_schema = load_json(policy_schema_path)
        else:
            policy_payload_schema = protocol.read_json("schemas/PolicyReportPayload.schema.json")

        if isinstance(args.test_payload_schema, str) and args.test_payload_schema:
            _require_dev_mode("--test-payload-schema")
            test_schema_path = _resolve_repo_rel_path(
                repo_root, str(args.test_payload_schema), must_exist=True, must_be_file=True
            )
            test_payload_schema = load_json(test_schema_path)
        else:
            test_payload_schema = protocol.read_json("schemas/TestReportPayload.schema.json")
        if not isinstance(policy_payload_schema, dict):
            raise ValueError("PolicyReportPayload schema must be a JSON object")
        if not isinstance(test_payload_schema, dict):
            raise ValueError("TestReportPayload schema must be a JSON object")

        gate_verdict_obj = load_json(gate_verdict_path) if gate_verdict_path else None
        if gate_verdict_obj is not None and not isinstance(gate_verdict_obj, dict):
            raise ValueError("GateVerdict must be a JSON object")

        upstream_commit_sha = ""
        upstream_state = locked.get("upstream_state")
        if isinstance(upstream_state, dict):
            sha = upstream_state.get("commit_sha")
            if isinstance(sha, str) and sha.strip():
                upstream_commit_sha = sha.strip()

        if not upstream_commit_sha:
            raise ValueError("LockedSpec.upstream_state.commit_sha missing/invalid")

        evaluated_commit_sha = git_resolve_commit(repo_root, str(args.evaluated_revision))

        ctx = RCheckContext(
            repo_root=repo_root,
            protocol=protocol,
            locked_spec_path=locked_spec_path,
            evidence_manifest_path=evidence_manifest_path,
            gate_verdict_path=gate_verdict_path,
            locked_spec=locked,
            evidence_manifest=evidence,
            gate_verdict=gate_verdict_obj,
            tier_params=tier_params,
            evaluated_revision=evaluated_commit_sha,
            upstream_commit_sha=upstream_commit_sha,
            policy_payload_schema=policy_payload_schema,
            test_payload_schema=test_payload_schema,
            required_policy_report_ids=_normalize_required_ids(str(args.required_policy_report_ids)),
            required_test_report_id=str(args.required_test_report_id),
        )

        grouped: list[list[CheckResult]] = []
        linear: list[CheckResult] = []

        if preflight_fails:
            grouped.append(list(preflight_fails))
            linear.extend(preflight_fails)
        for run_check in get_checks():
            batch = run_check(ctx)
            grouped.append(batch)
            linear.extend(batch)

        # Verify protocol identity (fail-closed on mismatch)
        proto_check = verify_protocol_identity(
            locked_spec=locked,
            active_pack_id=protocol.pack_id,
            active_manifest_sha256=protocol.manifest_sha256,
            active_pack_name=protocol.pack_name,
            active_source=protocol.source,
            gate_id="R",
        )
        if proto_check is not None:
            linear.insert(0, proto_check)

        results = _flatten(grouped)

        report = _make_report(run_id=run_id, repo_revision=evaluated_commit_sha, results=results)
        _write_json_deterministic(out_path, report)

        evidence_ref = _make_object_ref(repo_root, evidence_manifest_path, object_id=f"evidence-manifest-{run_id}")
        locked_ref = _make_object_ref(repo_root, locked_spec_path, object_id=f"locked-spec-{run_id}")

        gate_schema = protocol.read_json("schemas/GateVerdict.schema.json")
        if not isinstance(gate_schema, dict):
            raise ValueError("GateVerdict schema must be a JSON object")

        first = _first_fail(linear)
        if first is None:
            verdict_obj: dict[str, Any] = {
                "schema_version": "1.0.0",
                "run_id": run_id,
                "gate_id": "R",
                "verdict": "GO",
                "failure_category": None,
                "failures": [],
                "evidence_manifest_ref": evidence_ref,
                "evaluated_at": EVALUATED_AT,
                "evaluator": EVALUATOR,
            }
        else:
            category = _select_failure_category(protocol, gate_id="R", first=first)
            remediation = first.remediation_next_instruction or "Do fix the primary failure then re-run R."
            verdict_obj = {
                "schema_version": "1.0.0",
                "run_id": run_id,
                "gate_id": "R",
                "verdict": "NO-GO",
                "failure_category": category,
                "failures": [
                    {
                        "id": _stable_failure_id("R", first.check_id, 1),
                        "category": category,
                        "rule_id": first.check_id,
                        "message": first.message,
                        "evidence_refs": [evidence_ref, locked_ref],
                    }
                ],
                "remediation": {"next_instruction": remediation, "constraints": []},
                "evidence_manifest_ref": evidence_ref,
                "evaluated_at": EVALUATED_AT,
                "evaluator": EVALUATOR,
            }

        verrs = validate_schema(verdict_obj, gate_schema, root_schema=gate_schema, path="GateVerdict")
        if verrs:
            first_err = verrs[0]
            raise ValueError(f"GateVerdict output schema invalid at {first_err.path}: {first_err.message}")

        _write_json_deterministic(gate_verdict_out_path, verdict_obj)

        return _exit_code_from_results(results)
    except SystemExit as e:
        if isinstance(e.code, int):
            return e.code
        return 3
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
