#!/usr/bin/env python3
"""Deterministic Gate S verifier (Seal): verify SealManifest binding + signature.

This tool verifies:
- SealManifest schema validity
- ObjectRef hash binding (including pinned seal_pubkey_ref)
- seal_hash per docs/operations/evidence-bundles.md
- Tier-2/3 Ed25519 cryptographic seal signature (and fail-closed if present for tier-0/1)

Outputs:
- Writes a schema-validated GateVerdict JSON (requires EvidenceManifest for evidence_manifest_ref).

Exit codes:
- 0: GO
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

from belgi.core.jail import resolve_repo_rel_path
from belgi.core.hash import sha256_bytes
from belgi.core.jail import safe_relpath
from belgi.core.schema import validate_schema
from chain.logic.base import CheckResult, load_json, verify_protocol_identity
from chain.logic.s_checks.context import SCheckContext
from chain.logic.s_checks.registry import get_checks

from belgi.protocol.pack import (
    ProtocolContext,
    get_builtin_protocol_context,
    load_protocol_context_from_dir,
    DevOverrideNotAllowedError,
)


EVALUATED_AT = "1970-01-01T00:00:00Z"
EVALUATOR = "chain/gate_s_verify.py"

_TAXO_IDS_CACHE_BY_PACK: dict[str, set[str]] = {}


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


_CATEGORY_MAP: dict[str, str] = {
    "S2": "FS-OBJECTREF-HASH-MISMATCH",
    "S3": "FS-SEALHASH-MISMATCH",
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


def _write_json_deterministic(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    with path.open("w", encoding="utf-8", errors="strict", newline="\n") as f:
        f.write(data)


def _resolve_repo_rel_path(repo_root: Path, rel: str, *, must_exist: bool, must_be_file: bool | None = None) -> Path:
    return resolve_repo_rel_path(
        repo_root,
        rel,
        must_exist=must_exist,
        must_be_file=must_be_file,
        allow_backslashes=False,
        forbid_symlinks=True,
    )


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


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True, help="Repo root")
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
    ap.add_argument("--locked-spec", required=True, help="Repo-relative path to LockedSpec.json")
    ap.add_argument("--seal-manifest", required=True, help="Repo-relative path to SealManifest.json")
    ap.add_argument("--evidence-manifest", required=True, help="Repo-relative path to EvidenceManifest.json")
    ap.add_argument("--out", required=True, help="Output path for GateVerdict.json")
    return ap.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parse_args(argv)
        repo_root = Path(args.repo).resolve()

        protocol = _load_protocol_context(repo_root=repo_root, args=args)

        locked_spec_path = _resolve_repo_rel_path(repo_root, str(args.locked_spec), must_exist=True, must_be_file=True)
        seal_manifest_path = _resolve_repo_rel_path(repo_root, str(args.seal_manifest), must_exist=True, must_be_file=True)
        evidence_manifest_path = _resolve_repo_rel_path(
            repo_root, str(args.evidence_manifest), must_exist=True, must_be_file=True
        )
        out_path = _resolve_repo_rel_path(repo_root, str(args.out), must_exist=False)

        locked_spec = load_json(locked_spec_path)
        if not isinstance(locked_spec, dict):
            raise ValueError("LockedSpec must be a JSON object")

        seal_manifest = load_json(seal_manifest_path)
        if not isinstance(seal_manifest, dict):
            raise ValueError("SealManifest must be a JSON object")

        evidence_manifest = load_json(evidence_manifest_path)
        if not isinstance(evidence_manifest, dict):
            raise ValueError("EvidenceManifest must be a JSON object")

        schemas: dict[str, dict[str, Any]] = {}
        for name, rel in (
            ("LockedSpec", "schemas/LockedSpec.schema.json"),
            ("SealManifest", "schemas/SealManifest.schema.json"),
            ("EvidenceManifest", "schemas/EvidenceManifest.schema.json"),
            ("GateVerdict", "schemas/GateVerdict.schema.json"),
            ("Waiver", "schemas/Waiver.schema.json"),
        ):
            obj = protocol.read_json(rel)
            if not isinstance(obj, dict):
                raise ValueError(f"{name} schema must be a JSON object")
            schemas[name] = obj

        replay_schema: dict[str, Any] | None = None
        if "replay_instructions_ref" in seal_manifest:
            try:
                obj = protocol.read_json("schemas/ReplayInstructionsPayload.schema.json")
                if isinstance(obj, dict):
                    replay_schema = obj
            except Exception:
                replay_schema = None

        run_id = locked_spec.get("run_id")
        if not isinstance(run_id, str) or not run_id.strip():
            raise ValueError("LockedSpec.run_id missing/invalid")
        run_id = run_id.strip()

        tier = locked_spec.get("tier")
        tier_id = str(tier.get("tier_id") or "").strip() if isinstance(tier, dict) else ""
        if not tier_id:
            raise ValueError("LockedSpec.tier.tier_id missing/empty")

        ctx = SCheckContext(
            repo_root=repo_root,
            locked_spec_path=locked_spec_path,
            seal_manifest_path=seal_manifest_path,
            evidence_manifest_path=evidence_manifest_path,
            locked_spec=locked_spec,
            seal_manifest=seal_manifest,
            evidence_manifest=evidence_manifest,
            locked_spec_schema=schemas["LockedSpec"],
            seal_manifest_schema=schemas["SealManifest"],
            evidence_manifest_schema=schemas["EvidenceManifest"],
            gate_verdict_schema=schemas["GateVerdict"],
            waiver_schema=schemas["Waiver"],
            replay_instructions_schema=replay_schema,
            tier_id=tier_id,
            run_id=run_id,
        )

        linear: list[CheckResult] = []
        for module in get_checks():
            linear.extend(module.run(ctx))

        # Verify protocol identity (fail-closed on mismatch)
        proto_check = verify_protocol_identity(
            locked_spec=locked_spec,
            active_pack_id=protocol.pack_id,
            active_manifest_sha256=protocol.manifest_sha256,
            active_pack_name=protocol.pack_name,
            active_source=protocol.source,
            gate_id="S",
        )
        if proto_check is not None:
            linear.insert(0, proto_check)

        first = _first_fail(linear)

        evidence_ref = _make_object_ref(repo_root, evidence_manifest_path, object_id=f"evidence-manifest-{run_id}")
        locked_ref = _make_object_ref(repo_root, locked_spec_path, object_id=f"locked-spec-{run_id}")
        seal_ref = _make_object_ref(repo_root, seal_manifest_path, object_id=f"seal-manifest-{run_id}")

        if first is None:
            verdict_obj: dict[str, Any] = {
                "schema_version": "1.0.0",
                "run_id": run_id,
                "gate_id": "S",
                "verdict": "GO",
                "failure_category": None,
                "failures": [],
                "evidence_manifest_ref": evidence_ref,
                "evaluated_at": EVALUATED_AT,
                "evaluator": EVALUATOR,
            }
        else:
            category = _select_failure_category(protocol, gate_id="S", first=first)
            remediation = first.remediation_next_instruction or "Do fix the primary failure then re-run S."
            verdict_obj = {
                "schema_version": "1.0.0",
                "run_id": run_id,
                "gate_id": "S",
                "verdict": "NO-GO",
                "failure_category": category,
                "failures": [
                    {
                        "id": _stable_failure_id("S", first.check_id, 1),
                        "category": category,
                        "rule_id": first.check_id,
                        "message": first.message,
                        "evidence_refs": [evidence_ref, locked_ref, seal_ref],
                    }
                ],
                "remediation": {"next_instruction": remediation, "constraints": []},
                "evidence_manifest_ref": evidence_ref,
                "evaluated_at": EVALUATED_AT,
                "evaluator": EVALUATOR,
            }

        gv_schema = schemas.get("GateVerdict")
        if not isinstance(gv_schema, dict):
            raise ValueError("Missing GateVerdict schema; cannot validate output deterministically")
        verrs = validate_schema(verdict_obj, gv_schema, root_schema=gv_schema, path="GateVerdict")
        if verrs:
            first_err = verrs[0]
            raise ValueError(f"GateVerdict output schema invalid at {first_err.path}: {first_err.message}")

        _write_json_deterministic(out_path, verdict_obj)

        return 0 if first is None else 2

    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else 3
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
