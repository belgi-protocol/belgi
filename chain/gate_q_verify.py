#!/usr/bin/env python3
"""Deterministic Gate Q verifier (pre-LLM) in the "chain/" layout.

Gate Q is executed as an ordered plugin pipeline (registry):
  chain/logic/q_checks/registry.py

This implementation currently covers the checks needed by the public fixture
suite and follows the Gate Q contract for deterministic failure selection.

Exit codes:
- 0: GO
- 2: NO-GO
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
from chain.logic.tier_packs import parse_tier_params
from chain.logic.q_checks.context import QCheckContext
from chain.logic.q_checks.registry import get_checks
from chain.logic.q_checks.yaml_subset import YamlParseError, extract_single_fenced_yaml, parse_yaml_subset

from belgi.protocol.pack import (
    ProtocolContext,
    get_builtin_protocol_context,
    load_protocol_context_from_dir,
    DevOverrideNotAllowedError,
)


EVALUATED_AT = "1970-01-01T00:00:00Z"
EVALUATOR = "chain/gate_q_verify.py"

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


def _select_failure_category(protocol: ProtocolContext, *, gate_id: str, first: CheckResult) -> str:
    category = first.category.strip() if isinstance(first.category, str) and first.category.strip() else ""
    if not category:
        category = _failure_category_for(first.check_id)
    taxo_ids = _load_taxonomy_ids(protocol)
    if category not in taxo_ids:
        raise ValueError(
            f"INTERNAL ERROR: Gate {gate_id} category_id not in taxonomy: {category!r} (check_id={first.check_id!r})"
        )
    return category


def _first_missing_required_evidence_kind_q(ctx: QCheckContext) -> str:
    required = ctx.tier_params.get("required_evidence_kinds_q")
    if not isinstance(required, list):
        raise ValueError("Tier required_evidence_kinds_q missing/invalid; cannot select missing_kind deterministically")

    ordered: list[str] = []
    seen: set[str] = set()
    for x in required:
        if not isinstance(x, str) or not x:
            continue
        if x in seen:
            continue
        seen.add(x)
        ordered.append(x)
    if not ordered:
        raise ValueError("Tier required_evidence_kinds_q empty/invalid after normalization")

    present: set[str] = set()
    if isinstance(ctx.evidence_manifest, dict):
        artifacts = ctx.evidence_manifest.get("artifacts")
        if isinstance(artifacts, list):
            for a in artifacts:
                if not isinstance(a, dict):
                    continue
                k = a.get("kind")
                if isinstance(k, str) and k:
                    present.add(k)

    for k in ordered:
        if k not in present:
            return k

    raise ValueError("Q-EVIDENCE-002 primary but no missing kind detected")


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


def _load_schema(protocol: ProtocolContext, rel: str) -> dict[str, Any]:
    obj = protocol.read_json(rel)
    if not isinstance(obj, dict):
        raise ValueError(f"Schema is not a JSON object: {rel}")
    return obj


def _require_dev_mode(flag_name: str) -> None:
    """Local dev guard for non-protocol-pack dev flags (--tiers, etc.)."""
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


def _failure_category_for(check_id: str) -> str:
    if check_id.startswith("Q-INTENT-"):
        return "FQ-INTENT-INSUFFICIENT"
    if check_id == "Q1":
        return "FQ-SCHEMA-LOCKEDSPEC-INVALID"
    if check_id == "Q-EVIDENCE-001":
        return "FQ-SCHEMA-EVIDENCEMANIFEST-INVALID"
    if check_id == "Q-EVIDENCE-002":
        return "FQ-EVIDENCE-MISSING"
    if check_id.startswith("Q-DOC"):
        return "FQ-SCHEMA-LOCKEDSPEC-INVALID"
    if check_id.startswith("Q-HOTL"):
        return "FQ-HOTL-MISSING"
    return "FQ-INTENT-INSUFFICIENT"


def _remediation_for(check_id: str) -> str:
    if check_id == "Q-INTENT-001":
        return "Do fix IntentSpec.core.md so it contains exactly one parseable YAML block then re-run Q."
    if check_id == "Q-INTENT-002":
        return "Do fix IntentSpec schema validation errors for missing_field then re-run Q."
    if check_id == "Q-INTENT-003":
        return "Do fix C1 compilation so LockedSpec fields match the deterministic IntentSpec mapping rules then re-run Q."
    if check_id == "Q1":
        return "Do fix LockedSpec schema validation errors for missing_field then re-run Q."
    if check_id == "Q-EVIDENCE-001":
        return "Do fix EvidenceManifest schema validation errors for missing_field then re-run Q."
    if check_id == "Q-EVIDENCE-002":
        return "Do produce required evidence kind missing_kind under the declared envelope then re-run Q."
    return "Do fix the primary failure then re-run Q."


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
    ap = argparse.ArgumentParser(description="Gate Q deterministic verifier (chain)")
    ap.add_argument("--repo", required=True, help="Repo root")
    ap.add_argument("--intent-spec", required=True, help="Path to IntentSpec.core.md")
    ap.add_argument("--locked-spec", required=True, help="Path to LockedSpec.json")
    ap.add_argument("--evidence-manifest", required=True, help="Path to EvidenceManifest.json")
    ap.add_argument("--out", required=True, help="Output path for GateVerdict.json")
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
    return ap.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parse_args(argv)
        repo_root = Path(args.repo).resolve()

        protocol = _load_protocol_context(repo_root=repo_root, args=args)

        intent_path = _resolve_repo_rel_path(repo_root, str(args.intent_spec), must_exist=False)
        locked_path = _resolve_repo_rel_path(repo_root, str(args.locked_spec), must_exist=True, must_be_file=True)
        evidence_path = _resolve_repo_rel_path(repo_root, str(args.evidence_manifest), must_exist=False)
        out_path = _resolve_repo_rel_path(repo_root, str(args.out), must_exist=False)

        tiers_text: str
        if isinstance(args.tiers, str) and args.tiers:
            _require_dev_mode("--tiers")
            tiers_path = _resolve_repo_rel_path(repo_root, str(args.tiers), must_exist=True, must_be_file=True)
            tiers_text = tiers_path.read_text(encoding="utf-8", errors="strict")
        else:
            tiers_text = protocol.read_text("tiers/tier-packs.json")

        if not evidence_path.exists():
            raise ValueError("EvidenceManifest.json missing; cannot emit schema-valid GateVerdict")

        evidence_bytes = evidence_path.read_bytes()

        # Load inputs (fail-closed to Q-INTENT-001 for missing intent file).
        intent_text = ""
        yaml_count = 0
        yaml_text: str | None = None
        intent_obj: dict[str, Any] | None = None
        yaml_err: str | None = None

        if intent_path.exists():
            intent_text = intent_path.read_text(encoding="utf-8", errors="strict")
            yaml_count, yaml_text = extract_single_fenced_yaml(intent_text)
            if yaml_text is not None:
                try:
                    parsed = parse_yaml_subset(yaml_text)
                    if isinstance(parsed, dict):
                        intent_obj = parsed
                    else:
                        yaml_err = "parsed YAML is not an object"
                except YamlParseError as e:
                    yaml_err = str(e)
        else:
            # Missing file must fail Q-INTENT-001.
            yaml_count = 0
            yaml_err = "IntentSpec.core.md missing"

        locked_spec = None
        if locked_path.exists():
            try:
                locked_spec = load_json(locked_path)
            except Exception:
                locked_spec = None

        evidence_manifest = None
        try:
            evidence_manifest = load_json(evidence_path)
        except Exception:
            evidence_manifest = None

        tier_id = None
        if isinstance(locked_spec, dict):
            tier = locked_spec.get("tier")
            if isinstance(tier, dict):
                v = tier.get("tier_id")
                if isinstance(v, str) and v:
                    tier_id = v

        tier_params: dict[str, Any] = {}
        if isinstance(tier_id, str) and tier_id:
            tier_params = parse_tier_params(tiers_text, tier_id)
        else:
            tier_params = {"_tier_parse_error": "LockedSpec.tier.tier_id missing/invalid"}

        schemas: dict[str, dict[str, Any]] = {}
        for name, rel in (
            ("IntentSpec", "schemas/IntentSpec.schema.json"),
            ("LockedSpec", "schemas/LockedSpec.schema.json"),
            ("EvidenceManifest", "schemas/EvidenceManifest.schema.json"),
            ("Waiver", "schemas/Waiver.schema.json"),
            ("HOTLApproval", "schemas/HOTLApproval.schema.json"),
            ("GateVerdict", "schemas/GateVerdict.schema.json"),
        ):
            schemas[name] = _load_schema(protocol, rel)

        run_id = None
        if isinstance(locked_spec, dict):
            rid = locked_spec.get("run_id")
            if isinstance(rid, str) and rid.strip():
                run_id = rid.strip()
        if run_id is None and isinstance(evidence_manifest, dict):
            rid = evidence_manifest.get("run_id")
            if isinstance(rid, str) and rid.strip():
                run_id = rid.strip()
        if not isinstance(run_id, str) or not run_id:
            run_id = "UNKNOWN"

        ctx = QCheckContext(
            repo_root=repo_root,
            run_id=run_id,
            intent_spec_path=intent_path,
            locked_spec_path=locked_path,
            evidence_manifest_path=evidence_path,
            intent_spec_text=intent_text,
            yaml_block_count=yaml_count,
            yaml_text=yaml_text,
            intent_obj=intent_obj,
            yaml_parse_error=yaml_err,
            locked_spec=locked_spec if isinstance(locked_spec, dict) else None,
            evidence_manifest=evidence_manifest if isinstance(evidence_manifest, dict) else None,
            tiers_md=tiers_text,
            tier_id=tier_id,
            tier_params=tier_params,
            schemas=schemas,
        )

        results: list[CheckResult] = []
        for module in get_checks():
            results.extend(module.run(ctx))

        # Verify protocol identity (fail-closed on mismatch)
        proto_check = verify_protocol_identity(
            locked_spec=locked_spec if isinstance(locked_spec, dict) else None,
            active_pack_id=protocol.pack_id,
            active_manifest_sha256=protocol.manifest_sha256,
            active_pack_name=protocol.pack_name,
            active_source=protocol.source,
            gate_id="Q",
        )
        if proto_check is not None:
            results.insert(0, proto_check)

        first = _first_fail(results)

        evidence_ref = {
            "id": f"evidence-manifest-{run_id}",
            "hash": sha256_bytes(evidence_bytes),
            "storage_ref": safe_relpath(repo_root, evidence_path),
        }

        if first is None:
            # Spec: Gate Q MUST emit the locked, immutable LockedSpec used for later stages.
            locked_bytes = locked_path.read_bytes()
            locked_out_path = out_path.parent / "LockedSpec.json"
            locked_out_path.parent.mkdir(parents=True, exist_ok=True)
            with locked_out_path.open("wb") as f:
                f.write(locked_bytes)

            verdict = {
                "schema_version": "1.0.0",
                "run_id": run_id,
                "gate_id": "Q",
                "verdict": "GO",
                "failure_category": None,
                "failures": [],
                "evidence_manifest_ref": evidence_ref,
                "evaluated_at": EVALUATED_AT,
                "evaluator": EVALUATOR,
            }

            gv_schema = schemas.get("GateVerdict")
            if not isinstance(gv_schema, dict):
                raise ValueError("Missing GateVerdict schema; cannot validate output deterministically")
            errs = validate_schema(verdict, gv_schema, root_schema=gv_schema, path="GateVerdict")
            if errs:
                first_err = errs[0]
                raise ValueError(f"GateVerdict output is schema-invalid at {first_err.path}: {first_err.message}")
            _write_json_deterministic(out_path, verdict)
            return 0

        category = _select_failure_category(protocol, gate_id="Q", first=first)
        remediation = first.remediation_next_instruction or _remediation_for(first.check_id)
        if first.check_id == "Q-EVIDENCE-002":
            missing_kind = _first_missing_required_evidence_kind_q(ctx)
            remediation = f"Do produce required evidence kind {missing_kind} under the declared envelope then re-run Q."
        locked_ref = _make_object_ref(repo_root, locked_path, object_id=f"locked-spec-{run_id}")
        verdict = {
            "schema_version": "1.0.0",
            "run_id": run_id,
            "gate_id": "Q",
            "verdict": "NO-GO",
            "failure_category": category,
            "failures": [
                {
                    "id": _stable_failure_id("Q", first.check_id, 1),
                    "category": category,
                    "rule_id": first.check_id,
                    "message": first.message,
                    "evidence_refs": [evidence_ref, locked_ref],
                }
            ],
            "remediation": {
                "next_instruction": remediation,
                "constraints": [],
            },
            "evidence_manifest_ref": evidence_ref,
            "evaluated_at": EVALUATED_AT,
            "evaluator": EVALUATOR,
        }

        gv_schema = schemas.get("GateVerdict")
        if not isinstance(gv_schema, dict):
            raise ValueError("Missing GateVerdict schema; cannot validate output deterministically")
        errs = validate_schema(verdict, gv_schema, root_schema=gv_schema, path="GateVerdict")
        if errs:
            first_err = errs[0]
            raise ValueError(f"GateVerdict output is schema-invalid at {first_err.path}: {first_err.message}")
        _write_json_deterministic(out_path, verdict)
        return 2

    except SystemExit as e:
        if isinstance(e.code, int):
            return e.code
        return 3
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
