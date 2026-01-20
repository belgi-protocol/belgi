#!/usr/bin/env python3
"""C1 Prompt Compiler (IntentSpec.core.md -> LockedSpec.json).

Implements the deterministic, fail-closed compilation boundary for C1.

Core guarantees:
- Deterministic parsing: extract exactly one fenced YAML block (```yaml ... ```).
- Schema validation: IntentSpec and output LockedSpec must validate.
- Confinement: all file operations are repo-root jailed and symlink-rejecting.
- Determinism: stable JSON serialization with explicit '\n'.
- Atomicity: atomic write via temp + fsync + os.replace.

Invariants contract:
- C1 is responsible for compiling `LockedSpec.invariants[]` from the human-authored intent.
- Invariant `id` tokens are the stable rule identifiers that R1 evidence (`policy.invariant_eval`) may reference.
- Gate Q enforces invariants are present/non-empty; Gate R enforces invariant evaluation evidence.

Exit codes:
- 0: success
- 3: usage/internal error (fail-closed)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

from importlib.metadata import PackageNotFoundError, version as pkg_version

from belgi.core.jail import normalize_repo_rel, resolve_repo_rel_path
from belgi.core.schema import SchemaError, validate_schema
from belgi.protocol.pack import ProtocolContext, get_builtin_protocol_context, load_protocol_context_from_dir

from chain.logic.q_checks.yaml_subset import YamlParseError, extract_single_fenced_yaml, parse_yaml_subset




EVALUATED_AT = "1970-01-01T00:00:00Z"
COMPILER_ID = "chain/compiler_c1_intent.py"
COMPILER_VERSION = "1.0"


class _UserInputError(RuntimeError):
    pass


def _validate_repo_rel(rel: str) -> str:
    try:
        return normalize_repo_rel(rel, allow_backslashes=True)
    except ValueError as e:
        raise _UserInputError(str(e)) from e


def _resolve_repo_path(
    repo_root: Path,
    rel: str,
    *,
    must_exist: bool,
    must_be_file: bool | None = None,
) -> Path:
    try:
        return resolve_repo_rel_path(
            repo_root,
            rel,
            must_exist=must_exist,
            must_be_file=must_be_file,
            allow_backslashes=True,
            forbid_symlinks=True,
        )
    except ValueError as e:
        raise _UserInputError(str(e)) from e


def _require_dev_mode(flag_name: str) -> None:
    if os.environ.get("CI"):
        raise _UserInputError(f"{flag_name} is not allowed in CI")
    if os.environ.get("BELGI_DEV") != "1":
        raise _UserInputError(f"{flag_name} requires BELGI_DEV=1")


def _load_protocol_context(*, repo_root: Path, args: argparse.Namespace) -> ProtocolContext:
    if isinstance(getattr(args, "protocol_pack", None), str) and args.protocol_pack:
        pack_root = _resolve_repo_path(repo_root, str(args.protocol_pack), must_exist=True, must_be_file=None)
        if not pack_root.is_dir():
            raise _UserInputError("--protocol-pack must point to a directory containing ProtocolPackManifest.json")
        return load_protocol_context_from_dir(pack_root=pack_root, source="override")

    if isinstance(getattr(args, "dev_protocol_pack", None), str) and args.dev_protocol_pack:
        _require_dev_mode("--dev-protocol-pack")
        print("DEV MODE: protocol pack override enabled", file=sys.stderr)
        pack_root = Path(str(args.dev_protocol_pack)).resolve()
        if not pack_root.exists() or not pack_root.is_dir():
            raise _UserInputError("--dev-protocol-pack must point to an existing directory")
        return load_protocol_context_from_dir(pack_root=pack_root, source="dev-override")

    return get_builtin_protocol_context()


def _atomic_write_text(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".tmp.c1")
    with tmp.open("w", encoding="utf-8", errors="strict", newline="\n") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(str(tmp), str(path))


def _atomic_write_json(path: Path, obj: object) -> None:
    _atomic_write_text(path, json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp.c1")
    with tmp.open("wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(str(tmp), str(path))


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_relpath(repo_root: Path, p: Path) -> str:
    try:
        return p.resolve().relative_to(repo_root.resolve()).as_posix()
    except Exception:
        return p.as_posix()


def _git_head_sha(repo_root: Path) -> str:
    try:
        out = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(repo_root))
    except Exception as e:
        raise _UserInputError("git rev-parse HEAD failed") from e
    s = out.decode("utf-8", errors="strict").strip()
    if not re.fullmatch(r"[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64}", s):
        raise _UserInputError(f"unexpected git HEAD sha: {s!r}")
    return s


def _git_is_clean(repo_root: Path) -> bool:
    try:
        out = subprocess.check_output(["git", "status", "--porcelain"], cwd=str(repo_root))
    except Exception as e:
        raise _UserInputError("git status --porcelain failed") from e
    s = out.decode("utf-8", errors="strict")
    return s.strip() == ""


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="strict"))


def _format_schema_errors(errors: Iterable[SchemaError]) -> str:
    parts: list[str] = []
    for e in errors:
        parts.append(f"{e.path}: {e.message}")
    return "\n".join(parts)


def _expect_scope_string(intent_obj: dict[str, Any]) -> str:
    scope = intent_obj.get("scope")
    if not isinstance(scope, dict):
        return "allowed_dirs: []; forbidden_dirs: []; max_touched_files: null; max_loc_delta: null"

    allowed = scope.get("allowed_dirs")
    forbidden = scope.get("forbidden_dirs")
    max_touched_files = scope.get("max_touched_files")
    max_loc_delta = scope.get("max_loc_delta")

    def fmt_list(v: Any) -> str:
        if not isinstance(v, list):
            return "[]"
        if any(not isinstance(x, str) for x in v):
            return "[INVALID]"
        return "[" + ", ".join([x for x in v]) + "]"

    mtf = max_touched_files if isinstance(max_touched_files, int) and not isinstance(max_touched_files, bool) else None
    mld = max_loc_delta if isinstance(max_loc_delta, int) and not isinstance(max_loc_delta, bool) else None

    mtf_s = str(mtf) if mtf is not None else "null"
    mld_s = str(mld) if mld is not None else "null"

    return (
        f"allowed_dirs: {fmt_list(allowed)}; forbidden_dirs: {fmt_list(forbidden)}; "
        f"max_touched_files: {mtf_s}; max_loc_delta: {mld_s}"
    )


def _expect_success_criteria(intent_obj: dict[str, Any]) -> str:
    acceptance = intent_obj.get("acceptance")
    if not isinstance(acceptance, dict):
        return ""
    sc = acceptance.get("success_criteria")
    if not isinstance(sc, list):
        return ""
    if any(not isinstance(x, str) for x in sc):
        return "[INVALID]"
    return "\n".join([f"- {x}" for x in sc])


def _compile_invariants(intent_obj: dict[str, Any]) -> list[dict[str, str]]:
    acceptance = intent_obj.get("acceptance")
    sc: list[str] = []
    if isinstance(acceptance, dict):
        raw = acceptance.get("success_criteria")
        if isinstance(raw, list):
            sc = [x for x in raw if isinstance(x, str) and x.strip()]

    invs: list[dict[str, str]] = []
    for i, text in enumerate(sc, start=1):
        invs.append(
            {
                "id": f"INV-SC-{i:03d}",
                "description": f"Success criterion: {text}",
                "severity": "success_criteria",
            }
        )

    if not invs:
        invs.append(
            {
                "id": "INV-INTENT-001",
                "description": "Run MUST satisfy the declared intent success criteria.",
                "severity": "success_criteria",
            }
        )
    return invs


def _tier_name_for(tier_id: str) -> str:
    if tier_id == "tier-0":
        return "Tier 0"
    if tier_id == "tier-1":
        return "Tier 1"
    if tier_id == "tier-2":
        return "Tier 2"
    if tier_id == "tier-3":
        return "Tier 3"
    return f"Tier ({tier_id})"


def _parse_kv_pair(arg: str, *, name: str) -> tuple[str, str]:
    if not isinstance(arg, str) or "=" not in arg:
        raise _UserInputError(f"{name} must be in ID=repo/relative/path form")
    k, v = arg.split("=", 1)
    k = k.strip()
    v = v.strip()
    if not k or not v:
        raise _UserInputError(f"{name} must be in ID=repo/relative/path form")
    return k, v


def _object_ref(repo_root: Path, *, object_id: str, storage_ref: str) -> dict[str, str]:
    p = _resolve_repo_path(repo_root, storage_ref, must_exist=True, must_be_file=True)
    rel = _safe_relpath(repo_root, p)
    rel = _validate_repo_rel(rel)
    return {"id": object_id, "hash": _sha256_file(p), "storage_ref": rel}


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="C1 compiler: compile IntentSpec.core.md into LockedSpec.json")
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
    ap.add_argument("--intent-spec", required=True, help="Path to IntentSpec.core.md (repo-relative)")
    ap.add_argument("--out", required=True, help="Output path for LockedSpec.json (repo-relative)")
    ap.add_argument("--run-id", required=True, help="Run identifier")

    ap.add_argument("--repo-ref", required=True, help="Pinned repository reference string")
    pb_group = ap.add_mutually_exclusive_group(required=True)
    pb_group.add_argument(
        "--prompt-bundle",
        default=None,
        help="Prompt bundle object ref in ID=repo/relative/path form (hash is computed)",
    )
    pb_group.add_argument(
        "--prompt-bundle-out",
        default=None,
        help="Repo-relative output path for assembled PromptBundle bytes (C1 will write this file)",
    )
    ap.add_argument(
        "--prompt-bundle-id",
        default="prompt.bundle",
        help="ObjectRef id for LockedSpec.prompt_bundle_ref when assembling (default: prompt.bundle)",
    )
    ap.add_argument(
        "--prompt-block-hashes-out",
        default=None,
        help=(
            "(assembly mode) Optional repo-relative output path for JSON mapping {block_id: sha256_hex}. "
            "Default: sibling 'prompt_block_hashes.json' next to --prompt-bundle-out."
        ),
    )
    ap.add_argument(
        "--prompt-bundle-policy-out",
        default=None,
        help=(
            "(assembly mode) Optional repo-relative output path for PolicyReportPayload documenting bundle integrity. "
            "Default: sibling 'policy.prompt_bundle.json' next to --prompt-bundle-out."
        ),
    )
    ap.add_argument(
        "--tolerances",
        required=True,
        help="Tier tolerances object ref in ID=repo/relative/path form (hash is computed)",
    )

    ap.add_argument("--envelope-id", required=True, help="Environment envelope identifier")
    ap.add_argument("--envelope-description", required=True, help="Environment envelope description")
    ap.add_argument("--expected-runner", required=True, help="Expected runner string")
    ap.add_argument(
        "--toolchain-ref",
        action="append",
        default=[],
        help="Pinned toolchain object ref in ID=repo/relative/path form (repeatable; at least one required)",
    )

    ap.add_argument(
        "--attestation-pubkey",
        default=None,
        help="(tier-2/3 required) Attestation public key ref in ID=repo/relative/path form",
    )
    ap.add_argument(
        "--seal-pubkey",
        default=None,
        help="(tier-2/3 required) Seal public key ref in ID=repo/relative/path form",
    )
    return ap.parse_args(argv)


def _pb_sort_key(block_id: str) -> tuple[int, str]:
    m = re.fullmatch(r"PB-(\d{3})", block_id)
    if m is None:
        return (10**9, block_id)
    return (int(m.group(1)), block_id)


def _prompt_block_ids_for_tier(tier_id: str) -> list[str]:
    base = [
        "PB-001",
        "PB-002",
        "PB-003",
        "PB-004",
        "PB-005",
        "PB-006",
        "PB-007",
        "PB-008",
        "PB-012",
        "PB-013",
        "PB-014",
    ]
    if tier_id in ("tier-1", "tier-2", "tier-3"):
        base.extend(["PB-009", "PB-010", "PB-011"])
    if tier_id not in ("tier-0", "tier-1", "tier-2", "tier-3"):
        raise _UserInputError(f"unsupported tier_id for PromptBundle assembly: {tier_id!r}")
    return sorted(set(base), key=_pb_sort_key)


def _render_prompt_block(*, block_id: str, locked_spec_preimage: dict[str, Any]) -> bytes:
    """Deterministically render prompt block bytes.

    This intentionally uses the LockedSpec *preimage* (without prompt_bundle_ref) to avoid self-reference.
    """
    run_id = locked_spec_preimage.get("run_id")
    tier_obj = locked_spec_preimage.get("tier") if isinstance(locked_spec_preimage.get("tier"), dict) else {}
    tier_id = tier_obj.get("tier_id") if isinstance(tier_obj, dict) else None
    intent = locked_spec_preimage.get("intent") if isinstance(locked_spec_preimage.get("intent"), dict) else {}
    constraints = (
        locked_spec_preimage.get("constraints") if isinstance(locked_spec_preimage.get("constraints"), dict) else {}
    )
    invariants = locked_spec_preimage.get("invariants") if isinstance(locked_spec_preimage.get("invariants"), list) else []

    lines: list[str] = [f"# {block_id}"]

    if block_id == "PB-001":
        lines.extend(
            [
                "You are proposing code changes. Gates are authoritative; comply with LockedSpec constraints.",
                "Produce deterministic, auditable outputs: explicit file list, explicit commands, no hidden steps.",
            ]
        )
    elif block_id == "PB-002":
        lines.extend(
            [
                "Canonical chain reference: CANONICALS.md#canonical-chain",
                "Principle: LLMs propose; gates dispose.",
            ]
        )
    elif block_id == "PB-003":
        lines.append("Publication posture reference: CANONICALS.md#publication-posture")
    elif block_id == "PB-004":
        summary_obj = {
            "run_id": run_id,
            "tier_id": tier_id,
            "intent": {"intent_id": intent.get("intent_id"), "title": intent.get("title")},
        }
        lines.append("LockedSpec summary (header only):")
        lines.append(json.dumps(summary_obj, indent=2, sort_keys=True, ensure_ascii=False))
    elif block_id == "PB-005":
        ap = constraints.get("allowed_paths")
        fp = constraints.get("forbidden_paths")
        lines.append("Constraints (allowed/forbidden paths):")
        lines.append(json.dumps({"allowed_paths": ap, "forbidden_paths": fp}, indent=2, sort_keys=True, ensure_ascii=False))
    elif block_id == "PB-006":
        lines.append("Constraints (scope budgets):")
        lines.append(
            json.dumps(
                {
                    "max_touched_files": constraints.get("max_touched_files"),
                    "max_loc_delta": constraints.get("max_loc_delta"),
                },
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
        )
    elif block_id == "PB-007":
        inv_ids: list[str] = []
        for inv in invariants:
            if isinstance(inv, dict):
                iid = inv.get("id")
                if isinstance(iid, str) and iid:
                    inv_ids.append(iid)
        lines.append("Invariants (ids):")
        lines.extend([f"- {x}" for x in inv_ids])
    elif block_id == "PB-008":
        lines.append("Evidence obligations (category-level): see gates/GATE_R.md and tiers/tier-packs.md")
    elif block_id == "PB-009":
        lines.append("Command log reminder: structured command records required at higher tiers.")
    elif block_id == "PB-010":
        lines.append("Tests policy reminder: see gates/GATE_R.md#r5--tests-policy-satisfied")
    elif block_id == "PB-011":
        lines.append("Envelope attestation reminder: see gates/GATE_R.md#r6--envelope-attestation-satisfied")
    elif block_id == "PB-012":
        lines.append("Supply chain evidence obligation: see gates/GATE_R.md#r7--supply-chain-changes-detected-and-accounted-for")
    elif block_id == "PB-013":
        lines.append("Adversarial scan evidence obligation: see gates/GATE_R.md#r8--adversarial-diff-scan-category-level")
    elif block_id == "PB-014":
        lines.append("Output format contract: be explicit, auditable, deterministic.")
    else:
        raise _UserInputError(f"unsupported prompt block id for assembly: {block_id}")

    text = "\n".join(lines).replace("\r\n", "\n").replace("\r", "\n") + "\n"
    return text.encode("utf-8", errors="strict")


def _assemble_prompt_bundle(
    *,
    locked_spec_preimage: dict[str, Any],
) -> tuple[list[str], dict[str, str], bytes, str, str]:
    tier_obj = locked_spec_preimage.get("tier")
    if not isinstance(tier_obj, dict):
        raise _UserInputError("LockedSpec.tier missing/invalid")
    tier_id = tier_obj.get("tier_id")
    if not isinstance(tier_id, str) or not tier_id.strip():
        raise _UserInputError("LockedSpec.tier.tier_id missing/invalid")

    block_ids = _prompt_block_ids_for_tier(tier_id)
    blocks: list[bytes] = []
    block_hashes: dict[str, str] = {}

    for bid in block_ids:
        b = _render_prompt_block(block_id=bid, locked_spec_preimage=locked_spec_preimage)
        h = _sha256_bytes(b)
        blocks.append(b)
        block_hashes[bid] = h

    sep = "\n\n---\n\n".encode("utf-8", errors="strict")
    prompt_bundle_bytes = sep.join(blocks)

    manifest_text = "".join([f"{bid} {block_hashes[bid]}\n" for bid in block_ids])
    manifest_bytes = manifest_text.encode("utf-8", errors="strict")
    prompt_bundle_manifest_hash = _sha256_bytes(manifest_bytes)
    prompt_bundle_bytes_hash = _sha256_bytes(prompt_bundle_bytes)

    return block_ids, block_hashes, prompt_bundle_bytes, prompt_bundle_manifest_hash, prompt_bundle_bytes_hash


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parse_args(argv)
        repo_root = Path(args.repo).resolve()
        if not repo_root.is_dir():
            raise _UserInputError("--repo must be an existing directory")

        protocol = _load_protocol_context(repo_root=repo_root, args=args)

        intent_path = _resolve_repo_path(repo_root, str(args.intent_spec), must_exist=True, must_be_file=True)
        out_path = _resolve_repo_path(repo_root, str(args.out), must_exist=False)

        if not isinstance(args.run_id, str) or not args.run_id.strip():
            raise _UserInputError("--run-id missing/empty")
        if not isinstance(args.repo_ref, str) or not args.repo_ref.strip():
            raise _UserInputError("--repo-ref missing/empty")

        if os.environ.get("CI") and not _git_is_clean(repo_root):
            raise _UserInputError("repo is dirty; refuse to emit LockedSpec with dirty_flag=false")

        intent_text = intent_path.read_text(encoding="utf-8", errors="strict")
        yaml_count, yaml_text = extract_single_fenced_yaml(intent_text)
        if yaml_count != 1 or yaml_text is None:
            raise _UserInputError("IntentSpec.core.md must contain exactly one fenced YAML block (```yaml ... ```)")

        try:
            parsed = parse_yaml_subset(yaml_text)
        except YamlParseError as e:
            raise _UserInputError(f"IntentSpec YAML parse error: {e}") from e

        if not isinstance(parsed, dict):
            raise _UserInputError("IntentSpec YAML must parse to an object/mapping")

        intent_schema = protocol.read_json("schemas/IntentSpec.schema.json")
        if not isinstance(intent_schema, dict):
            raise _UserInputError("IntentSpec schema is not a JSON object")

        intent_errors = validate_schema(parsed, intent_schema, root_schema=intent_schema, path="intent_spec")
        if intent_errors:
            raise _UserInputError("IntentSpec schema validation failed:\n" + _format_schema_errors(intent_errors))

        tier_obj = parsed.get("tier")
        if not isinstance(tier_obj, dict):
            raise _UserInputError("IntentSpec.tier missing/invalid")
        tier_id = tier_obj.get("tier_pack_id")
        if not isinstance(tier_id, str) or not tier_id.strip():
            raise _UserInputError("IntentSpec.tier.tier_pack_id missing/invalid")

        # Align with Gate Q non-authoritative field enforcement early.
        if tier_id in ("tier-1", "tier-2", "tier-3"):
            proj_ext = parsed.get("project_extension")
            if isinstance(proj_ext, str) and proj_ext.strip():
                raise _UserInputError("IntentSpec.project_extension must be empty for tier-1..3")
            waivers_requested = parsed.get("waivers_requested")
            if isinstance(waivers_requested, list) and len(waivers_requested) > 0:
                raise _UserInputError("IntentSpec.waivers_requested must be empty for tier-1..3")

        pb_mode_ref = str(args.prompt_bundle) if args.prompt_bundle is not None else None
        pb_mode_out = str(args.prompt_bundle_out) if args.prompt_bundle_out is not None else None

        pb_id: str
        pb_ref: str
        pb_out_path: Path | None = None
        pb_hashes_out_path: Path | None = None
        pb_policy_out_path: Path | None = None

        if pb_mode_ref is not None:
            pb_id, pb_ref = _parse_kv_pair(pb_mode_ref, name="--prompt-bundle")
            if pb_ref.replace("\\", "/") == "belgi/templates/PromptBundle.blocks.md":
                raise _UserInputError(
                    "--prompt-bundle must reference assembled PromptBundle bytes; got the registry markdown. "
                    "Use --prompt-bundle-out to have C1 assemble the PromptBundle deterministically."
                )
        else:
            if pb_mode_out is None:
                raise _UserInputError("Either --prompt-bundle or --prompt-bundle-out is required")
            pb_out_path = _resolve_repo_path(repo_root, pb_mode_out, must_exist=False)
            pb_id = str(args.prompt_bundle_id)
            if not pb_id.strip():
                raise _UserInputError("--prompt-bundle-id missing/empty")

            hashes_rel = str(args.prompt_block_hashes_out) if args.prompt_block_hashes_out is not None else None
            if hashes_rel is None:
                pb_hashes_out_path = pb_out_path.with_name("prompt_block_hashes.json")
            else:
                pb_hashes_out_path = _resolve_repo_path(repo_root, hashes_rel, must_exist=False)

            policy_rel = str(args.prompt_bundle_policy_out) if args.prompt_bundle_policy_out is not None else None
            if policy_rel is None:
                pb_policy_out_path = pb_out_path.with_name("policy.prompt_bundle.json")
            else:
                pb_policy_out_path = _resolve_repo_path(repo_root, policy_rel, must_exist=False)

            pb_ref = _validate_repo_rel(_safe_relpath(repo_root, pb_out_path))
        tol_id, tol_ref = _parse_kv_pair(str(args.tolerances), name="--tolerances")

        toolchain_pairs = [str(x) for x in (args.toolchain_ref or [])]
        if len(toolchain_pairs) == 0:
            raise _UserInputError("--toolchain-ref must be provided at least once")

        toolchain_refs: list[dict[str, str]] = []
        seen_toolchain_ids: set[str] = set()
        for raw in toolchain_pairs:
            tc_id, tc_ref = _parse_kv_pair(raw, name="--toolchain-ref")
            if tc_id in seen_toolchain_ids:
                raise _UserInputError(f"duplicate toolchain id: {tc_id}")
            seen_toolchain_ids.add(tc_id)
            toolchain_refs.append(_object_ref(repo_root, object_id=tc_id, storage_ref=tc_ref))

        env_envelope: dict[str, Any] = {
            "id": str(args.envelope_id),
            "description": str(args.envelope_description),
            "expected_runner": str(args.expected_runner),
            "pinned_toolchain_refs": toolchain_refs,
        }

        if tier_id in ("tier-2", "tier-3"):
            if args.attestation_pubkey is None or args.seal_pubkey is None:
                raise _UserInputError("tier-2/3 require --attestation-pubkey and --seal-pubkey")
            ap_id, ap_ref = _parse_kv_pair(str(args.attestation_pubkey), name="--attestation-pubkey")
            sp_id, sp_ref = _parse_kv_pair(str(args.seal_pubkey), name="--seal-pubkey")
            env_envelope["attestation_pubkey_ref"] = _object_ref(repo_root, object_id=ap_id, storage_ref=ap_ref)
            env_envelope["seal_pubkey_ref"] = _object_ref(repo_root, object_id=sp_id, storage_ref=sp_ref)

        # Map intent fields exactly as Gate Q recomputes.
        locked_intent = {
            "intent_id": parsed.get("intent_id"),
            "title": parsed.get("title"),
            "narrative": parsed.get("goal"),
            "scope": _expect_scope_string(parsed),
            "success_criteria": _expect_success_criteria(parsed),
        }

        scope = parsed.get("scope")
        if not isinstance(scope, dict):
            raise _UserInputError("IntentSpec.scope missing/invalid")

        locked_constraints: dict[str, Any] = {
            "allowed_paths": scope.get("allowed_dirs"),
            "forbidden_paths": scope.get("forbidden_dirs"),
        }
        if "max_touched_files" in scope:
            locked_constraints["max_touched_files"] = scope.get("max_touched_files")
        if "max_loc_delta" in scope:
            locked_constraints["max_loc_delta"] = scope.get("max_loc_delta")

        try:
            belgi_version = pkg_version("belgi")
        except PackageNotFoundError:
            if os.environ.get("CI"):
                raise _UserInputError("belgi package metadata version unavailable in CI")
            if os.environ.get("BELGI_DEV") != "1":
                raise _UserInputError("belgi package metadata version unavailable; install belgi or set BELGI_DEV=1")
            belgi_version_path = _resolve_repo_path(repo_root, "VERSION", must_exist=True, must_be_file=True)
            belgi_version = belgi_version_path.read_text(encoding="utf-8", errors="strict").strip()
            if not belgi_version:
                raise _UserInputError("VERSION file is empty")

        locked_spec: dict[str, Any] = {
            "schema_version": "1.0.0",
            "belgi_version": belgi_version,
            "run_id": str(args.run_id),
            "intent": locked_intent,
            "tier": {
                "tier_id": tier_id,
                "tier_name": _tier_name_for(tier_id),
                "tolerances_ref": _object_ref(repo_root, object_id=tol_id, storage_ref=tol_ref),
            },
            "environment_envelope": env_envelope,
            "invariants": _compile_invariants(parsed),
            "constraints": locked_constraints,
            "compilation": {
                "compiler_id": COMPILER_ID,
                "compiler_version": COMPILER_VERSION,
                "compiled_at": EVALUATED_AT,
                "source_hashes": [
                    _sha256_file(intent_path),
                ],
            },
            "upstream_state": {
                "repo_ref": str(args.repo_ref),
                "commit_sha": _git_head_sha(repo_root),
                "dirty_flag": False,
            },
            "protocol_pack": {
                "pack_id": protocol.pack_id,
                "manifest_sha256": protocol.manifest_sha256,
                "pack_name": protocol.pack_name,
                "source": protocol.source,
            },
        }

        # doc_impact is always emitted to keep tier-2/3 deterministic and to keep mapping stable.
        locked_spec["doc_impact"] = parsed.get("doc_impact")

        pub_intent = parsed.get("publication_intent")
        if pub_intent is not None:
            locked_spec["publication_intent"] = pub_intent

        if pb_out_path is not None:
            # Bind prompt bundle to LockedSpec preimage (excluding prompt_bundle_ref) to prevent self-reference.
            preimage = dict(locked_spec)
            block_ids, block_hashes, pb_bytes, pb_manifest_hash, pb_bytes_hash = _assemble_prompt_bundle(
                locked_spec_preimage=preimage
            )

            assert pb_hashes_out_path is not None
            assert pb_policy_out_path is not None

            pb_out_path.parent.mkdir(parents=True, exist_ok=True)
            pb_hashes_out_path.parent.mkdir(parents=True, exist_ok=True)
            pb_policy_out_path.parent.mkdir(parents=True, exist_ok=True)

            _atomic_write_bytes(pb_out_path, pb_bytes)
            _atomic_write_json(pb_hashes_out_path, block_hashes)

            policy_payload: dict[str, Any] = {
                "schema_version": "1.0.0",
                "run_id": str(args.run_id),
                "generated_at": EVALUATED_AT,
                "summary": {"total_checks": 1, "passed": 1, "failed": 0},
                "checks": [
                    {
                        "check_id": "policy.prompt_bundle",
                        "passed": True,
                        "message": f"prompt_bundle_manifest_hash={pb_manifest_hash} prompt_bundle_bytes_hash={pb_bytes_hash}",
                    }
                ],
                "block_ids": list(block_ids),
                "block_hashes": dict(block_hashes),
                "prompt_bundle_manifest_hash": pb_manifest_hash,
                "prompt_bundle_bytes_hash": pb_bytes_hash,
                "compiler_id": COMPILER_ID,
                "compiler_version": COMPILER_VERSION,
                "prompt_bundle_storage_ref": pb_ref,
            }
            _atomic_write_json(pb_policy_out_path, policy_payload)

        locked_spec["prompt_bundle_ref"] = _object_ref(repo_root, object_id=pb_id, storage_ref=pb_ref)

        locked_schema = protocol.read_json("schemas/LockedSpec.schema.json")
        if not isinstance(locked_schema, dict):
            raise _UserInputError("LockedSpec schema is not a JSON object")

        locked_errors = validate_schema(locked_spec, locked_schema, root_schema=locked_schema, path="locked_spec")
        if locked_errors:
            raise _UserInputError("LockedSpec schema validation failed:\n" + _format_schema_errors(locked_errors))

        out_path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_json(out_path, locked_spec)
        return 0

    except _UserInputError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 3
    except Exception as e:
        print(f"INTERNAL ERROR: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
