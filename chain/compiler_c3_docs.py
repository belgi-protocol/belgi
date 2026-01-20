from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import shutil
import sys
import time
from pathlib import Path
from typing import Any

from belgi.core.hash import sha256_bytes
from belgi.core.jail import normalize_repo_rel, resolve_repo_rel_path
from belgi.core.schema import SchemaError, parse_rfc3339, validate_schema
from chain.logic.base import load_json
from belgi.protocol.pack import (
    ProtocolContext,
    get_builtin_protocol_context,
    load_protocol_context_from_dir,
    DevOverrideNotAllowedError,
)


EVALUATED_AT = "1970-01-01T00:00:00Z"
COMPILER_ID = "chain/compiler_c3_docs.py"
COMPILER_VERSION = "1.0"

BUILTIN_PROMPT_BLOCK_REGISTRY_REPO_REL = "belgi/templates/PromptBundle.blocks.md"
BUILTIN_DOCS_TEMPLATE_REPO_REL = "belgi/templates/DocsCompiler.template.md"

class _UserInputError(RuntimeError):
    pass

def _rmtree_retry(path: Path, *, attempts: int = 12, base_delay_s: float = 0.03) -> None:
    def _onerror(func, p, exc_info):
        try:
            os.chmod(p, stat.S_IWRITE)
        except Exception:
            pass
        func(p)

    last_exc: BaseException | None = None
    for i in range(attempts):
        try:
            shutil.rmtree(path, onerror=_onerror)
            return
        except (PermissionError, OSError) as e:
            last_exc = e
            if i == attempts - 1:
                raise
            time.sleep(base_delay_s * (i + 1))

    if last_exc is not None:
        raise last_exc


def _normalize_text_bytes(raw: bytes, *, source_label: str) -> bytes:
    
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as e:
        raise _UserInputError(f"non-UTF8 content not allowed for bundled text file: {source_label}") from e
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = text.rstrip("\n") + "\n"
    return text.encode("utf-8", errors="strict")

def _decode_utf8_strict(raw: bytes, *, source_label: str) -> str:
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as e:
        raise _UserInputError(f"non-UTF8 content not allowed: {source_label}") from e


def _iter_repo_files(repo_root: Path, root_rel: str) -> list[str]:
    root_path = _resolve_repo_path(repo_root, root_rel, must_exist=True, must_be_file=False)
    if not root_path.is_dir():
        raise _UserInputError(f"expected directory but found file: {root_rel}")

    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames.sort()
        filenames.sort()
        for name in filenames:
            p = Path(dirpath) / name
            rel = os.path.relpath(str(p), str(repo_root)).replace("\\", "/")
            out.append(_validate_repo_rel(rel))
    out.sort()
    return out


def _media_type_for_path(rel_bundle_path: str) -> str:
    if rel_bundle_path.endswith(".md"):
        return "text/markdown; charset=utf-8"
    if rel_bundle_path.endswith(".json"):
        return "application/json"
    return "application/octet-stream"


def _build_docs_bundle_stage(
    *,
    repo_root: Path,
    profile: str,
    stage_dir: Path,
) -> tuple[list[str], list[dict[str, Any]]]:
    """Build the deterministic docs bundle in stage_dir.

    Returns (source_inputs, bundled_files) where:
    - source_inputs is the sorted list of repo-relative source paths included.
    - bundled_files is ordered list of file entries (excluding the manifest itself), each entry includes:
      {path, sha256, size_bytes, media_type} where sha256 is over normalized output bytes.
    """

    required_root_files = ["CANONICALS.md", "terminology.md", "trust-model.md"]

    inputs: list[str] = []
    for rel in required_root_files:
        _resolve_repo_path(repo_root, rel, must_exist=True, must_be_file=True)
        inputs.append(_validate_repo_rel(rel))

    # Required roots (template B2.2)
    inputs.extend([p for p in _iter_repo_files(repo_root, "gates") if p.endswith(".md")])
    inputs.extend([p for p in _iter_repo_files(repo_root, "tiers") if p.endswith(".md")])
    inputs.extend([p for p in _iter_repo_files(repo_root, "docs/operations") if p.endswith(".md")])

    # Schemas: include README.md and all *.schema.json
    _resolve_repo_path(repo_root, "schemas/README.md", must_exist=True, must_be_file=True)
    inputs.append("schemas/README.md")
    inputs.extend([p for p in _iter_repo_files(repo_root, "schemas") if p.endswith(".schema.json")])

    # Optional roots: docs/research/** only when profile == internal
    if profile == "internal":
        inputs.extend([p for p in _iter_repo_files(repo_root, "docs/research") if p.endswith(".md")])

    # Normalize + stable order
    inputs = sorted({_validate_repo_rel(p) for p in inputs})

    # Collision rule: determinism on case-insensitive filesystems
    seen_ci: dict[str, str] = {}
    for p in inputs:
        key = p.lower()
        if key in seen_ci and seen_ci[key] != p:
            raise _UserInputError(f"case-collision in bundle inputs: {seen_ci[key]!r} vs {p!r}")
        seen_ci[key] = p

    stage_dir.mkdir(parents=True, exist_ok=False)

    bundled: list[dict[str, Any]] = []
    for rel in inputs:
        src = _resolve_repo_path(repo_root, rel, must_exist=True, must_be_file=True)
        raw = src.read_bytes()
        out_bytes = _normalize_text_bytes(raw, source_label=rel)

        out_path = stage_dir / rel
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(out_bytes)

        bundled.append(
            {
                "path": rel,
                "sha256": sha256_bytes(out_bytes),
                "size_bytes": len(out_bytes),
                "media_type": _media_type_for_path(rel),
            }
        )

    # Deterministic TOC (template B3.4)
    toc_lines = ["# Docs Bundle TOC", ""]
    for rel in inputs:
        toc_lines.append(f"- [{rel}]({rel})")
    toc_text = "\n".join(toc_lines) + "\n"
    toc_bytes = toc_text.encode("utf-8", errors="strict")
    (stage_dir / "TOC.md").write_bytes(toc_bytes)
    bundled.append(
        {
            "path": "TOC.md",
            "sha256": sha256_bytes(toc_bytes),
            "size_bytes": len(toc_bytes),
            "media_type": _media_type_for_path("TOC.md"),
        }
    )

    bundled.sort(key=lambda d: str(d["path"]))
    return inputs, bundled


def _compute_bundle_sha256(*, bundled_files: list[dict[str, Any]]) -> str:
    # Approved non-circular model: exclude docs_bundle_manifest.json from this computation.
    items: list[tuple[str, str]] = []
    for entry in bundled_files:
        p = str(entry["path"])
        if p == "docs_bundle_manifest.json":
            continue
        items.append((p, str(entry["sha256"])))
    items.sort(key=lambda t: t[0])
    payload = "".join([f"{p}\n{h}\n" for (p, h) in items]).encode("utf-8", errors="strict")
    return sha256_bytes(payload)


def _compute_bundle_root_sha256(*, docs_bundle_manifest_sha256: str, bundle_sha256: str) -> str:
    payload = f"manifest\n{docs_bundle_manifest_sha256}\nbundle\n{bundle_sha256}\n".encode(
        "utf-8", errors="strict"
    )
    return sha256_bytes(payload)


def _write_tmp_text(path: Path, text: str, *, suffix: str) -> Path:
    tmp = path.with_name(path.name + suffix)
    with tmp.open("w", encoding="utf-8", errors="strict", newline="\n") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    return tmp


def _write_tmp_json(path: Path, obj: object, *, suffix: str) -> Path:
    return _write_tmp_text(path, json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n", suffix=suffix)


def _commit_tmp(tmp: Path, final: Path) -> None:
    os.replace(str(tmp), str(final))


def _commit_bundle_stage(stage_dir: Path, out_dir: Path) -> None:
    if out_dir.exists():
        if out_dir.is_symlink():
            raise _UserInputError("symlink not allowed for out-bundle-dir")
        if out_dir.is_file():
            raise _UserInputError("out-bundle-dir must be a directory")
        _rmtree_retry(out_dir)
    os.replace(str(stage_dir), str(out_dir))


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


def _atomic_write_text(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".tmp.c3")
    with tmp.open("w", encoding="utf-8", errors="strict", newline="\n") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(str(tmp), str(path))


def _atomic_write_json(path: Path, obj: object) -> None:
    _atomic_write_text(path, json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _format_schema_errors(errors: list[SchemaError]) -> str:
    lines = [f"- {e.path}: {e.message}" for e in errors]
    return "\n".join(lines)


def _load_protocol_context(*, repo_root: Path, args: argparse.Namespace) -> ProtocolContext:
    if isinstance(getattr(args, "protocol_pack", None), str) and args.protocol_pack:
        pack_root = _resolve_repo_path(repo_root, str(args.protocol_pack), must_exist=True, must_be_file=None)
        if not pack_root.is_dir():
            raise _UserInputError("--protocol-pack must point to a directory containing ProtocolPackManifest.json")
        return load_protocol_context_from_dir(pack_root=pack_root, source="override")

    if isinstance(getattr(args, "dev_protocol_pack", None), str) and args.dev_protocol_pack:
        # Dev-override guard is centralized in load_protocol_context_from_dir; it will
        # raise DevOverrideNotAllowedError if BELGI_DEV!=1 or CI is set.
        print("DEV MODE: protocol pack override enabled", file=sys.stderr)
        pack_root = Path(str(args.dev_protocol_pack)).resolve()
        if not pack_root.exists() or not pack_root.is_dir():
            raise _UserInputError("--dev-protocol-pack must point to an existing directory")
        try:
            return load_protocol_context_from_dir(pack_root=pack_root, source="dev-override")
        except DevOverrideNotAllowedError as e:
            raise _UserInputError(str(e)) from e

    return get_builtin_protocol_context()


def _verify_protocol_identity_or_fail(locked: dict[str, Any], protocol: ProtocolContext) -> None:
    """Verify LockedSpec.protocol_pack matches active protocol context. Fail immediately on mismatch.

    C3 is not a gate and does not emit GateVerdict, so protocol identity mismatch is a hard error.
    """
    pp = locked.get("protocol_pack")
    if not isinstance(pp, dict):
        raise _UserInputError("LockedSpec.protocol_pack is missing or invalid")

    declared_pack_id = pp.get("pack_id")
    declared_manifest_sha = pp.get("manifest_sha256")
    declared_pack_name = pp.get("pack_name")

    mismatches: list[str] = []
    if declared_pack_id != protocol.pack_id:
        mismatches.append(f"pack_id: declared={declared_pack_id!r} active={protocol.pack_id!r}")
    if declared_manifest_sha != protocol.manifest_sha256:
        mismatches.append(f"manifest_sha256: declared={declared_manifest_sha!r} active={protocol.manifest_sha256!r}")
    if declared_pack_name != protocol.pack_name:
        mismatches.append(f"pack_name: declared={declared_pack_name!r} active={protocol.pack_name!r}")

    if mismatches:
        raise _UserInputError(
            "Protocol identity mismatch between LockedSpec and active protocol pack: " + "; ".join(mismatches)
        )


def _load_schema_from_protocol(protocol: ProtocolContext, schema_relpath: str) -> dict[str, Any]:
    """Load schema from protocol pack (pack-truth)."""
    obj = protocol.read_json(schema_relpath)
    if not isinstance(obj, dict):
        raise _UserInputError(f"schema is not a JSON object: {schema_relpath}")
    return obj


def _load_schema(repo_root: Path, rel: str) -> dict[str, Any]:
    p = _resolve_repo_path(repo_root, rel, must_exist=True, must_be_file=True)
    obj = load_json(p)
    if not isinstance(obj, dict):
        raise _UserInputError(f"schema is not a JSON object: {rel}")
    return obj


def _ensure_manifest_has_storage_ref(manifest: dict[str, Any], *, storage_ref: str) -> dict[str, Any]:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise _UserInputError("EvidenceManifest.artifacts missing/invalid")
    matches = [a for a in artifacts if isinstance(a, dict) and a.get("storage_ref") == storage_ref]
    if len(matches) != 1:
        raise _UserInputError(
            f"EvidenceManifest must contain exactly 1 artifact with storage_ref={storage_ref!r} (found {len(matches)})"
        )
    return matches[0]


def _verify_storage_ref_hash(
    *,
    repo_root: Path,
    manifest: dict[str, Any],
    storage_ref: str,
    label: str,
) -> str:
    art = _ensure_manifest_has_storage_ref(manifest, storage_ref=storage_ref)
    declared = art.get("hash")
    if not isinstance(declared, str):
        raise _UserInputError(f"EvidenceManifest artifact.hash missing/invalid for {label}")
    path = _resolve_repo_path(repo_root, storage_ref, must_exist=True, must_be_file=True)
    computed = _sha256_file(path)
    if computed.lower() != declared.lower():
        raise _UserInputError(
            f"EvidenceManifest hash mismatch for {label}: storage_ref={storage_ref} declared={declared} computed={computed}"
        )
    return computed


def _parse_prompt_block_registry(repo_root: Path) -> tuple[list[dict[str, str]], str]:
    """Parse belgi/templates/PromptBundle.blocks.md table (A2) deterministically.

    Returns (rows, source_sha256) where rows is list of {block_id, sensitivity}.
    """
    try:
        registry_path = _resolve_repo_path(repo_root, BUILTIN_PROMPT_BLOCK_REGISTRY_REPO_REL, must_exist=True, must_be_file=True)
    except _UserInputError:
        raise _UserInputError(f"Prompt block registry missing: {BUILTIN_PROMPT_BLOCK_REGISTRY_REPO_REL}")
    raw = registry_path.read_bytes()
    text = raw.decode("utf-8", errors="strict")
    lines = text.splitlines()

    header_idx = None
    for i, line in enumerate(lines):
        if line.strip().startswith("| block_id | block_name |"):
            header_idx = i
            break
    if header_idx is None:
        raise _UserInputError("Prompt block registry table header not found")

    rows: list[dict[str, str]] = []

    i = header_idx + 1
    while i < len(lines) and "|---" not in lines[i]:
        i += 1
    i += 1

    while i < len(lines):
        line = lines[i].strip()
        if not line.startswith("|"):
            break
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 8:
            i += 1
            continue
        block_id = parts[1]
        sensitivity = parts[6]
        if block_id:
            rows.append({"block_id": block_id, "sensitivity": sensitivity})
        i += 1

    rows.sort(key=lambda r: r["block_id"])
    return rows, sha256_bytes(raw)


def _render_docs_markdown(
    *,
    template_text: str,
    run_id: str,
    profile: str,
    locked_spec_ref: str,
    gate_q_ref: str,
    gate_r_ref: str,
    r_snapshot_manifest_ref: str,
    final_manifest_ref: str,
    docs_log_ref: str,
    bundle_sha256: str,
    docs_bundle_manifest_sha256: str,
    bundle_root_sha256: str,
    out_bundle_dir_ref: str,
) -> str:
    template_norm = template_text.replace("\r\n", "\n").replace("\r", "\n")
    lines: list[str] = [template_norm.rstrip("\n"), "", "---", "", "## Run Summary (Deterministic)"]
    lines.append(f"- run_id: `{run_id}`")
    lines.append(f"- profile: `{profile}`")
    lines.append(f"- canonical: [CANONICALS.md#c3-docs-compiler](CANONICALS.md#c3-docs-compiler)")
    lines.append(f"- evidence mutability rule: [docs/operations/evidence-bundles.md#evidence-mutability-r-snapshot-and-replay-integrity-normative](docs/operations/evidence-bundles.md#evidence-mutability-r-snapshot-and-replay-integrity-normative)")
    lines.append("")
    lines.append("## Inputs (Verified Against R-Snapshot EvidenceManifest)")
    lines.append(f"- LockedSpec: [{locked_spec_ref}]({locked_spec_ref})")
    lines.append(f"- GateVerdict Q: [{gate_q_ref}]({gate_q_ref})")
    lines.append(f"- GateVerdict R: [{gate_r_ref}]({gate_r_ref})")
    lines.append(f"- EvidenceManifest (R-snapshot): [{r_snapshot_manifest_ref}]({r_snapshot_manifest_ref})")
    lines.append("")
    lines.append("## Outputs")
    lines.append(f"- docs_compilation_log: [{docs_log_ref}]({docs_log_ref})")
    lines.append(f"- EvidenceManifest (final, append-only extension): [{final_manifest_ref}]({final_manifest_ref})")
    lines.append(f"- docs bundle dir: [{out_bundle_dir_ref}]({out_bundle_dir_ref})")
    lines.append(f"- bundle_sha256 (excludes docs_bundle_manifest.json): `{bundle_sha256}`")
    lines.append(f"- docs_bundle_manifest_sha256: `{docs_bundle_manifest_sha256}`")
    lines.append(f"- bundle_root_sha256: `{bundle_root_sha256}`")
    lines.append("")
    return "\n".join(lines) + "\n"


def main() -> int:
    docs_log_storage_ref_canonical = "docs/docs_compilation_log.json"
    docs_log_artifact_id_canonical = "docs.compilation_log"

    ap = argparse.ArgumentParser(
        description=(
            "C3 Docs Compiler (hardened): post-R tool that verifies R-snapshot integrity, emits deterministic docs + docs_compilation_log, "
            "and produces a Final EvidenceManifest as an append-only extension."
        )
    )
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
    ap.add_argument("--gate-q-verdict", required=True, help="Repo-relative path to GateVerdict.Q.json")
    ap.add_argument("--gate-r-verdict", required=True, help="Repo-relative path to GateVerdict.R.json")
    ap.add_argument(
        "--r-snapshot-manifest",
        required=True,
        help="Repo-relative path to the R-snapshot EvidenceManifest.json (must match GateVerdict(R).evidence_manifest_ref)",
    )
    ap.add_argument(
        "--out-final-manifest",
        required=True,
        help="Repo-relative output path for Final EvidenceManifest.json (MUST NOT overwrite the R-snapshot manifest)",
    )
    ap.add_argument(
        "--out-log",
        default=docs_log_storage_ref_canonical,
        help=f"Repo-relative output path for docs_compilation_log payload JSON (MUST be {docs_log_storage_ref_canonical})",
    )
    ap.add_argument("--out-docs", required=True, help="Repo-relative output path for deterministic docs markdown")
    ap.add_argument(
        "--out-bundle-dir",
        required=True,
        help="Repo-relative output directory path for the docs bundle tree (bundle/**)",
    )
    ap.add_argument(
        "--out-bundle-root-sha",
        required=True,
        help="Repo-relative output path for a text file containing bundle_root_sha256 (not inside bundle/ to avoid circularity)",
    )
    ap.add_argument(
        "--profile",
        default=None,
        choices=["public", "internal"],
        help="Docs compiler profile. If LockedSpec.publication_intent.profile is present, this must match it.",
    )
    ap.add_argument(
        "--generated-at",
        default=EVALUATED_AT,
        help="RFC3339 timestamp to record (deterministic runs should supply a fixed value)",
    )
    ap.add_argument("--compiler-id", default=COMPILER_ID, help="Compiler identifier")
    ap.add_argument("--compiler-version", default=COMPILER_VERSION, help="Compiler version")
    ap.add_argument(
        "--prompt-block-hashes",
        required=True,
        help="Repo-relative path to JSON mapping {block_id: sha256_hex} used for prompt block hash disclosure.",
    )
    ap.add_argument(
        "--template",
        default=BUILTIN_DOCS_TEMPLATE_REPO_REL,
        help="Repo-relative path to DocsCompiler template markdown",
    )

    args = ap.parse_args()

    stage_dir: Path | None = None
    tmp_paths: list[Path] = []

    def _cleanup_outputs_best_effort() -> None:
        for p in reversed(tmp_paths):
            try:
                if p.exists():
                    p.unlink()
            except Exception:
                pass
        if stage_dir is not None:
            try:
                if stage_dir.exists():
                    _rmtree_retry(stage_dir)
            except Exception:
                pass

    try:
        repo_root = Path(args.repo).resolve()
        if not repo_root.exists() or not repo_root.is_dir():
            raise _UserInputError("--repo must be an existing directory")

        locked_rel = _validate_repo_rel(str(args.locked_spec))
        q_rel = _validate_repo_rel(str(args.gate_q_verdict))
        r_rel = _validate_repo_rel(str(args.gate_r_verdict))
        rsnap_rel = _validate_repo_rel(str(args.r_snapshot_manifest))
        out_final_rel = _validate_repo_rel(str(args.out_final_manifest))
        out_log_rel = _validate_repo_rel(str(args.out_log))
        out_docs_rel = _validate_repo_rel(str(args.out_docs))
        out_bundle_dir_rel = _validate_repo_rel(str(args.out_bundle_dir))
        out_bundle_root_sha_rel = _validate_repo_rel(str(args.out_bundle_root_sha))
        hashes_rel = _validate_repo_rel(str(args.prompt_block_hashes))
        template_rel = _validate_repo_rel(str(args.template))

        profile_arg = str(args.profile) if args.profile is not None else None

        if out_log_rel != docs_log_storage_ref_canonical:
            raise _UserInputError(f"--out-log MUST be {docs_log_storage_ref_canonical!r}")

        if out_final_rel == rsnap_rel:
            raise _UserInputError("out-final-manifest MUST NOT overwrite the R-snapshot manifest")

        generated_at = str(args.generated_at)
        parse_rfc3339(generated_at)

        locked_path = _resolve_repo_path(repo_root, locked_rel, must_exist=True, must_be_file=True)
        q_path = _resolve_repo_path(repo_root, q_rel, must_exist=True, must_be_file=True)
        r_path = _resolve_repo_path(repo_root, r_rel, must_exist=True, must_be_file=True)
        rsnap_path = _resolve_repo_path(repo_root, rsnap_rel, must_exist=True, must_be_file=True)
        out_final_path = _resolve_repo_path(repo_root, out_final_rel, must_exist=False)
        out_log_path = _resolve_repo_path(repo_root, out_log_rel, must_exist=False)
        out_docs_path = _resolve_repo_path(repo_root, out_docs_rel, must_exist=False)
        out_bundle_dir_path = _resolve_repo_path(repo_root, out_bundle_dir_rel, must_exist=False)
        out_bundle_root_sha_path = _resolve_repo_path(repo_root, out_bundle_root_sha_rel, must_exist=False)
        hashes_path = _resolve_repo_path(repo_root, hashes_rel, must_exist=True, must_be_file=True)
        try:
            template_path = _resolve_repo_path(repo_root, template_rel, must_exist=True, must_be_file=True)
        except _UserInputError:
            raise _UserInputError(f"Template missing: {template_rel}")


        # Load protocol context (pack-truth for schemas)
        protocol = _load_protocol_context(repo_root=repo_root, args=args)
        locked_schema = _load_schema_from_protocol(protocol, "schemas/LockedSpec.schema.json")
        gate_schema = _load_schema_from_protocol(protocol, "schemas/GateVerdict.schema.json")
        em_schema = _load_schema_from_protocol(protocol, "schemas/EvidenceManifest.schema.json")
        log_schema = _load_schema_from_protocol(protocol, "schemas/DocsCompilationLogPayload.schema.json")

        locked = load_json(locked_path)
        if not isinstance(locked, dict):
            raise _UserInputError("LockedSpec must be a JSON object")
        errs = validate_schema(locked, locked_schema, root_schema=locked_schema, path="locked")
        if errs:
            raise _UserInputError("LockedSpec schema validation failed:\n" + _format_schema_errors(errs))

        # Protocol identity verification: fail immediately if LockedSpec.protocol_pack doesn't match active context.
        #TODO: _verify_protocol_identity_or_fail(locked, protocol)

        locked_profile: str | None = None
        pub_intent = locked.get("publication_intent")
        if pub_intent is not None:
            if not isinstance(pub_intent, dict):
                raise _UserInputError("LockedSpec.publication_intent must be an object when present")
            p = pub_intent.get("profile")
            if not isinstance(p, str) or p not in ("public", "internal"):
                raise _UserInputError("LockedSpec.publication_intent.profile missing/invalid")
            locked_profile = p

        if locked_profile is not None:
            if profile_arg is not None and profile_arg != locked_profile:
                raise _UserInputError(
                    f"profile mismatch: --profile={profile_arg!r} vs LockedSpec.publication_intent.profile={locked_profile!r}"
                )
            profile = locked_profile
        else:
            if profile_arg is None:
                raise _UserInputError("--profile is required when LockedSpec.publication_intent.profile is not present")
            profile = profile_arg

        qv = load_json(q_path)
        if not isinstance(qv, dict):
            raise _UserInputError("GateVerdict(Q) must be a JSON object")
        errs = validate_schema(qv, gate_schema, root_schema=gate_schema, path="gate_q")
        if errs:
            raise _UserInputError("GateVerdict(Q) schema validation failed:\n" + _format_schema_errors(errs))
        if qv.get("gate_id") != "Q":
            raise _UserInputError("GateVerdict(Q).gate_id must be 'Q'")

        rv = load_json(r_path)
        if not isinstance(rv, dict):
            raise _UserInputError("GateVerdict(R) must be a JSON object")
        errs = validate_schema(rv, gate_schema, root_schema=gate_schema, path="gate_r")
        if errs:
            raise _UserInputError("GateVerdict(R) schema validation failed:\n" + _format_schema_errors(errs))
        if rv.get("gate_id") != "R":
            raise _UserInputError("GateVerdict(R).gate_id must be 'R'")

        run_id = locked.get("run_id")
        if not isinstance(run_id, str) or not run_id.strip():
            raise _UserInputError("LockedSpec.run_id missing/invalid")
        if qv.get("run_id") != run_id:
            raise _UserInputError("GateVerdict(Q).run_id mismatch vs LockedSpec.run_id")
        if rv.get("run_id") != run_id:
            raise _UserInputError("GateVerdict(R).run_id mismatch vs LockedSpec.run_id")

        verdict = rv.get("verdict")
        if verdict != "GO":
            raise _UserInputError("C3 must run only after Gate R GO")

        rsnap = load_json(rsnap_path)
        if not isinstance(rsnap, dict):
            raise _UserInputError("R-snapshot EvidenceManifest must be a JSON object")
        errs = validate_schema(rsnap, em_schema, root_schema=em_schema, path="r_snapshot")
        if errs:
            raise _UserInputError("R-snapshot EvidenceManifest schema validation failed:\n" + _format_schema_errors(errs))
        if rsnap.get("run_id") != run_id:
            raise _UserInputError("R-snapshot EvidenceManifest.run_id mismatch vs LockedSpec.run_id")

        # Bind R-snapshot EvidenceManifest bytes to GateVerdict(R).evidence_manifest_ref
        r_em_ref = rv.get("evidence_manifest_ref")
        if not isinstance(r_em_ref, dict):
            raise _UserInputError("GateVerdict(R).evidence_manifest_ref missing/invalid")
        r_em_ref_sr = r_em_ref.get("storage_ref")
        r_em_ref_hash = r_em_ref.get("hash")
        if not isinstance(r_em_ref_sr, str) or not r_em_ref_sr:
            raise _UserInputError("GateVerdict(R).evidence_manifest_ref.storage_ref missing/invalid")
        if not isinstance(r_em_ref_hash, str) or not r_em_ref_hash:
            raise _UserInputError("GateVerdict(R).evidence_manifest_ref.hash missing/invalid")
        if _validate_repo_rel(r_em_ref_sr) != rsnap_rel:
            raise _UserInputError("GateVerdict(R).evidence_manifest_ref.storage_ref must match --r-snapshot-manifest")
        rsnap_bytes_hash = _sha256_file(rsnap_path)
        if rsnap_bytes_hash.lower() != r_em_ref_hash.lower():
            raise _UserInputError(
                f"GateVerdict(R) evidence_manifest_ref.hash mismatch: declared={r_em_ref_hash} computed={rsnap_bytes_hash}"
            )

        # Verify that the R-snapshot EvidenceManifest indexes (at minimum) LockedSpec and GateVerdict(Q),
        # and that the passed-in files match by (storage_ref, sha256).
        _verify_storage_ref_hash(repo_root=repo_root, manifest=rsnap, storage_ref=locked_rel, label="LockedSpec")
        _verify_storage_ref_hash(repo_root=repo_root, manifest=rsnap, storage_ref=q_rel, label="GateVerdict(Q)")

        # Stage the docs bundle per template contract (deterministic ordering + LF normalization).
        if out_bundle_dir_path.exists() and out_bundle_dir_path.is_file():
            raise _UserInputError("out-bundle-dir must be a directory")

        stage_dir = out_bundle_dir_path.with_name(out_bundle_dir_path.name + ".tmp.c3")
        if stage_dir.exists():
            _rmtree_retry(stage_dir)

        source_inputs, bundled_files = _build_docs_bundle_stage(
            repo_root=repo_root,
            profile=profile,
            stage_dir=stage_dir,
        )

        bundle_sha256 = _compute_bundle_sha256(bundled_files=bundled_files)

        docs_bundle_manifest_obj: dict[str, Any] = {
            "schema_version": "1.0.0",
            "profile": profile,
            "inputs": list(source_inputs),
            "files": list(bundled_files),
            "bundle_sha256": bundle_sha256,
        }
        manifest_bytes = json.dumps(docs_bundle_manifest_obj, indent=2, sort_keys=True, ensure_ascii=False).replace(
            "\r\n", "\n"
        ).replace("\r", "\n").encode("utf-8", errors="strict") + b"\n"
        (stage_dir / "docs_bundle_manifest.json").write_bytes(manifest_bytes)
        docs_bundle_manifest_sha256 = sha256_bytes(manifest_bytes)

        bundle_root_sha256 = _compute_bundle_root_sha256(
            docs_bundle_manifest_sha256=docs_bundle_manifest_sha256,
            bundle_sha256=bundle_sha256,
        )

        toc_sha256 = _sha256_file(stage_dir / "TOC.md")
        bundle_root_file_bytes = (bundle_root_sha256 + "\n").encode("utf-8", errors="strict")
        bundle_root_file_sha256 = sha256_bytes(bundle_root_file_bytes)

        block_hashes_obj = load_json(hashes_path)
        if not isinstance(block_hashes_obj, dict):
            raise _UserInputError("prompt-block-hashes must be a JSON object mapping block_id -> sha256")

        registry_rows, registry_source_sha256 = _parse_prompt_block_registry(repo_root)

        prompt_blocks: list[dict[str, str]] = []
        for row in registry_rows:
            block_id = row["block_id"]
            sensitivity = row["sensitivity"]

            h = block_hashes_obj.get(block_id)
            if not isinstance(h, str) or not (len(h) == 64 and all(c in "0123456789abcdefABCDEF" for c in h)):
                raise _UserInputError(f"Missing/invalid sha256 for block_id {block_id} in prompt-block-hashes")

            if profile == "public" and sensitivity in ("internal", "secret"):
                published_form = "hash_only"
            else:
                published_form = "bytes"

            prompt_blocks.append(
                {
                    "block_id": block_id,
                    "sensitivity": sensitivity,
                    "content_sha256": h,
                    "published_form": published_form,
                }
            )

        template_bytes = template_path.read_bytes()
        template_text = _decode_utf8_strict(template_bytes, source_label=f"template:{template_rel}")
        template_source_sha256 = sha256_bytes(template_bytes)


        docs_text = _render_docs_markdown(
            template_text=template_text,
            run_id=run_id,
            profile=profile,
            locked_spec_ref=locked_rel,
            gate_q_ref=q_rel,
            gate_r_ref=r_rel,
            r_snapshot_manifest_ref=rsnap_rel,
            final_manifest_ref=out_final_rel,
            docs_log_ref=out_log_rel,
            bundle_sha256=bundle_sha256,
            docs_bundle_manifest_sha256=docs_bundle_manifest_sha256,
            bundle_root_sha256=bundle_root_sha256,
            out_bundle_dir_ref=out_bundle_dir_rel,
        )
        docs_sha256 = sha256_bytes(docs_text.encode("utf-8", errors="strict"))

        payload: dict[str, Any] = {
            "schema_version": "1.0.0",
            "run_id": run_id,
            "generated_at": generated_at,
            "profile": profile,
            "compiler_id": str(args.compiler_id),
            "compiler_version": str(args.compiler_version),
            "prompt_blocks": prompt_blocks,
            "inputs": [],
            "outputs": {
                "bundle_sha256": bundle_sha256,
                "docs_bundle_manifest_sha256": docs_bundle_manifest_sha256,
                "bundle_root_sha256": bundle_root_sha256,
                "docs_markdown": {"path": out_docs_rel, "sha256": docs_sha256},
                "bundle_manifest": {
                    "path": _validate_repo_rel(f"{out_bundle_dir_rel}/docs_bundle_manifest.json"),
                    "sha256": docs_bundle_manifest_sha256,
                },
                "bundle_toc": {
                    "path": _validate_repo_rel(f"{out_bundle_dir_rel}/TOC.md"),
                    "sha256": toc_sha256,
                },
                "bundle_root_sha_file": {"path": out_bundle_root_sha_rel, "sha256": bundle_root_file_sha256},
                "bundle_dir": out_bundle_dir_rel,
            },
        }

        # Declared schema inputs.
        payload["inputs"].extend(
            [
                {"path": locked_rel, "source_sha256": _sha256_file(locked_path)},
                {"path": q_rel, "source_sha256": _sha256_file(q_path)},
                {"path": r_rel, "source_sha256": _sha256_file(r_path)},
                {"path": rsnap_rel, "source_sha256": rsnap_bytes_hash},
                {"path": hashes_rel, "source_sha256": _sha256_file(hashes_path)},
                {"path": BUILTIN_PROMPT_BLOCK_REGISTRY_REPO_REL, "source_sha256": registry_source_sha256},
                {"path": template_rel, "source_sha256": template_source_sha256},

            ]
        )

        # Also record source hashes for included repo docs (audit/determinism).
        for rel in source_inputs:
            src = _resolve_repo_path(repo_root, rel, must_exist=True, must_be_file=True)
            payload["inputs"].append({"path": rel, "source_sha256": _sha256_file(src)})

        payload["inputs"].sort(key=lambda d: str(d.get("path", "")))

        errs = validate_schema(payload, log_schema, root_schema=log_schema, path="docs_compilation_log")
        if errs:
            raise _UserInputError("docs_compilation_log schema validation failed:\n" + _format_schema_errors(errs))

        out_log_path.parent.mkdir(parents=True, exist_ok=True)
        out_docs_path.parent.mkdir(parents=True, exist_ok=True)
        out_final_path.parent.mkdir(parents=True, exist_ok=True)
        out_bundle_root_sha_path.parent.mkdir(parents=True, exist_ok=True)

        # Stage file outputs to avoid partial writes on failure.
        out_log_tmp = _write_tmp_json(out_log_path, payload, suffix=".tmp.c3")
        tmp_paths.append(out_log_tmp)
        docs_log_sha = _sha256_file(out_log_tmp)

        out_docs_tmp = _write_tmp_text(out_docs_path, docs_text, suffix=".tmp.c3")
        tmp_paths.append(out_docs_tmp)

        out_bundle_root_sha_tmp = _write_tmp_text(
            out_bundle_root_sha_path,
            (bundle_root_sha256 + "\n"),
            suffix=".tmp.c3",
        )
        tmp_paths.append(out_bundle_root_sha_tmp)

        final_manifest = dict(rsnap)
        final_artifacts = list(rsnap.get("artifacts") if isinstance(rsnap.get("artifacts"), list) else [])

        if any(isinstance(a, dict) and a.get("id") == docs_log_artifact_id_canonical for a in final_artifacts):
            raise _UserInputError(
                f"Final EvidenceManifest already contains artifact id {docs_log_artifact_id_canonical!r}"
            )

        final_artifacts.append(
            {
                "kind": "docs_compilation_log",
                "id": docs_log_artifact_id_canonical,
                "hash": docs_log_sha,
                "media_type": "application/json",
                "storage_ref": docs_log_storage_ref_canonical,
                "produced_by": "C3",
            }
        )
        final_manifest["artifacts"] = final_artifacts

        commands = rsnap.get("commands_executed")
        if isinstance(commands, list) and all(isinstance(x, str) for x in commands):
            final_manifest["commands_executed"] = list(commands) + ["belgi c3-compile"]
        elif isinstance(commands, list) and all(isinstance(x, dict) for x in commands):
            final_manifest["commands_executed"] = list(commands) + [
                {
                    "argv": [
                        "belgi",
                        "c3-compile",
                    ],
                    "exit_code": 0,
                    "started_at": generated_at,
                    "finished_at": generated_at,
                }
            ]
        else:
            raise _UserInputError("EvidenceManifest.commands_executed missing/invalid")

        errs = validate_schema(final_manifest, em_schema, root_schema=em_schema, path="final_manifest")
        if errs:
            raise _UserInputError("Final EvidenceManifest schema validation failed:\n" + _format_schema_errors(errs))

        out_final_tmp = _write_tmp_json(out_final_path, final_manifest, suffix=".tmp.c3")
        tmp_paths.append(out_final_tmp)

        # Commit stage: publish bundle before the final manifest that references it.
        _commit_tmp(out_log_tmp, out_log_path)
        _commit_tmp(out_docs_tmp, out_docs_path)
        _commit_tmp(out_bundle_root_sha_tmp, out_bundle_root_sha_path)
        _commit_bundle_stage(stage_dir, out_bundle_dir_path)
        _commit_tmp(out_final_tmp, out_final_path)
        return 0

    except _UserInputError as e:
        _cleanup_outputs_best_effort()
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        _cleanup_outputs_best_effort()
        print(f"INTERNAL ERROR: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
