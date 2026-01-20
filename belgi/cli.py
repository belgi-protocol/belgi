#!/usr/bin/env python3
"""BELGI CLI — Protocol pack management and evidence generation tools.

This is the installable CLI entrypoint (console_scripts).

Subcommands:
- belgi pack build     → Build/update protocol pack manifest deterministically
- belgi pack verify    → Verify protocol pack manifest matches file tree
- belgi bundle check   → Check an evidence bundle (demo-grade checker, --demo required)
- belgi about          → Print package identity info

Exit codes:
- 0: success
- 1: check failed (verification failed, etc.)
- 3: usage/internal error
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from importlib.metadata import PackageNotFoundError, metadata, version
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any


# ---------------------------------------------------------------------------
# Constants for seal_hash computation
# ---------------------------------------------------------------------------
# NOTE: Do not treat this file as an algorithm SSOT. The normative seal_hash
# algorithm is defined in docs/operations/evidence-bundles.md and implemented
# by the repo-local seal producer/verifier tooling.
SEAL_HASH_DELIMITER = b"\x00"


ABOUT_PHILOSOPHY = '"Hayatta en hakiki mürşit ilimdir." (M.K. Atatürk)'
ABOUT_DEDICATION = "Bilge (8)"
ABOUT_REPO_URL = "https://github.com/belgi-protocol/belgi"


def _compute_seal_hash(
    *,
    run_id: str,
    locked_spec_hash: str,
    evidence_manifest_hash: str,
    gate_q_hash: str,
    gate_r_hash: str,
    final_commit_sha: str,
    protocol_pack_id: str,
) -> str:
    """Compute deterministic seal_hash from binding fields.

    This implementation is used by the publish-safe `belgi bundle check --demo`
    path to recompute SealManifest.seal_hash deterministically.

    Normative definition lives in docs/operations/evidence-bundles.md.
    """
    parts = [
        run_id.encode("utf-8"),
        locked_spec_hash.encode("utf-8"),
        evidence_manifest_hash.encode("utf-8"),
        gate_q_hash.encode("utf-8"),
        gate_r_hash.encode("utf-8"),
        final_commit_sha.encode("utf-8"),
        protocol_pack_id.encode("utf-8"),
    ]
    payload = SEAL_HASH_DELIMITER.join(parts)
    return hashlib.sha256(payload).hexdigest()


# ---------------------------------------------------------------------------
# supply-chain subcommand
# ---------------------------------------------------------------------------

def cmd_supplychain_scan(args: argparse.Namespace) -> int:
    from belgi.commands.supplychain_scan import run_supplychain_scan
    try:
        return run_supplychain_scan(
            repo=Path(args.repo),
            evaluated_revision=str(args.evaluated_revision),
            out_path=Path(args.out),
            deterministic=bool(args.deterministic),
            run_id=str(getattr(args, "run_id", "unknown") or "unknown"),
        )
    except Exception as e:
        print(f"[belgi supplychain-scan] ERROR: {e}", file=sys.stderr)
        print("[belgi supplychain-scan] Remediation: Do ensure git is available and --repo is a valid git repository, then re-run supplychain-scan.", file=sys.stderr)
        return 3

# ---------------------------------------------------------------------------
# adversarial-scan subcommand
# ---------------------------------------------------------------------------

def cmd_adversarial_scan(args: argparse.Namespace) -> int:
    from belgi.commands.adversarial_scan import run_adversarial_scan
    try:
        return run_adversarial_scan(
            repo=Path(args.repo),
            out_path=Path(args.out),
            deterministic=bool(args.deterministic),
            run_id=str(getattr(args, "run_id", "unknown") or "unknown"),
        )
    except Exception as e:
        print(f"[belgi adversarial-scan] ERROR: {e}", file=sys.stderr)
        print("[belgi adversarial-scan] Remediation: Do ensure the repo is readable and Python sources can be parsed, then re-run adversarial-scan.", file=sys.stderr)
        return 3

# ---------------------------------------------------------------------------
# about subcommand
# ---------------------------------------------------------------------------

def cmd_about(_: argparse.Namespace) -> int:
    """Print package identity info (human-readable)."""

    try:
        pkg_version = version("belgi")
    except PackageNotFoundError:
        pkg_version = "0.0.0"

    pkg_name = "belgi"
    pkg_summary = ""
    try:
        meta = metadata("belgi")
        pkg_name = str(meta.get("Name") or pkg_name)
        pkg_summary = str(meta.get("Summary") or "")
    except PackageNotFoundError:
        pass

    print(f"{pkg_name} {pkg_version}")
    if pkg_summary:
        print(pkg_summary)
    print(f"Philosophy: {ABOUT_PHILOSOPHY}")
    print(f"Dedication: {ABOUT_DEDICATION}")
    print(f"Repo: {ABOUT_REPO_URL}")
    return 0


# ---------------------------------------------------------------------------
# pack build subcommand
# ---------------------------------------------------------------------------

def cmd_pack_build(args: argparse.Namespace) -> int:
    """Build/update protocol pack manifest deterministically.
    
    Scans --in directory, computes file hashes/sizes, generates
    ProtocolPackManifest.json with deterministic pack_id.
    """
    from belgi.protocol.pack import (
        MANIFEST_FILENAME,
        build_manifest_bytes,
        validate_manifest_bytes,
    )
    
    in_dir = Path(args.input).resolve()
    out_dir = Path(args.output).resolve() if args.output else in_dir
    pack_name = args.pack_name
    
    if not in_dir.exists():
        print(f"[belgi pack build] ERROR: input directory does not exist: {in_dir}", file=sys.stderr)
        return 3
    if not in_dir.is_dir():
        print(f"[belgi pack build] ERROR: input is not a directory: {in_dir}", file=sys.stderr)
        return 3
    if in_dir.is_symlink():
        print(f"[belgi pack build] ERROR: symlink directory not allowed: {in_dir}", file=sys.stderr)
        return 3
    
    # If out_dir != in_dir, we need to copy content first (not implemented here; use build_builtin_pack.py for that).
    if out_dir != in_dir:
        print(f"[belgi pack build] ERROR: --out must equal --in (use build_builtin_pack.py for copy workflows)", file=sys.stderr)
        return 3
    
    try:
        manifest_bytes = build_manifest_bytes(
            pack_root=in_dir,
            pack_name=pack_name,
        )
    except Exception as e:
        print(f"[belgi pack build] ERROR: failed to build manifest: {e}", file=sys.stderr)
        return 1
    
    manifest_path = out_dir / MANIFEST_FILENAME
    manifest_path.write_bytes(manifest_bytes)
    
    # Fail-closed: validate immediately after writing.
    try:
        validate_manifest_bytes(pack_root=out_dir, manifest_bytes=manifest_bytes)
    except Exception as e:
        print(f"[belgi pack build] ERROR: validation failed after build: {e}", file=sys.stderr)
        return 1
    
    # Parse to show summary.
    parsed = json.loads(manifest_bytes.decode("utf-8"))
    pack_id = parsed.get("pack_id", "")
    file_count = len(parsed.get("files", []))
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    
    print(f"[belgi pack build] Wrote: {manifest_path}", file=sys.stderr)
    print(f"[belgi pack build] pack_id: {pack_id}", file=sys.stderr)
    print(f"[belgi pack build] manifest_sha256: {manifest_sha256}", file=sys.stderr)
    print(f"[belgi pack build] files: {file_count}", file=sys.stderr)
    print(f"[belgi pack build] PASS: manifest built and validated", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# pack verify subcommand
# ---------------------------------------------------------------------------

def cmd_pack_verify(args: argparse.Namespace) -> int:
    """Verify protocol pack manifest matches file tree.
    
    If --builtin is specified, verifies the builtin pack from installed resources.
    Otherwise, verifies the pack at --in directory.
    """
    from importlib.resources import as_file, files

    from belgi.protocol.pack import (
        MANIFEST_FILENAME,
        validate_manifest_bytes,
    )

    def _emit_manifest_files_diff(*, pack_root: Path, manifest_bytes: bytes) -> None:
        try:
            from belgi.protocol.pack import scan_pack_dir
            from belgi.core.jail import normalize_repo_rel_path
        except Exception as e:  # pragma: no cover
            print(f"[belgi pack verify] NOTE: cannot import diff helpers: {e}", file=sys.stderr)
            return

        try:
            parsed = json.loads(bytes(manifest_bytes).decode("utf-8", errors="strict"))
        except Exception as e:
            print(f"[belgi pack verify] NOTE: cannot parse manifest JSON for diff: {e}", file=sys.stderr)
            return
        if not isinstance(parsed, dict):
            print("[belgi pack verify] NOTE: manifest JSON is not an object; diff unavailable", file=sys.stderr)
            return

        files = parsed.get("files")
        if not isinstance(files, list):
            print("[belgi pack verify] NOTE: manifest.files missing/invalid; diff unavailable", file=sys.stderr)
            return

        manifest_map: dict[str, tuple[str, int]] = {}
        for entry in files:
            if not isinstance(entry, dict):
                continue
            rel_raw = entry.get("relpath")
            sha = entry.get("sha256")
            size = entry.get("size_bytes")
            if not isinstance(rel_raw, str) or not rel_raw:
                continue
            if not isinstance(sha, str) or not sha:
                continue
            if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                continue
            try:
                rel = normalize_repo_rel_path(rel_raw)
            except Exception:
                continue
            if rel == MANIFEST_FILENAME:
                continue
            manifest_map[rel] = (sha, size)

        scanned_entries = scan_pack_dir(pack_root)
        scanned_map: dict[str, tuple[str, int]] = {e.relpath: (e.sha256, e.size_bytes) for e in scanned_entries}

        manifest_paths = set(manifest_map)
        scanned_paths = set(scanned_map)

        missing_in_manifest = sorted(scanned_paths - manifest_paths)
        extra_in_manifest = sorted(manifest_paths - scanned_paths)
        mismatched = sorted(
            [
                rel
                for rel in (manifest_paths & scanned_paths)
                if manifest_map.get(rel) != scanned_map.get(rel)
            ]
        )

        print(f"[belgi pack verify] diff: missing_in_manifest={len(missing_in_manifest)}", file=sys.stderr)
        for rel in missing_in_manifest:
            print(f"[belgi pack verify] diff: missing_in_manifest: {rel}", file=sys.stderr)

        print(f"[belgi pack verify] diff: extra_in_manifest={len(extra_in_manifest)}", file=sys.stderr)
        for rel in extra_in_manifest:
            print(f"[belgi pack verify] diff: extra_in_manifest: {rel}", file=sys.stderr)

        print(f"[belgi pack verify] diff: mismatched={len(mismatched)}", file=sys.stderr)
        for rel in mismatched:
            m_sha, m_size = manifest_map[rel]
            s_sha, s_size = scanned_map[rel]
            print(
                f"[belgi pack verify] diff: mismatched: {rel} "
                f"(manifest sha256={m_sha} size_bytes={m_size}; scanned sha256={s_sha} size_bytes={s_size})",
                file=sys.stderr,
            )
    
    if args.builtin:
        # Verify builtin pack from installed package resources.
        # Use as_file() to get a real Path that works with validate_manifest_bytes.
        # This is robust for both filesystem and zip-based resource loaders.
        pack_traversable = files("belgi").joinpath("_protocol_packs", "v1")
        
        try:
            with as_file(pack_traversable) as pack_root:
                manifest_bytes = (pack_root / MANIFEST_FILENAME).read_bytes()
                validate_manifest_bytes(pack_root=pack_root, manifest_bytes=manifest_bytes)
        except Exception as e:
            if str(e) == "manifest.files do not match scanned pack contents":
                try:
                    with as_file(pack_traversable) as pack_root:
                        manifest_bytes = (pack_root / MANIFEST_FILENAME).read_bytes()
                        _emit_manifest_files_diff(pack_root=pack_root, manifest_bytes=manifest_bytes)
                except Exception:
                    pass
            print(f"[belgi pack verify] FAIL (builtin): {e}", file=sys.stderr)
            return 1
        
        parsed = json.loads(manifest_bytes.decode("utf-8"))
        pack_id = parsed.get("pack_id", "")
        pack_name = parsed.get("pack_name", "")
        file_count = len(parsed.get("files", []))
        manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
        
        if getattr(args, "verbose", False):
            print(f"[belgi pack verify] source: builtin (installed package)", file=sys.stderr)
            print(f"[belgi pack verify] pack_name: {pack_name}", file=sys.stderr)
            print(f"[belgi pack verify] pack_id: {pack_id}", file=sys.stderr)
            print(f"[belgi pack verify] manifest_sha256: {manifest_sha256}", file=sys.stderr)
            print(f"[belgi pack verify] files: {file_count}", file=sys.stderr)
            print(f"[belgi pack verify] PASS: builtin manifest verified", file=sys.stderr)
        return 0
    
    # Verify pack at --in directory.
    if not args.input:
        print(f"[belgi pack verify] ERROR: --in or --builtin required", file=sys.stderr)
        return 3
    
    in_dir = Path(args.input).resolve()
    
    if not in_dir.exists():
        print(f"[belgi pack verify] ERROR: input directory does not exist: {in_dir}", file=sys.stderr)
        return 3
    if not in_dir.is_dir():
        print(f"[belgi pack verify] ERROR: input is not a directory: {in_dir}", file=sys.stderr)
        return 3
    if in_dir.is_symlink():
        print(f"[belgi pack verify] ERROR: symlink directory not allowed: {in_dir}", file=sys.stderr)
        return 3
    
    manifest_path = in_dir / MANIFEST_FILENAME
    if not manifest_path.exists():
        print(f"[belgi pack verify] ERROR: manifest not found: {manifest_path}", file=sys.stderr)
        return 1
    if manifest_path.is_symlink():
        print(f"[belgi pack verify] ERROR: symlink manifest not allowed: {manifest_path}", file=sys.stderr)
        return 1
    
    manifest_bytes = manifest_path.read_bytes()
    
    try:
        validate_manifest_bytes(pack_root=in_dir, manifest_bytes=manifest_bytes)
    except Exception as e:
        if str(e) == "manifest.files do not match scanned pack contents":
            _emit_manifest_files_diff(pack_root=in_dir, manifest_bytes=manifest_bytes)
        print(f"[belgi pack verify] FAIL: {e}", file=sys.stderr)
        return 1
    
    # Parse to show summary.
    parsed = json.loads(manifest_bytes.decode("utf-8"))
    pack_id = parsed.get("pack_id", "")
    pack_name = parsed.get("pack_name", "")
    file_count = len(parsed.get("files", []))
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()

    if getattr(args, "verbose", False):
        src = "builtin" if args.builtin else str(in_dir)
        print(f"[belgi pack verify] source: {src}", file=sys.stderr)
        print(f"[belgi pack verify] pack_name: {pack_name}", file=sys.stderr)
        print(f"[belgi pack verify] pack_id: {pack_id}", file=sys.stderr)
        print(f"[belgi pack verify] manifest_sha256: {manifest_sha256}", file=sys.stderr)
        print(f"[belgi pack verify] files: {file_count}", file=sys.stderr)
        print(f"[belgi pack verify] PASS: manifest verified", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# bundle check subcommand (demo-grade checker)
# ---------------------------------------------------------------------------

def cmd_bundle_check(args: argparse.Namespace) -> int:
    """Check an evidence bundle (demo-grade checker).
    
    This is a publish-safe checker that ONLY depends on belgi* modules.
    It checks:
    - Required bundle files exist (no symlinks)
        - Protocol identity binding: LockedSpec.protocol_pack must match the active pack
            on pack_id, pack_name, and manifest_sha256 (source is metadata)
    - Run_id consistency across all core artifacts
    - All ObjectRefs in SealManifest exist and hash-match (fail-closed)
    - GateVerdicts are all GO
    - seal_hash recomputes correctly
    
    IMPORTANT: This is a DEMO-GRADE checker. It does NOT replay Gate Q/R/S logic.
    For production verification, use the full gate verifiers (chain/gate_*_verify.py).
    
    --demo flag is REQUIRED to acknowledge this limitation.
    """
    from belgi.protocol.pack import get_builtin_protocol_context
    from belgi.core.hash import sha256_bytes, is_hex_sha256
    
    if not args.demo:
        print("[belgi bundle check] ERROR: --demo flag required", file=sys.stderr)
        print("", file=sys.stderr)
        print("This is a DEMO-GRADE checker that does NOT replay Gate Q/R/S logic.", file=sys.stderr)
        print("It only verifies bundle structure, hash bindings, and seal integrity.", file=sys.stderr)
        print("For production verification, use the full gate verifiers.", file=sys.stderr)
        print("", file=sys.stderr)
        print("To acknowledge and proceed: belgi bundle check --in <dir> --demo", file=sys.stderr)
        return 3
    
    bundle_dir = Path(args.input).resolve()
    
    if not bundle_dir.exists():
        print(f"[belgi bundle check] ERROR: bundle directory does not exist: {bundle_dir}", file=sys.stderr)
        return 3
    if not bundle_dir.is_dir():
        print(f"[belgi bundle check] ERROR: path is not a directory: {bundle_dir}", file=sys.stderr)
        return 3
    if bundle_dir.is_symlink():
        print(f"[belgi bundle check] ERROR: symlink directory not allowed: {bundle_dir}", file=sys.stderr)
        return 3
    
    # Required bundle files (fail-closed: all must exist)
    required_files = [
        "LockedSpec.json",
        "EvidenceManifest.json",
        "SealManifest.json",
        "GateVerdict_Q.json",
        "GateVerdict_R.json",
        "GateVerdict_S.json",
    ]
    
    failures: list[str] = []
    checks_passed = 0
    checks_total = 0
    
    # Check required files exist (fail-closed: no symlinks)
    for fname in required_files:
        checks_total += 1
        fpath = bundle_dir / fname
        if not fpath.exists():
            failures.append(f"missing required file: {fname}")
        elif fpath.is_symlink():
            failures.append(f"symlink not allowed: {fname}")
        else:
            checks_passed += 1
    
    if failures:
        print(f"[belgi bundle check] FAIL: required files check", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    
    # Load files (fail-closed on parse error)
    def load_json_file(name: str) -> dict[str, Any] | None:
        try:
            p = bundle_dir / name
            return json.loads(p.read_text(encoding="utf-8", errors="strict"))
        except Exception as e:
            failures.append(f"{name}: failed to parse JSON: {e}")
            return None
    
    locked_spec = load_json_file("LockedSpec.json")
    evidence_manifest = load_json_file("EvidenceManifest.json")
    seal_manifest = load_json_file("SealManifest.json")
    verdict_q = load_json_file("GateVerdict_Q.json")
    verdict_r = load_json_file("GateVerdict_R.json")
    verdict_s = load_json_file("GateVerdict_S.json")
    
    if failures:
        print(f"[belgi bundle check] FAIL: JSON parse errors", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    
    # Verify protocol identity binding (pack_id/pack_name/manifest_sha256).
    # NOTE: source is metadata and is intentionally NOT treated as identity.
    checks_total += 1
    protocol_pack_id: str = ""
    try:
        protocol = get_builtin_protocol_context()
        if locked_spec is not None:
            proto_pack = locked_spec.get("protocol_pack")
            if isinstance(proto_pack, dict):
                declared_pack_id = proto_pack.get("pack_id")
                declared_pack_name = proto_pack.get("pack_name")
                declared_manifest_sha256 = proto_pack.get("manifest_sha256")
                
                # Identity fields must match exactly.
                mismatches = []
                if declared_pack_id != protocol.pack_id:
                    mismatches.append(f"pack_id: declared={declared_pack_id}, builtin={protocol.pack_id}")
                if declared_pack_name != protocol.pack_name:
                    mismatches.append(f"pack_name: declared={declared_pack_name}, builtin={protocol.pack_name}")
                if declared_manifest_sha256 != protocol.manifest_sha256:
                    mismatches.append(f"manifest_sha256: declared={declared_manifest_sha256}, builtin={protocol.manifest_sha256}")
                
                if mismatches:
                    for m in mismatches:
                        failures.append(f"protocol_pack binding mismatch: {m}")
                else:
                    protocol_pack_id = str(protocol.pack_id)
                    checks_passed += 1
            else:
                failures.append("LockedSpec.protocol_pack missing or invalid")
        else:
            failures.append("LockedSpec is None")
    except Exception as e:
        failures.append(f"protocol identity check failed: {e}")
    
    # Verify run_id consistency (FAIL-CLOSED: all 6 artifacts MUST have non-empty run_id)
    checks_total += 1
    run_ids: dict[str, str | None] = {
        "LockedSpec": locked_spec.get("run_id") if locked_spec else None,
        "EvidenceManifest": evidence_manifest.get("run_id") if evidence_manifest else None,
        "SealManifest": seal_manifest.get("run_id") if seal_manifest else None,
        "GateVerdict_Q": verdict_q.get("run_id") if verdict_q else None,
        "GateVerdict_R": verdict_r.get("run_id") if verdict_r else None,
        "GateVerdict_S": verdict_s.get("run_id") if verdict_s else None,
    }
    
    # FAIL-CLOSED: Each artifact MUST have a non-empty string run_id.
    missing_run_id = [name for name, rid in run_ids.items() if not isinstance(rid, str) or not rid]
    if missing_run_id:
        for name in missing_run_id:
            failures.append(f"{name}: run_id missing or empty (fail-closed)")
    else:
        # All present; now check uniqueness
        unique_run_ids = set(run_ids.values())
        if len(unique_run_ids) == 1:
            checks_passed += 1
        else:
            # Report which artifacts have which run_id
            failures.append(f"run_id mismatch: found {len(unique_run_ids)} distinct values")
            for name, rid in run_ids.items():
                failures.append(f"  {name}: {rid}")
    
    # Verify gate verdicts are GO (fail-closed)
    for name, verdict in [("Q", verdict_q), ("R", verdict_r), ("S", verdict_s)]:
        checks_total += 1
        if verdict is None:
            failures.append(f"GateVerdict_{name} is None")
            continue
        v = verdict.get("verdict")
        if v == "GO":
            checks_passed += 1
        elif v == "NO-GO":
            failures.append(f"GateVerdict_{name}.verdict is NO-GO")
        else:
            failures.append(f"GateVerdict_{name}.verdict invalid: expected GO|NO-GO, got {v!r}")
    
    # Verify ObjectRef hash bindings in SealManifest (FAIL-CLOSED: all must exist and hash-match)
    def verify_object_ref(ref: dict[str, Any] | None, field: str, bundle_dir: Path) -> tuple[bool, str]:
        """Verify ObjectRef exists and hash matches. Returns (ok, hash_value)."""
        if ref is None or not isinstance(ref, dict):
            failures.append(f"{field}: missing or invalid ObjectRef")
            return False, ""
        
        obj_hash = ref.get("hash")
        storage_ref = ref.get("storage_ref")
        
        if not is_hex_sha256(str(obj_hash) if obj_hash else ""):
            failures.append(f"{field}.hash: invalid SHA-256 format")
            return False, ""
        
        if not isinstance(storage_ref, str) or not storage_ref:
            failures.append(f"{field}.storage_ref: missing or empty")
            return False, ""
        
        # Resolve file path (storage_ref should be bundle-relative filename)
        # FAIL-CLOSED: file MUST exist in bundle and hash MUST match
        target_path = bundle_dir / Path(storage_ref).name
        
        if target_path.is_symlink():
            failures.append(f"{field}: symlink not allowed: {target_path.name}")
            return False, ""
        
        if not target_path.exists():
            failures.append(f"{field}: referenced file not found in bundle: {target_path.name}")
            return False, ""
        
        if not target_path.is_file():
            failures.append(f"{field}: referenced path is not a file: {target_path.name}")
            return False, ""
        
        computed = sha256_bytes(target_path.read_bytes())
        if computed != obj_hash:
            failures.append(
                f"{field}: hash mismatch for {target_path.name} "
                f"(declared={obj_hash[:16]}..., computed={computed[:16]}...)"
            )
            return False, ""
        
        return True, str(obj_hash)
    
    # Collect hashes for seal_hash verification
    locked_spec_hash = ""
    evidence_manifest_hash = ""
    gate_q_hash = ""
    gate_r_hash = ""
    
    if seal_manifest:
        for ref_field, hash_target in [
            ("locked_spec_ref", "locked_spec"),
            ("gate_q_verdict_ref", "gate_q"),
            ("gate_r_verdict_ref", "gate_r"),
            ("evidence_manifest_ref", "evidence_manifest"),
        ]:
            checks_total += 1
            ref = seal_manifest.get(ref_field)
            ok, hash_val = verify_object_ref(ref, f"SealManifest.{ref_field}", bundle_dir)
            if ok:
                checks_passed += 1
                if hash_target == "locked_spec":
                    locked_spec_hash = hash_val
                elif hash_target == "evidence_manifest":
                    evidence_manifest_hash = hash_val
                elif hash_target == "gate_q":
                    gate_q_hash = hash_val
                elif hash_target == "gate_r":
                    gate_r_hash = hash_val
    
    # Verify seal_hash (deterministic recomputation)
    checks_total += 1
    if seal_manifest and locked_spec_hash and evidence_manifest_hash and gate_q_hash and gate_r_hash:
        declared_seal_hash = seal_manifest.get("seal_hash")
        final_commit_sha = seal_manifest.get("final_commit_sha", "")
        run_id = seal_manifest.get("run_id", "")
        
        if not is_hex_sha256(str(declared_seal_hash) if declared_seal_hash else ""):
            failures.append("SealManifest.seal_hash: invalid or missing SHA-256")
        elif not final_commit_sha:
            failures.append("SealManifest.final_commit_sha: missing or empty")
        elif not run_id:
            failures.append("SealManifest.run_id: missing or empty")
        elif not protocol_pack_id:
            failures.append("seal_hash check skipped: protocol_pack_id not available")
        else:
            computed_seal = _compute_seal_hash(
                run_id=run_id,
                locked_spec_hash=locked_spec_hash,
                evidence_manifest_hash=evidence_manifest_hash,
                gate_q_hash=gate_q_hash,
                gate_r_hash=gate_r_hash,
                final_commit_sha=final_commit_sha,
                protocol_pack_id=protocol_pack_id,
            )
            if computed_seal == declared_seal_hash:
                checks_passed += 1
            else:
                failures.append(
                    f"seal_hash mismatch: declared={declared_seal_hash[:16]}..., "
                    f"computed={computed_seal[:16]}..."
                )
    else:
        failures.append("seal_hash check skipped: prerequisite ObjectRef checks failed")
    
    # Summary
    if failures:
        print(f"[belgi bundle check] FAIL: {checks_passed}/{checks_total} checks passed", file=sys.stderr)
        for f in failures[:15]:
            print(f"  - {f}", file=sys.stderr)
        if len(failures) > 15:
            print(f"  ... and {len(failures) - 15} more failures", file=sys.stderr)
        return 1
    
    # Success summary (run_ids all present and unique at this point)
    display_run_id = run_ids.get("SealManifest") or "UNKNOWN"
    if getattr(args, "verbose", False):
        print(f"[belgi bundle check] source: {bundle_dir}", file=sys.stdout)
        print(f"[belgi bundle check] run_id: {display_run_id}", file=sys.stdout)
        print(f"[belgi bundle check] protocol_pack: {protocol.pack_name} ({protocol.pack_id[:16]}...)", file=sys.stdout)
        print(f"[belgi bundle check] checks: {checks_passed}/{checks_total} passed", file=sys.stdout)
    print("PASS", file=sys.stdout)
    return 0


# ---------------------------------------------------------------------------
# Main CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="belgi",
        description="BELGI CLI — Protocol pack management and evidence generation tools",
    )
    subparsers = parser.add_subparsers(dest="command", help="Subcommand")

    # about
    subparsers.add_parser("about", help="Print package identity info")
    
    # pack (subparser group)
    p_pack = subparsers.add_parser("pack", help="Protocol pack management commands")
    pack_subs = p_pack.add_subparsers(dest="pack_command", help="Pack subcommand")
    
    # pack build
    p_pack_build = pack_subs.add_parser("build", help="Build/update protocol pack manifest")
    p_pack_build.add_argument("--in", dest="input", help="Input pack directory")
    p_pack_build.add_argument("--out", dest="output", help="Output directory (default: same as --in)")
    p_pack_build.add_argument("--pack-name", default="belgi-protocol-pack-v1", help="Pack name for manifest")
    
    # pack verify
    p_pack_verify = pack_subs.add_parser("verify", help="Verify protocol pack manifest")
    p_pack_verify.add_argument("--in", dest="input", help="Pack directory to verify")
    p_pack_verify.add_argument("--builtin", action="store_true", help="Verify builtin pack from installed package")
    p_pack_verify.add_argument("--verbose", action="store_true", help="Verbose output")
    
    # bundle (subparser group)
    p_bundle = subparsers.add_parser("bundle", help="Evidence bundle commands")
    bundle_subs = p_bundle.add_subparsers(dest="bundle_command", help="Bundle subcommand")
    
    # bundle check
    p_bundle_check = bundle_subs.add_parser("check", help="Check an evidence bundle (demo-grade checker)")
    p_bundle_check.add_argument("--in", dest="input", required=True, help="Bundle directory to check")
    p_bundle_check.add_argument(
        "--demo", action="store_true",
        help="Acknowledge this is a demo-grade checker (required)"
    )
    p_bundle_check.add_argument("--verbose", action="store_true", help="Verbose output")
    
    # supplychain-scan
    p_sc = subparsers.add_parser("supplychain-scan", help="Run supplychain scan and produce policy.supplychain artifact")
    p_sc.add_argument("--repo", default=".", help="Repo root")
    p_sc.add_argument("--run-id", default="unknown", help="Run ID to embed in the PolicyReportPayload (default: unknown)")
    p_sc.add_argument(
        "--evaluated-revision",
        default="HEAD~1",
        help="Git revision to diff against (e.g. HEAD~1 or commit sha). Default: HEAD~1",
    )
    p_sc.add_argument(
        "--out",
        default="out/policy-supplychain.json",
        help="Output JSON path (default: out/policy-supplychain.json)",
    )
    p_sc.add_argument("--deterministic", action="store_true", help="Use fixed timestamps for deterministic output")
    p_sc.set_defaults(func=cmd_supplychain_scan)

    # adversarial-scan
    p_adv = subparsers.add_parser("adversarial-scan", help="Run adversarial scan and produce policy.adversarial_scan artifact")
    p_adv.add_argument("--repo", default=".", help="Repo root")
    p_adv.add_argument("--run-id", default="unknown", help="Run ID to embed in the PolicyReportPayload (default: unknown)")
    p_adv.add_argument(
        "--out",
        default="out/policy-adversarial-scan.json",
        help="Output JSON path (default: out/policy-adversarial-scan.json)",
    )
    p_adv.add_argument("--deterministic", action="store_true", help="Use fixed timestamps for deterministic output")
    p_adv.set_defaults(func=cmd_adversarial_scan)

    args = parser.parse_args(argv)
    
    if args.command == "about":
        return cmd_about(args)
    elif args.command == "pack":
        if args.pack_command == "build":
            if not args.input:
                print("[belgi pack build] ERROR: --in required", file=sys.stderr)
                return 3
            return cmd_pack_build(args)
        elif args.pack_command == "verify":
            return cmd_pack_verify(args)
        else:
            p_pack.print_help()
            return 3
    elif args.command == "bundle":
        if args.bundle_command == "check":
            return cmd_bundle_check(args)
        else:
            p_bundle.print_help()
            return 3
    elif args.command == "supplychain-scan":
        return int(args.func(args))
    elif args.command == "adversarial-scan":
        return int(args.func(args))
    else:
        parser.print_help()
        return 3


if __name__ == "__main__":
    sys.exit(main())
