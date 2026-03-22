from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def cmd_manifest_add(args: argparse.Namespace) -> int:
    from belgi.core.hash import sha256_bytes
    from belgi.core.jail import normalize_repo_rel, resolve_repo_rel_path, safe_relpath
    from belgi.core.schema import validate_schema
    from belgi.protocol.pack import get_builtin_protocol_context

    try:
        repo_root = Path(str(args.repo)).resolve()
        if not repo_root.exists() or not repo_root.is_dir():
            raise ValueError(f"invalid repo root: {repo_root}")
        if repo_root.is_symlink():
            raise ValueError(f"symlink repo root not allowed: {repo_root}")

        manifest_path = resolve_repo_rel_path(
            repo_root,
            str(args.manifest),
            must_exist=True,
            must_be_file=True,
            allow_backslashes=False,
            forbid_symlinks=True,
        )
        artifact_path = resolve_repo_rel_path(
            repo_root,
            str(args.artifact),
            must_exist=True,
            must_be_file=True,
            allow_backslashes=False,
            forbid_symlinks=True,
        )
        if artifact_path.is_symlink():
            raise ValueError("artifact path symlink not allowed")

        kind = str(args.kind or "").strip()
        artifact_id = str(args.artifact_id or "").strip()
        media_type = str(args.media_type or "").strip()
        produced_by = str(args.produced_by or "").strip()
        if not artifact_id:
            raise ValueError("--id missing/invalid")
        if not media_type:
            raise ValueError("--media-type missing/invalid")

        protocol = get_builtin_protocol_context()
        evidence_schema = protocol.read_json("schemas/EvidenceManifest.schema.json")
        if not isinstance(evidence_schema, dict):
            raise ValueError("EvidenceManifest schema must be a JSON object")

        props = (
            evidence_schema.get("properties", {})
            .get("artifacts", {})
            .get("items", {})
            .get("properties", {})
        )
        allowed_kinds = props.get("kind", {}).get("enum", [])
        allowed_produced_by = props.get("produced_by", {}).get("enum", [])
        if kind not in allowed_kinds:
            raise ValueError(
                f"--kind not allowed by EvidenceManifest schema enum: {kind!r}"
            )
        if produced_by not in allowed_produced_by:
            raise ValueError(
                f"--produced-by not allowed by EvidenceManifest schema enum: {produced_by!r}"
            )

        manifest_obj = json.loads(manifest_path.read_text(encoding="utf-8", errors="strict"))
        if not isinstance(manifest_obj, dict):
            raise ValueError("EvidenceManifest must be a JSON object")
        artifacts = manifest_obj.get("artifacts")
        if not isinstance(artifacts, list):
            raise ValueError("EvidenceManifest.artifacts missing/invalid")

        artifact_bytes = artifact_path.read_bytes()
        artifact_hash = sha256_bytes(artifact_bytes)
        storage_ref_raw = safe_relpath(repo_root, artifact_path)
        storage_ref = normalize_repo_rel(storage_ref_raw, allow_backslashes=False)
        new_artifact = {
            "kind": kind,
            "id": artifact_id,
            "hash": artifact_hash,
            "media_type": media_type,
            "storage_ref": storage_ref,
            "produced_by": produced_by,
        }

        replaced = False
        out_artifacts: list[object] = []
        for item in artifacts:
            if not isinstance(item, dict):
                out_artifacts.append(item)
                continue
            if item.get("kind") == kind and item.get("id") == artifact_id:
                if not replaced:
                    out_artifacts.append(new_artifact)
                    replaced = True
                continue
            out_artifacts.append(item)
        if not replaced:
            out_artifacts.append(new_artifact)

        manifest_obj["artifacts"] = out_artifacts
        errs = validate_schema(
            manifest_obj,
            evidence_schema,
            root_schema=evidence_schema,
            path="EvidenceManifest",
        )
        if errs:
            first = errs[0]
            raise ValueError(
                f"EvidenceManifest schema invalid after mutation at {first.path}: {first.message}"
            )

        out_data = json.dumps(manifest_obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        manifest_path.write_text(
            out_data,
            encoding="utf-8",
            errors="strict",
            newline="\n",
        )

        print(f"[belgi manifest add] manifest: {safe_relpath(repo_root, manifest_path)}", file=sys.stderr)
        print(
            f"[belgi manifest add] artifact: {kind}:{artifact_id} hash={artifact_hash}",
            file=sys.stderr,
        )
        print(f"[belgi manifest add] storage_ref: {storage_ref}", file=sys.stderr)
        return 0
    except Exception as e:
        print(f"[belgi manifest add] ERROR: {e}", file=sys.stderr)
        return 3

def cmd_bundle_check(args: argparse.Namespace) -> int:
    """Run the bounded demo-grade evidence bundle checker."""
    from belgi.core.hash import is_hex_sha256, sha256_bytes
    from belgi.protocol.pack import get_builtin_protocol_context
    from chain.seal_bundle import _seal_hash as canonical_seal_hash
    
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
        print("[belgi bundle check] FAIL: required files check", file=sys.stderr)
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
        print("[belgi bundle check] FAIL: JSON parse errors", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    
    # Verify protocol identity binding (pack_id/pack_name/manifest_sha256).
    # NOTE: source is metadata and is intentionally NOT treated as identity.
    checks_total += 1
    protocol: Any | None = None
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

        if not isinstance(obj_hash, str) or not is_hex_sha256(obj_hash):
            failures.append(f"{field}.hash: invalid SHA-256 format")
            return False, ""
        declared_hash = obj_hash.lower()
        
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
        if computed != declared_hash:
            failures.append(
                f"{field}: hash mismatch for {target_path.name} "
                f"(declared={declared_hash[:16]}..., computed={computed[:16]}...)"
            )
            return False, ""

        return True, declared_hash
    
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

        if not isinstance(declared_seal_hash, str) or not is_hex_sha256(declared_seal_hash):
            failures.append("SealManifest.seal_hash: invalid or missing SHA-256")
        elif not final_commit_sha:
            failures.append("SealManifest.final_commit_sha: missing or empty")
        elif not run_id:
            failures.append("SealManifest.run_id: missing or empty")
        else:
            declared_seal_hash = declared_seal_hash.lower()
            try:
                computed_seal = canonical_seal_hash(dict(seal_manifest))
            except Exception as e:
                failures.append(f"seal_hash recomputation failed: {e}")
            else:
                computed_seal_l = computed_seal.lower()
                if computed_seal_l == declared_seal_hash:
                    checks_passed += 1
                else:
                    failures.append(
                        f"seal_hash mismatch: declared={declared_seal_hash[:16]}..., "
                        f"computed={computed_seal_l[:16]}..."
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
    if protocol is None:
        print("[belgi bundle check] ERROR: builtin protocol context unavailable", file=sys.stderr)
        return 1
    if getattr(args, "verbose", False):
        print(f"[belgi bundle check] source: {bundle_dir}", file=sys.stdout)
        print(f"[belgi bundle check] run_id: {display_run_id}", file=sys.stdout)
        print(f"[belgi bundle check] protocol_pack: {protocol.pack_name} ({protocol.pack_id[:16]}...)", file=sys.stdout)
        print(f"[belgi bundle check] checks: {checks_passed}/{checks_total} passed", file=sys.stdout)
    print("PASS", file=sys.stdout)
    return 0
