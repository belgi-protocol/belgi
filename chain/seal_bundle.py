#!/usr/bin/env python3
"""BELGI Seal tool (S): produce SealManifest.json deterministically.

- Reads: LockedSpec.json + GateVerdict(Q).json + GateVerdict(R).json + EvidenceManifest.json
- Optionally reads: Waiver.json files + replay instructions file
- Writes: SealManifest.json (schema-valid) with seal_hash per docs/operations/evidence-bundles.md

Determinism posture:
- No timestamps are generated; sealed_at MUST be provided.
- JSON is serialized canonically (sorted keys, no whitespace).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from belgi.core.jail import resolve_repo_rel_path
from belgi.core.jail import resolve_storage_ref
from belgi.core.schema import validate_schema


_SHA256_RE = re_compile = None


def _re(pattern: str) -> Any:
    # Local helper to avoid importing re at module import time in older runtimes.
    import re

    return re.compile(pattern)


_SHA256_RE = _re(r"^[A-Fa-f0-9]{64}$")
_SHA1_RE = _re(r"^[A-Fa-f0-9]{40}$")
_GIT_SHA_RE = _re(r"^[A-Fa-f0-9]{40}([A-Fa-f0-9]{24})?$")  # SHA-1 (40) or SHA-256 (64)
_SEMVER_RE = _re(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_STORAGE_REF_RE = _re(r"^(?!/)(?!\\./)(?!.*\\.\\.)(?!.*\\\\)(?!.*://)(?!.*:)(?!.*//).+$")
_B64_RE = _re(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")


def _sha256_hex_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(obj: Any) -> str:
    # Normative requirements in docs/operations/evidence-bundles.md
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _verify_keys_sorted_lexicographically(obj: Any, path: str = "") -> list[str]:
    """Recursively verify all object keys are sorted lexicographically.
    
    Returns list of violations (empty if all sorted).
    """
    violations: list[str] = []
    
    if isinstance(obj, dict):
        keys = list(obj.keys())
        sorted_keys = sorted(keys)
        if keys != sorted_keys:
            violations.append(f"{path or 'root'}: keys not sorted (got {keys}, expected {sorted_keys})")
        for k, v in obj.items():
            child_path = f"{path}.{k}" if path else k
            violations.extend(_verify_keys_sorted_lexicographically(v, child_path))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            violations.extend(_verify_keys_sorted_lexicographically(item, f"{path}[{i}]"))
    
    return violations


def _verify_canonical_json_conformance(obj: Any, *, field: str) -> None:
    """Verify JSON object conforms to canonical serialization (RFC 8785-like).
    
    Deterministic checks:
    1. Key ordering: all object keys MUST be sorted lexicographically
    2. Round-trip stability: parse + re-serialize must be byte-identical
    3. Control characters: \n, \r, \t MUST be escaped (not literal) in output
    4. No disallowed control characters (U+0000-U+001F except escaped)
    """
    # 1. Explicit key ordering check (defense-in-depth beyond sort_keys=True)
    key_violations = _verify_keys_sorted_lexicographically(obj)
    if key_violations:
        raise ValueError(f"{field} has unsorted keys: {'; '.join(key_violations[:3])}")
    
    canonical = _canonical_json(obj)
    
    # 2. Round-trip stability check: parse and re-serialize must be identical
    try:
        reparsed = json.loads(canonical)
        recanonical = _canonical_json(reparsed)
        if canonical != recanonical:
            raise ValueError(f"{field} fails canonical JSON round-trip stability")
    except json.JSONDecodeError as e:
        raise ValueError(f"{field} produces invalid JSON: {e}") from e
    
    # 3. Control character check: NO literal control chars in output.
    # JSON spec requires \n, \r, \t to be escaped as \\n, \\r, \\t in strings.
    # The canonical output should contain NO literal bytes < 0x20.
    for i, ch in enumerate(canonical):
        if ord(ch) < 0x20:
            # ANY control character in serialized JSON is a conformance violation.
            # Proper JSON escapes them as \n, \r, \t, \uXXXX (which are printable).
            raise ValueError(
                f"{field} contains literal control character U+{ord(ch):04X} at position {i}; "
                f"control characters must be escaped in canonical JSON"
            )


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="strict"))


def _parse_rfc3339(dt: str) -> None:
    if not isinstance(dt, str) or not dt.strip():
        raise ValueError("sealed_at missing/empty")
    s = dt.strip()
    if "T" not in s:
        raise ValueError("sealed_at missing 'T' separator")
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    parsed = datetime.fromisoformat(s)
    if parsed.tzinfo is None:
        raise ValueError("sealed_at missing timezone offset")


def _require_sha256_hex(v: Any, *, field: str) -> str:
    if not isinstance(v, str) or not _SHA256_RE.match(v):
        raise ValueError(f"{field} must be SHA-256 hex")
    return v


def _validate_object_ref(obj: Any, *, field: str) -> None:
    if not isinstance(obj, dict):
        raise ValueError(f"{field} must be an object")
    allowed_keys = {"id", "hash", "storage_ref"}
    extra = set(obj.keys()) - allowed_keys
    if extra:
        raise ValueError(f"{field} has unexpected keys: {sorted(extra)}")
    obj_id = obj.get("id")
    if not isinstance(obj_id, str) or not obj_id.strip():
        raise ValueError(f"{field}.id missing/empty")
    _require_sha256_hex(obj.get("hash"), field=f"{field}.hash")
    storage_ref = obj.get("storage_ref")
    if not isinstance(storage_ref, str) or not storage_ref.strip():
        raise ValueError(f"{field}.storage_ref missing/empty")
    if not _STORAGE_REF_RE.match(storage_ref):
        raise ValueError(f"{field}.storage_ref is not a safe repo/bundle-relative POSIX path")


def _validate_seal_manifest(manifest: Any) -> None:
    if not isinstance(manifest, dict):
        raise ValueError("SealManifest must be a JSON object")

    required = {
        "schema_version",
        "belgi_version",
        "run_id",
        "locked_spec_ref",
        "gate_q_verdict_ref",
        "gate_r_verdict_ref",
        "evidence_manifest_ref",
        "waivers",
        "final_commit_sha",
        "sealed_at",
        "seal_hash",
        "signer",
    }
    allowed = set(required) | {"replay_instructions_ref", "signature_alg", "signature"}
    missing = [k for k in sorted(required) if k not in manifest]
    if missing:
        raise ValueError(f"SealManifest missing required field(s): {', '.join(missing)}")

    extra = set(manifest.keys()) - allowed
    if extra:
        raise ValueError(f"SealManifest has unexpected field(s): {sorted(extra)}")

    schema_version = manifest.get("schema_version")
    if not isinstance(schema_version, str) or not _SEMVER_RE.match(schema_version):
        raise ValueError("SealManifest.schema_version must be semver-like")

    belgi_version = manifest.get("belgi_version")
    if not isinstance(belgi_version, str) or not belgi_version.strip():
        raise ValueError("SealManifest.belgi_version missing/empty")

    run_id = manifest.get("run_id")
    if not isinstance(run_id, str) or not run_id.strip():
        raise ValueError("SealManifest.run_id missing/empty")

    _validate_object_ref(manifest.get("locked_spec_ref"), field="SealManifest.locked_spec_ref")
    _validate_object_ref(manifest.get("gate_q_verdict_ref"), field="SealManifest.gate_q_verdict_ref")
    _validate_object_ref(manifest.get("gate_r_verdict_ref"), field="SealManifest.gate_r_verdict_ref")
    _validate_object_ref(manifest.get("evidence_manifest_ref"), field="SealManifest.evidence_manifest_ref")

    waivers = manifest.get("waivers")
    if not isinstance(waivers, list):
        raise ValueError("SealManifest.waivers must be an array")
    for i, w in enumerate(waivers):
        _validate_object_ref(w, field=f"SealManifest.waivers[{i}]")

    final_commit_sha = manifest.get("final_commit_sha")
    if not isinstance(final_commit_sha, str) or not _GIT_SHA_RE.match(final_commit_sha):
        raise ValueError("SealManifest.final_commit_sha must be 40-hex (SHA-1) or 64-hex (SHA-256)")

    _parse_rfc3339(str(manifest.get("sealed_at")))
    _require_sha256_hex(manifest.get("seal_hash"), field="SealManifest.seal_hash")

    signer = manifest.get("signer")
    if not isinstance(signer, str) or not signer.strip():
        raise ValueError("SealManifest.signer missing/empty")

    sig_alg = manifest.get("signature_alg")
    sig_b64 = manifest.get("signature")
    if (sig_alg is None) != (sig_b64 is None):
        raise ValueError("SealManifest.signature_alg and SealManifest.signature must be both present or both absent")
    if sig_alg is not None:
        if not isinstance(sig_alg, str) or sig_alg != "ed25519":
            raise ValueError("SealManifest.signature_alg must equal 'ed25519'")
        if not isinstance(sig_b64, str) or not sig_b64.strip() or not _B64_RE.match(sig_b64.strip()):
            raise ValueError("SealManifest.signature must be base64")
        try:
            sig_bytes = base64.b64decode(sig_b64.strip(), validate=True)
        except Exception as e:
            raise ValueError("SealManifest.signature must be valid base64") from e
        if len(sig_bytes) != 64:
            raise ValueError("SealManifest.signature must decode to 64 bytes (Ed25519 signature)")

    if "replay_instructions_ref" in manifest:
        _validate_object_ref(manifest.get("replay_instructions_ref"), field="SealManifest.replay_instructions_ref")


def _repo_rel_posix(repo_root: Path, p: Path) -> str:
    try:
        rel = p.resolve().relative_to(repo_root.resolve())
    except Exception as e:
        raise ValueError(f"Path not under repo root: {p}") from e
    return rel.as_posix()


def _object_ref_for_json(repo_root: Path, path: Path, *, default_id: str, id_key: str | None) -> dict[str, str]:
    data = _load_json(path)

    obj_id = None
    if id_key:
        v = data.get(id_key) if isinstance(data, dict) else None
        if isinstance(v, str) and v.strip():
            obj_id = v.strip()

    if obj_id is None:
        obj_id = default_id

    digest = _sha256_hex_bytes(path.read_bytes())
    storage_ref = _repo_rel_posix(repo_root, path)

    # Canonical JSON conformance: keys MUST be lexicographically sorted.
    return {"hash": digest, "id": obj_id, "storage_ref": storage_ref}


def _resolve_objectref_bytes(repo_root: Path, obj_ref: dict[str, Any], *, field: str) -> bytes:
    _validate_object_ref(obj_ref, field=field)
    storage_ref = str(obj_ref.get("storage_ref"))
    if not _STORAGE_REF_RE.match(storage_ref):
        raise ValueError(f"{field}.storage_ref is not a safe repo/bundle-relative POSIX path")

    p = resolve_storage_ref(repo_root, storage_ref)
    blob = p.read_bytes()
    digest = _sha256_hex_bytes(blob)
    declared = str(obj_ref.get("hash"))
    if digest.lower() != declared.lower():
        raise ValueError(f"{field} hash mismatch: declared {declared}, computed {digest}")
    return blob


def _load_replay_instructions_schema(repo_root: Path) -> dict[str, Any]:
    schema_path = resolve_storage_ref(repo_root, "schemas/ReplayInstructionsPayload.schema.json")
    obj = _load_json(schema_path)
    if not isinstance(obj, dict):
        raise ValueError("ReplayInstructionsPayload schema must be a JSON object")
    return obj


def _validate_replay_instructions_payload(repo_root: Path, replay_ref: dict[str, Any], schema: dict[str, Any]) -> None:
    storage_ref = str(replay_ref.get("storage_ref") or "").strip()
    if not storage_ref:
        raise ValueError("ReplayInstructionsPayload storage_ref missing/empty")

    replay_path = resolve_storage_ref(repo_root, storage_ref)
    raw = replay_path.read_text(encoding="utf-8", errors="strict")
    try:
        replay_doc = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Replay instructions JSON invalid: {e}") from e

    if not isinstance(replay_doc, dict):
        raise ValueError("Replay instructions JSON must be an object")

    errs = validate_schema(replay_doc, schema, root_schema=schema, path="ReplayInstructionsPayload")
    if errs:
        raise ValueError("Replay instructions schema validation failed")

    source_ref = replay_doc.get("source_archive_ref")
    _validate_object_ref(source_ref, field="ReplayInstructionsPayload.source_archive_ref")
    _resolve_objectref_bytes(repo_root, source_ref, field="ReplayInstructionsPayload.source_archive_ref")


def _load_ed25519_public_key(blob: bytes) -> Any:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception as e:  # pragma: no cover
        raise ValueError(
            "Missing crypto dependency for Ed25519 verification (install 'cryptography' in the declared Environment Envelope)."
        ) from e

    trimmed = blob.strip()
    try:
        hex_s = trimmed.decode("ascii", errors="strict").strip()
        if len(hex_s) == 64 and all(c in "0123456789abcdefABCDEF" for c in hex_s):
            return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_s))
    except Exception:
        pass

    key = serialization.load_pem_public_key(trimmed)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Public key is not Ed25519")
    return key


def _load_ed25519_private_key(blob: bytes) -> Any:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except Exception as e:  # pragma: no cover
        raise ValueError(
            "Missing crypto dependency for Ed25519 signing (install 'cryptography' in the declared Environment Envelope)."
        ) from e

    trimmed = blob.strip()
    try:
        hex_s = trimmed.decode("ascii", errors="strict").strip()
        if len(hex_s) == 64 and all(c in "0123456789abcdefABCDEF" for c in hex_s):
            return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(hex_s))
    except Exception:
        pass

    key = serialization.load_pem_private_key(trimmed, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Private key is not Ed25519")
    return key


def _verify_ed25519_signature(pub: Any, sig_bytes: bytes, payload: bytes, *, context: str) -> None:
    try:
        pub.verify(sig_bytes, payload)
    except Exception as e:
        # Any verification failure is a deterministic policy failure (NO-GO).
        # (cryptography.exceptions.InvalidSignature has an empty string repr)
        raise ValueError(f"Invalid Ed25519 signature ({context})") from None


def _seal_hash(manifest: dict[str, Any]) -> str:
    # Normative algorithm in docs/operations/evidence-bundles.md
    unsigned = dict(manifest)
    unsigned.pop("seal_hash", None)
    # Signature fields are not part of the seal_hash computation.
    unsigned.pop("signature_alg", None)
    unsigned.pop("signature", None)

    # Verify canonical JSON conformance before computing seal_hash.
    # This ensures deterministic, reproducible sealing across implementations.
    _verify_canonical_json_conformance(unsigned, field="SealManifestUnsigned")

    ref_hashes: list[str] = [
        unsigned["locked_spec_ref"]["hash"],
        unsigned["gate_q_verdict_ref"]["hash"],
        unsigned["gate_r_verdict_ref"]["hash"],
        unsigned["evidence_manifest_ref"]["hash"],
    ]

    waivers = unsigned.get("waivers")
    if isinstance(waivers, list):
        for w in waivers:
            if not isinstance(w, dict):
                raise ValueError("SealManifest.waivers entries must be objects")
            ref_hashes.append(_require_sha256_hex(w.get("hash"), field="SealManifest.waivers[].hash"))

    if "replay_instructions_ref" in unsigned:
        rir = unsigned.get("replay_instructions_ref")
        if not isinstance(rir, dict):
            raise ValueError("SealManifest.replay_instructions_ref must be an object")
        ref_hashes.append(_require_sha256_hex(rir.get("hash"), field="SealManifest.replay_instructions_ref.hash"))

    payload = _canonical_json(unsigned) + "\n" + "\n".join(ref_hashes) + "\n"
    return _sha256_hex_bytes(payload.encode("utf-8"))


def _seal_signature_payload(manifest: dict[str, Any]) -> bytes:
    # Deterministic signature payload for Tier 2–3 cryptographic anchor.
    # Excludes final_commit_sha (informational) and derived fields.
    unsigned = dict(manifest)
    unsigned.pop("seal_hash", None)
    unsigned.pop("signature_alg", None)
    unsigned.pop("signature", None)
    unsigned.pop("final_commit_sha", None)

    _verify_canonical_json_conformance(unsigned, field="SealManifestAnchorUnsigned")

    # Signature binds the SealManifest anchor JSON bytes (not a derived ref-hash list).
    payload = _canonical_json(unsigned) + "\n"
    return payload.encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".", help="Repo root")
    ap.add_argument("--locked-spec", required=True, help="Path to LockedSpec.json")
    ap.add_argument("--gate-q-verdict", required=True, help="Path to GateVerdict(Q).json")
    ap.add_argument("--gate-r-verdict", required=True, help="Path to GateVerdict(R).json")
    ap.add_argument("--evidence-manifest", required=True, help="Path to EvidenceManifest.json")
    ap.add_argument("--waiver", action="append", default=[], help="Optional waiver JSON path (repeatable)")
    ap.add_argument("--replay-instructions", default=None, help="Optional replay instructions JSON path")

    ap.add_argument("--schema-version", default="1.0.0", help="SealManifest schema_version")
    ap.add_argument("--final-commit-sha", required=True, help="Final git commit SHA (40 hex)")
    ap.add_argument("--sealed-at", required=True, help="RFC3339 timestamp (must include timezone)")
    ap.add_argument("--signer", required=True, help="Signing identity label")
    ap.add_argument(
        "--seal-private-key",
        default=None,
        help="Optional Ed25519 private key (PEM or 64-hex seed) used to produce Tier-2/3 cryptographic seal signature.",
    )
    ap.add_argument(
        "--fixture-mode",
        action="store_true",
        help=(
            "Allow repo-local fixture signing keys for --seal-private-key (fixture-only). "
            "When set, --seal-private-key MUST be under policy/fixtures/. Default: NO-GO."
        ),
    )
    ap.add_argument(
        "--seal-signature",
        default=None,
        help="Optional base64 Ed25519 signature to embed as the cryptographic seal signature (verified against the pinned seal_pubkey_ref).",
    )
    ap.add_argument(
        "--seal-signature-file",
        default=None,
        help="Optional path to a file containing the base64 Ed25519 signature (whitespace-trimmed). Verified against the pinned seal_pubkey_ref.",
    )

    ap.add_argument("--out", default="SealManifest.json", help="Output SealManifest.json path")

    args = ap.parse_args(argv)

    repo_root = Path(args.repo).resolve()

    try:
        locked_spec_path = resolve_repo_rel_path(
            repo_root,
            args.locked_spec,
            must_exist=True,
            must_be_file=True,
            allow_backslashes=True,
            forbid_symlinks=True,
        )
        q_path = resolve_repo_rel_path(
            repo_root,
            args.gate_q_verdict,
            must_exist=True,
            must_be_file=True,
            allow_backslashes=True,
            forbid_symlinks=True,
        )
        r_path = resolve_repo_rel_path(
            repo_root,
            args.gate_r_verdict,
            must_exist=True,
            must_be_file=True,
            allow_backslashes=True,
            forbid_symlinks=True,
        )
        evidence_path = resolve_repo_rel_path(
            repo_root,
            args.evidence_manifest,
            must_exist=True,
            must_be_file=True,
            allow_backslashes=True,
            forbid_symlinks=True,
        )
    except ValueError as e:
        raise RuntimeError(str(e)) from e

    try:
        locked_spec = _load_json(locked_spec_path)
        if not isinstance(locked_spec, dict):
            raise ValueError("LockedSpec must be a JSON object")
        run_id = str(locked_spec.get("run_id") or "").strip()
        belgi_version = str(locked_spec.get("belgi_version") or "").strip()
        tier_id = ""
        tier = locked_spec.get("tier")
        if isinstance(tier, dict):
            tier_id = str(tier.get("tier_id") or "").strip()
        if not run_id:
            raise ValueError("LockedSpec.run_id missing/empty")
        if not belgi_version:
            raise ValueError("LockedSpec.belgi_version missing/empty")
        if not tier_id:
            raise ValueError("LockedSpec.tier.tier_id missing/empty")

        # Extract waivers_applied from LockedSpec for binding verification.
        locked_waivers_applied = locked_spec.get("waivers_applied")
        if not isinstance(locked_waivers_applied, list):
            locked_waivers_applied = []

        locked_ref = _object_ref_for_json(
            repo_root,
            locked_spec_path,
            default_id=f"lockedspec-{run_id}",
            id_key=None,
        )
        q_ref = _object_ref_for_json(
            repo_root,
            q_path,
            default_id=f"gate-Q-{run_id}",
            id_key=None,
        )
        r_ref = _object_ref_for_json(
            repo_root,
            r_path,
            default_id=f"gate-R-{run_id}",
            id_key=None,
        )
        evidence_ref = _object_ref_for_json(
            repo_root,
            evidence_path,
            default_id=f"evidence-manifest-{run_id}",
            id_key=None,
        )

        waiver_refs: list[dict[str, str]] = []
        for w in args.waiver:
            try:
                wp = resolve_repo_rel_path(
                    repo_root,
                    w,
                    must_exist=True,
                    must_be_file=True,
                    allow_backslashes=True,
                    forbid_symlinks=True,
                )
            except ValueError as e:
                raise RuntimeError(str(e)) from e
            waiver_doc = _load_json(wp)
            waiver_id = None
            if isinstance(waiver_doc, dict):
                v = waiver_doc.get("waiver_id")
                if isinstance(v, str) and v.strip():
                    waiver_id = v.strip()
            waiver_refs.append(
                _object_ref_for_json(
                    repo_root,
                    wp,
                    default_id=waiver_id or f"waiver-{wp.stem}",
                    id_key=None,
                )
            )

        # Waiver binding verification.
        # SealManifest.waivers MUST match LockedSpec.waivers_applied (by storage_ref).
        # This prevents post-hoc waiver injection or omission during sealing.
        sealed_waiver_refs = {ref["storage_ref"] for ref in waiver_refs}
        locked_waiver_refs = {str(w).strip() for w in locked_waivers_applied if isinstance(w, str) and w.strip()}
        
        if sealed_waiver_refs != locked_waiver_refs:
            missing_in_seal = locked_waiver_refs - sealed_waiver_refs
            extra_in_seal = sealed_waiver_refs - locked_waiver_refs
            parts = []
            if missing_in_seal:
                parts.append(f"missing from --waiver: {sorted(missing_in_seal)}")
            if extra_in_seal:
                parts.append(f"not in LockedSpec.waivers_applied: {sorted(extra_in_seal)}")
            raise ValueError(f"Waiver binding mismatch: {'; '.join(parts)}")

        replay_ref = None
        if args.replay_instructions:
            try:
                rp = resolve_repo_rel_path(
                    repo_root,
                    args.replay_instructions,
                    must_exist=True,
                    must_be_file=True,
                    allow_backslashes=True,
                    forbid_symlinks=True,
                )
            except ValueError as e:
                raise RuntimeError(str(e)) from e
            replay_ref = _object_ref_for_json(
                repo_root,
                rp,
                default_id=f"replay-{run_id}",
                id_key=None,
            )

            replay_schema = _load_replay_instructions_schema(repo_root)
            _validate_replay_instructions_payload(repo_root, replay_ref, replay_schema)

        # Canonical JSON conformance: insertion order MUST be lexicographically sorted.
        manifest_items: list[tuple[str, Any]] = [
            ("belgi_version", belgi_version),
            ("evidence_manifest_ref", evidence_ref),
            ("final_commit_sha", str(args.final_commit_sha)),
            ("gate_q_verdict_ref", q_ref),
            ("gate_r_verdict_ref", r_ref),
            ("locked_spec_ref", locked_ref),
        ]
        if replay_ref is not None:
            manifest_items.append(("replay_instructions_ref", replay_ref))
        manifest_items.extend(
            [
                ("run_id", run_id),
                ("schema_version", str(args.schema_version)),
                ("seal_hash", "0" * 64),
                ("sealed_at", str(args.sealed_at)),
                ("signer", str(args.signer)),
                ("waivers", waiver_refs),
            ]
        )
        manifest: dict[str, Any] = dict(manifest_items)

        manifest["seal_hash"] = _seal_hash(manifest)

        # Tier-2/3 cryptographic seal signature (Ed25519, detached).
        sig_required = tier_id in {"tier-2", "tier-3"}
        if args.seal_signature and args.seal_signature_file:
            raise ValueError("Provide at most one of --seal-signature or --seal-signature-file")

        sig_b64_override: str | None = None
        if args.seal_signature is not None:
            sig_b64_override = str(args.seal_signature).strip()
        elif args.seal_signature_file is not None:
            try:
                sig_path = resolve_repo_rel_path(
                    repo_root,
                    args.seal_signature_file,
                    must_exist=True,
                    must_be_file=True,
                    allow_backslashes=True,
                    forbid_symlinks=True,
                )
            except ValueError as e:
                raise RuntimeError(str(e)) from e
            sig_b64_override = sig_path.read_text(encoding="utf-8", errors="strict").strip()

        priv_path: Path | None = None
        if args.seal_private_key:
            try:
                priv_path = resolve_repo_rel_path(
                    repo_root,
                    args.seal_private_key,
                    must_exist=True,
                    must_be_file=True,
                    allow_backslashes=True,
                    forbid_symlinks=True,
                )
            except ValueError as e:
                raise RuntimeError(str(e)) from e

            # Fixture-only guard: deterministic fixture keys must not be used accidentally.
            fixtures_root = (repo_root / "policy" / "fixtures").resolve()

            is_fixture_key = False
            try:
                priv_path.resolve().relative_to(fixtures_root)
                is_fixture_key = True
            except Exception:
                is_fixture_key = False

            if is_fixture_key and not bool(args.fixture_mode):
                raise ValueError(
                    "FIXTURE-KEY NO-GO: --seal-private-key requires explicit --fixture-mode (fixture-only signing keys)."
                )
            if bool(args.fixture_mode) and not is_fixture_key:
                raise ValueError(
                    "FIXTURE-KEY NO-GO: --seal-private-key must be under policy/fixtures/ when --fixture-mode is set."
                )

        if sig_required or args.seal_private_key or sig_b64_override is not None:
            env = locked_spec.get("environment_envelope")
            if not isinstance(env, dict):
                raise ValueError("LockedSpec.environment_envelope missing/invalid")
            seal_pubkey_ref = env.get("seal_pubkey_ref")
            if not isinstance(seal_pubkey_ref, dict):
                raise ValueError("LockedSpec.environment_envelope.seal_pubkey_ref missing/invalid")
            pub_bytes = _resolve_objectref_bytes(repo_root, seal_pubkey_ref, field="LockedSpec.environment_envelope.seal_pubkey_ref")
            pub = _load_ed25519_public_key(pub_bytes)

            payload_bytes = _seal_signature_payload(manifest)

            if sig_b64_override is not None:
                if not sig_b64_override or not _B64_RE.match(sig_b64_override):
                    raise ValueError("--seal-signature must be valid base64")
                try:
                    sig_bytes = base64.b64decode(sig_b64_override, validate=True)
                except Exception as e:
                    raise ValueError("--seal-signature must be valid base64") from e
                if len(sig_bytes) != 64:
                    raise ValueError("--seal-signature must decode to 64 bytes (Ed25519 signature)")
                _verify_ed25519_signature(pub, sig_bytes, payload_bytes, context="--seal-signature")
                manifest["signature_alg"] = "ed25519"
                manifest["signature"] = sig_b64_override
            else:
                if not args.seal_private_key:
                    raise ValueError(
                        "Tier-2/3 requires a cryptographic seal signature: provide --seal-private-key (to sign) or --seal-signature/--seal-signature-file (precomputed, verified)."
                    )
                if priv_path is None:
                    raise ValueError("--seal-private-key resolved to empty path")

                priv_bytes = priv_path.read_bytes()
                priv = _load_ed25519_private_key(priv_bytes)

                sig_bytes = priv.sign(payload_bytes)
                sig_b64 = base64.b64encode(sig_bytes).decode("ascii")

                # Verify against the pinned public key (fail-closed if mismatch).
                _verify_ed25519_signature(pub, sig_bytes, payload_bytes, context="--seal-private-key")

                manifest["signature_alg"] = "ed25519"
                manifest["signature"] = sig_b64

        # Fail-closed: do not write an invalid SealManifest.
        _validate_seal_manifest(manifest)

        try:
            out_path = resolve_repo_rel_path(
                repo_root,
                args.out,
                must_exist=False,
                must_be_file=True,
                allow_backslashes=True,
                forbid_symlinks=True,
            )
        except ValueError as e:
            raise RuntimeError(str(e)) from e
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(_canonical_json(manifest) + "\n", encoding="utf-8", errors="strict")

        print(f"Wrote: {_repo_rel_posix(repo_root, out_path)}")
        print(f"seal_hash: {manifest['seal_hash']}")
        return 0

    except ValueError as e:
        # Deterministic policy/contract failure => NO-GO.
        print(f"NO-GO: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"Usage error: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
