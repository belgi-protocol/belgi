from __future__ import annotations

import base64
from typing import Any

from belgi.core.hash import sha256_bytes
from belgi.core.jail import safe_relpath
from belgi.core.jail import resolve_storage_ref
from chain.logic.base import CheckResult
from chain.logic.s_checks.context import SCheckContext


def _resolve_pubkey_bytes(repo_root, locked_spec: dict[str, Any]) -> bytes:
    env = locked_spec.get("environment_envelope")
    if not isinstance(env, dict):
        raise ValueError("LockedSpec.environment_envelope missing/invalid")

    seal_pubkey_ref = env.get("seal_pubkey_ref")
    if not isinstance(seal_pubkey_ref, dict):
        raise ValueError("LockedSpec.environment_envelope.seal_pubkey_ref missing/invalid")

    storage_ref = seal_pubkey_ref.get("storage_ref")
    declared_hash = seal_pubkey_ref.get("hash")
    if not isinstance(storage_ref, str) or not storage_ref:
        raise ValueError("seal_pubkey_ref.storage_ref missing/invalid")
    if not isinstance(declared_hash, str) or not declared_hash:
        raise ValueError("seal_pubkey_ref.hash missing/invalid")

    p = resolve_storage_ref(repo_root, storage_ref)
    blob = p.read_bytes()
    digest = sha256_bytes(blob).lower()
    if digest != str(declared_hash).lower():
        raise ValueError(f"seal_pubkey_ref hash mismatch: declared {declared_hash}, computed {digest}")
    return blob


def run(ctx: SCheckContext) -> list[CheckResult]:
    repo_root = ctx.repo_root
    sm = ctx.seal_manifest

    tier_requires_sig = ctx.tier_id in {"tier-2", "tier-3"}

    sig_alg = sm.get("signature_alg")
    sig_b64 = sm.get("signature")

    if tier_requires_sig and (sig_alg is None or sig_b64 is None):
        return [
            CheckResult(
                check_id="S4",
                status="FAIL",
                category="FS-SIGNATURE-MISSING",
                message="Tier-2/3 requires SealManifest.signature_alg and SealManifest.signature",
                pointers=[safe_relpath(repo_root, ctx.seal_manifest_path)],
                remediation_next_instruction="Do produce a Tier-2/3 cryptographic seal signature then re-run S.",
            )
        ]

    # Tier-0/1: signature is optional, but if present it MUST verify (fail-closed).
    if sig_alg is None and sig_b64 is None:
        return [CheckResult(check_id="S4", status="PASS", message="No signature present (allowed for tier-0/1).", pointers=[])]

    if sig_alg != "ed25519":
        return [
            CheckResult(
                check_id="S4",
                status="FAIL",
                category="FS-SIGNATURE-INVALID",
                message="SealManifest.signature_alg must equal 'ed25519'",
                pointers=[safe_relpath(repo_root, ctx.seal_manifest_path)],
                remediation_next_instruction="Do regenerate SealManifest with a valid signature_alg then re-run S.",
            )
        ]

    if not isinstance(sig_b64, str) or not sig_b64.strip():
        return [
            CheckResult(
                check_id="S4",
                status="FAIL",
                category="FS-SIGNATURE-INVALID",
                message="SealManifest.signature missing/empty",
                pointers=[safe_relpath(repo_root, ctx.seal_manifest_path)],
                remediation_next_instruction="Do provide a valid base64 Ed25519 signature then re-run S.",
            )
        ]

    try:
        sig_bytes = base64.b64decode(sig_b64.strip(), validate=True)
    except Exception:
        return [
            CheckResult(
                check_id="S4",
                status="FAIL",
                category="FS-SIGNATURE-INVALID",
                message="SealManifest.signature must be valid base64",
                pointers=[safe_relpath(repo_root, ctx.seal_manifest_path)],
                remediation_next_instruction="Do provide a valid base64 Ed25519 signature then re-run S.",
            )
        ]

    if len(sig_bytes) != 64:
        return [
            CheckResult(
                check_id="S4",
                status="FAIL",
                category="FS-SIGNATURE-INVALID",
                message="SealManifest.signature must decode to 64 bytes",
                pointers=[safe_relpath(repo_root, ctx.seal_manifest_path)],
                remediation_next_instruction="Do provide a valid Ed25519 signature (64 bytes) then re-run S.",
            )
        ]

    try:
        pub_bytes = _resolve_pubkey_bytes(repo_root, ctx.locked_spec)
        from chain.seal_bundle import _load_ed25519_public_key, _seal_signature_payload, _verify_ed25519_signature  # type: ignore

        pub = _load_ed25519_public_key(pub_bytes)
        payload_bytes = _seal_signature_payload(sm)
        _verify_ed25519_signature(pub, sig_bytes, payload_bytes, context="SealManifest.signature")
    except RuntimeError as e:
        return [
            CheckResult(
                check_id="S4",
                status="FAIL",
                category="FS-SIGNATURE-VERIFY-UNAVAILABLE",
                message=str(e),
                pointers=[safe_relpath(repo_root, ctx.locked_spec_path)],
                remediation_next_instruction="Do include the required crypto dependency in the declared Environment Envelope then re-run S.",
            )
        ]
    except Exception as e:
        return [
            CheckResult(
                check_id="S4",
                status="FAIL",
                category="FS-SIGNATURE-INVALID",
                message=str(e),
                pointers=[safe_relpath(repo_root, ctx.seal_manifest_path)],
                remediation_next_instruction="Do regenerate SealManifest with a valid cryptographic seal signature then re-run S.",
            )
        ]

    return [CheckResult(check_id="S4", status="PASS", message="Cryptographic seal signature verifies.", pointers=[])]
