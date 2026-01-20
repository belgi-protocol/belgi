from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from belgi.core.hash import sha256_bytes
from belgi.core.jail import safe_relpath
from belgi.core.schema import validate_schema
from belgi.core.jail import resolve_storage_ref
from chain.logic.base import CheckResult, command_satisfied, find_artifacts_by_kind_id
from .context import RCheckContext


def _load_schema(repo_root: Path, rel: str) -> dict[str, Any] | None:
    try:
        p = (repo_root / Path(*rel.split("/"))).resolve()
        obj = json.loads(p.read_text(encoding="utf-8", errors="strict"))
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def _find_required_command_strings(commands: Any, target: str) -> bool:
    if not isinstance(commands, list):
        return False
    return any(isinstance(entry, str) and entry == target for entry in commands)


def _find_required_command_structured(commands: Any, subcommand: str) -> bool:
    if not isinstance(commands, list):
        return False
    for entry in commands:
        if not isinstance(entry, dict):
            continue
        argv = entry.get("argv")
        if not isinstance(argv, list) or len(argv) < 2 or not all(isinstance(x, str) and x for x in argv):
            continue
        if argv[0] != "belgi" or argv[1] != subcommand:
            continue
        exit_code = entry.get("exit_code")
        if isinstance(exit_code, int) and not isinstance(exit_code, bool) and exit_code == 0:
            return True
    return False


def _command_ok(ctx: RCheckContext, subcommand: str) -> bool:
    mode = ctx.tier_params.get("command_log_mode")
    commands = ctx.evidence_manifest.get("commands_executed")
    return command_satisfied(commands, mode=str(mode), subcommand=subcommand)


def _single_artifact_of_kind(ctx: RCheckContext, kind: str) -> dict[str, Any] | None:
    artifacts = ctx.evidence_manifest.get("artifacts")
    if not isinstance(artifacts, list):
        return None

    matches: list[dict[str, Any]] = []
    for a in artifacts:
        if not isinstance(a, dict):
            continue
        if a.get("kind") == kind:
            matches.append(a)

    if len(matches) != 1:
        return None
    return matches[0]


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _load_ed25519_public_key(pem_bytes: bytes) -> Any:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception as e:  # pragma: no cover
        raise RuntimeError(
            "Missing crypto dependency for Ed25519 verification (install 'cryptography' in the declared Environment Envelope)."
        ) from e

    # Allow either PEM SubjectPublicKeyInfo OR a raw 32-byte public key stored as ASCII hex.
    # This keeps fixtures and bundle-local key pinning simple and deterministic.
    blob = pem_bytes.strip()
    try:
        hex_s = blob.decode("ascii", errors="strict").strip()
        if len(hex_s) == 64 and all(c in "0123456789abcdefABCDEF" for c in hex_s):
            return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_s))
    except Exception:
        pass

    key = serialization.load_pem_public_key(pem_bytes)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Public key is not Ed25519")
    return key


def run(ctx: RCheckContext) -> list[CheckResult]:
    """R6 — Envelope attestation provided + verified (tier-dependent)."""

    requires = ctx.tier_params.get("envelope_policy.requires_attestation")
    em_ptr = f"{safe_relpath(ctx.repo_root, ctx.evidence_manifest_path)}#/envelope_attestation"

    if requires is None:
        return [
            CheckResult(
                check_id="R6",
                status="FAIL",
                category="FR-EVIDENCE-ATTESTATION-MISSING",
                message="Tier parameter 'envelope_policy.requires_attestation' missing; cannot verify R6 deterministically.",
                pointers=[em_ptr],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    if requires != "yes":
        return [
            CheckResult(
                check_id="R6",
                status="PASS",
                category=None,
                message="R6 satisfied: tier does not require envelope attestation.",
                pointers=[em_ptr],
            )
        ]

    if not _command_ok(ctx, "verify-attestation"):
        return [
            CheckResult(
                check_id="R6",
                status="FAIL",
                category="FR-COMMAND-FAILED",
                message="Required command missing/failed: belgi verify-attestation.",
                pointers=[em_ptr],
                remediation_next_instruction="Do ensure required command record belgi verify-attestation exists with exit_code 0 in EvidenceManifest.commands_executed then re-run R.",
            )
        ]

    env = ctx.evidence_manifest.get("envelope_attestation")
    if env is None:
        return [
            CheckResult(
                check_id="R6",
                status="FAIL",
                category="FR-EVIDENCE-ATTESTATION-MISSING",
                message="Tier requires attestation but EvidenceManifest.envelope_attestation is null/missing.",
                pointers=[em_ptr],
                remediation_next_instruction="Do produce envelope attestation evidence under the declared envelope then re-run R.",
            )
        ]

    if not isinstance(env, dict) or not env:
        return [
            CheckResult(
                check_id="R6",
                status="FAIL",
                category="FR-EVIDENCE-ATTESTATION-MISSING",
                message="Tier requires attestation but EvidenceManifest.envelope_attestation is not a non-empty object.",
                pointers=[em_ptr],
                remediation_next_instruction="Do produce envelope attestation evidence under the declared envelope then re-run R.",
            )
        ]

    missing = [k for k in ("id", "hash", "storage_ref") if not isinstance(env.get(k), str) or not str(env.get(k)).strip()]
    if missing:
        return [
            CheckResult(
                check_id="R6",
                status="FAIL",
                category="FR-EVIDENCE-ATTESTATION-MISSING",
                message=f"Tier requires attestation but EvidenceManifest.envelope_attestation missing/empty field(s): {missing}",
                pointers=[em_ptr],
                remediation_next_instruction="Do produce envelope attestation evidence under the declared envelope then re-run R.",
            )
        ]

    attestation_id = str(env.get("id")).strip()
    arts = find_artifacts_by_kind_id(ctx.evidence_manifest.get("artifacts"), kind="env_attestation", artifact_id=attestation_id)
    if len(arts) != 1:
        return [
            CheckResult(
                check_id="R6",
                status="FAIL",
                category="FR-EVIDENCE-ATTESTATION-MISSING",
                message=f"Required env_attestation artifact must match exactly one entry: kind==env_attestation, id=={attestation_id} (count={len(arts)}).",
                pointers=[f"{safe_relpath(ctx.repo_root, ctx.evidence_manifest_path)}#/artifacts"],
                remediation_next_instruction="Do produce envelope attestation evidence under the declared envelope then re-run R.",
            )
        ]

    # Deterministic attestation payload validation + binding.
    # Enforce that the attestation payload binds to run_id and the command_log bytes hash.
    env_art = arts[0]
    storage_ref = env_art.get("storage_ref")
    declared_hash = env_art.get("hash")

    if not isinstance(storage_ref, str) or not storage_ref.strip():
        return [
            CheckResult(
                check_id="R6",
                status="FAIL",
                category="FR-EVIDENCE-ATTESTATION-MISSING",
                message="env_attestation storage_ref missing/empty; cannot verify attestation payload.",
                pointers=[f"{safe_relpath(ctx.repo_root, ctx.evidence_manifest_path)}#/artifacts"],
                remediation_next_instruction="Do produce envelope attestation evidence under the declared envelope then re-run R.",
            )
        ]

    if not isinstance(declared_hash, str) or not declared_hash.strip():
        return [
            CheckResult(
                check_id="R6",
                status="FAIL",
                category="FR-EVIDENCE-ATTESTATION-MISSING",
                message="env_attestation hash missing/empty; cannot verify attestation integrity.",
                pointers=[f"{safe_relpath(ctx.repo_root, ctx.evidence_manifest_path)}#/artifacts"],
                remediation_next_instruction="Do produce envelope attestation evidence under the declared envelope then re-run R.",
            )
        ]

    try:
        schema = ctx.protocol.read_json("schemas/EnvAttestationPayload.schema.json")
    except Exception as e:
        return [
            CheckResult(
                check_id="R6",
                status="FAIL",
                category="FR-SCHEMA-ARTIFACT-INVALID",
                message=f"Missing/invalid schemas/EnvAttestationPayload.schema.json; cannot verify env_attestation payload deterministically: {e}",
                pointers=["schemas/EnvAttestationPayload.schema.json"],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    if not isinstance(schema, dict):
        return [
            CheckResult(
                check_id="R6",
                status="FAIL",
                category="FR-SCHEMA-ARTIFACT-INVALID",
                message="EnvAttestationPayload schema must be a JSON object.",
                pointers=["schemas/EnvAttestationPayload.schema.json"],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    try:
        p = resolve_storage_ref(ctx.repo_root, storage_ref.strip())
        data = p.read_bytes()
    except Exception as e:
        return [
            CheckResult(
                check_id="R6",
                status="FAIL",
                category="FR-EVIDENCE-ATTESTATION-MISSING",
                message=f"Cannot resolve/read env_attestation storage_ref: {e}",
                pointers=[storage_ref.strip()],
                remediation_next_instruction="Do produce envelope attestation evidence under the declared envelope then re-run R.",
            )
        ]

    if sha256_bytes(data) != declared_hash.strip():
        return [
            CheckResult(
                check_id="R6",
                status="FAIL",
                category="FR-EVIDENCE-ATTESTATION-MISSING",
                message="env_attestation sha256(bytes) mismatch (declared != actual).",
                pointers=[storage_ref.strip()],
                remediation_next_instruction="Do produce envelope attestation evidence under the declared envelope then re-run R.",
            )
        ]

    try:
        payload = json.loads(data.decode("utf-8", errors="strict"))
    except Exception as e:
        return [
            CheckResult(
                check_id="R6",
                status="FAIL",
                category="FR-EVIDENCE-ATTESTATION-MISSING",
                message=f"env_attestation payload is not valid UTF-8 JSON: {e}",
                pointers=[storage_ref.strip()],
                remediation_next_instruction="Do produce envelope attestation evidence under the declared envelope then re-run R.",
            )
        ]

    if not isinstance(payload, dict):
        return [
            CheckResult(
                check_id="R6",
                status="FAIL",
                category="FR-EVIDENCE-ATTESTATION-MISSING",
                message="env_attestation payload must be a JSON object.",
                pointers=[storage_ref.strip()],
                remediation_next_instruction="Do produce envelope attestation evidence under the declared envelope then re-run R.",
            )
        ]

    errs = validate_schema(payload, schema, root_schema=schema, path="env_attestation")
    if errs:
        first = errs[0]
        return [
            CheckResult(
                check_id="R6",
                status="FAIL",
                category="FR-EVIDENCE-ATTESTATION-MISSING",
                message=f"env_attestation payload schema invalid at {first.path}: {first.message}",
                pointers=[storage_ref.strip()],
                remediation_next_instruction="Do produce envelope attestation evidence under the declared envelope then re-run R.",
            )
        ]

    # Bind to run.
    if payload.get("run_id") != ctx.locked_spec.get("run_id"):
        return [
            CheckResult(
                check_id="R6",
                status="FAIL",
                category="FR-EVIDENCE-ATTESTATION-MISSING",
                message="env_attestation.run_id must equal LockedSpec.run_id.",
                pointers=[storage_ref.strip(), safe_relpath(ctx.repo_root, ctx.locked_spec_path) + "#/run_id"],
                remediation_next_instruction="Do produce envelope attestation evidence under the declared envelope then re-run R.",
            )
        ]

    # Bind to envelope_attestation id.
    if payload.get("attestation_id") != attestation_id:
        return [
            CheckResult(
                check_id="R6",
                status="FAIL",
                category="FR-EVIDENCE-ATTESTATION-MISSING",
                message="env_attestation.attestation_id must equal EvidenceManifest.envelope_attestation.id.",
                pointers=[storage_ref.strip(), em_ptr],
                remediation_next_instruction="Do produce envelope attestation evidence under the declared envelope then re-run R.",
            )
        ]

    # Bind to command_log bytes hash.
    cmd_art = _single_artifact_of_kind(ctx, "command_log")
    if cmd_art is None:
        return [
            CheckResult(
                check_id="R6",
                status="FAIL",
                category="FR-EVIDENCE-ATTESTATION-MISSING",
                message="Cannot bind env_attestation to command_log: expected exactly one command_log artifact.",
                pointers=[f"{safe_relpath(ctx.repo_root, ctx.evidence_manifest_path)}#/artifacts"],
                remediation_next_instruction="Do produce envelope attestation evidence under the declared envelope then re-run R.",
            )
        ]

    cmd_hash = cmd_art.get("hash")
    if not isinstance(cmd_hash, str) or not cmd_hash.strip():
        return [
            CheckResult(
                check_id="R6",
                status="FAIL",
                category="FR-EVIDENCE-ATTESTATION-MISSING",
                message="command_log artifact hash missing/empty; cannot bind env_attestation.",
                pointers=[f"{safe_relpath(ctx.repo_root, ctx.evidence_manifest_path)}#/artifacts"],
                remediation_next_instruction="Do produce envelope attestation evidence under the declared envelope then re-run R.",
            )
        ]

    if payload.get("command_log_sha256") != cmd_hash.strip():
        return [
            CheckResult(
                check_id="R6",
                status="FAIL",
                category="FR-EVIDENCE-ATTESTATION-MISSING",
                message="env_attestation.command_log_sha256 must equal the declared hash of the command_log artifact.",
                pointers=[storage_ref.strip(), f"{safe_relpath(ctx.repo_root, ctx.evidence_manifest_path)}#/artifacts"],
                remediation_next_instruction="Do produce envelope attestation evidence under the declared envelope then re-run R.",
            )
        ]

    # Optional (tier-driven) cryptographic signature on the attestation payload.
    sig_required = ctx.tier_params.get("envelope_policy.attestation_signature_required")
    if sig_required not in ("yes", "no"):
        return [
            CheckResult(
                check_id="R6",
                status="FAIL",
                category="FR-EVIDENCE-ATTESTATION-MISSING",
                message="Tier parameter 'envelope_policy.attestation_signature_required' missing/invalid; cannot verify attestation signature deterministically.",
                pointers=[safe_relpath(ctx.repo_root, ctx.locked_spec_path)],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    if sig_required == "yes":
        # Load pinned public key reference from LockedSpec.
        env_ptr = safe_relpath(ctx.repo_root, ctx.locked_spec_path) + "#/environment_envelope/attestation_pubkey_ref"
        ee = ctx.locked_spec.get("environment_envelope")
        pubref = ee.get("attestation_pubkey_ref") if isinstance(ee, dict) else None
        if not isinstance(pubref, dict):
            return [
                CheckResult(
                    check_id="R6",
                    status="FAIL",
                    category="FR-EVIDENCE-ATTESTATION-MISSING",
                    message="Tier requires attestation signature but LockedSpec.environment_envelope.attestation_pubkey_ref is missing/invalid.",
                    pointers=[env_ptr],
                    remediation_next_instruction="Do produce envelope attestation evidence under the declared envelope then re-run R.",
                )
            ]

        pk_storage_ref = pubref.get("storage_ref")
        pk_hash = pubref.get("hash")
        if not isinstance(pk_storage_ref, str) or not pk_storage_ref.strip() or not isinstance(pk_hash, str) or not pk_hash.strip():
            return [
                CheckResult(
                    check_id="R6",
                    status="FAIL",
                    category="FR-EVIDENCE-ATTESTATION-MISSING",
                    message="attestation_pubkey_ref must include non-empty storage_ref and hash.",
                    pointers=[env_ptr],
                    remediation_next_instruction="Do produce envelope attestation evidence under the declared envelope then re-run R.",
                )
            ]

        try:
            pk_path = resolve_storage_ref(ctx.repo_root, pk_storage_ref.strip())
            pk_bytes = pk_path.read_bytes()
        except Exception as e:
            return [
                CheckResult(
                    check_id="R6",
                    status="FAIL",
                    category="FR-EVIDENCE-ATTESTATION-MISSING",
                    message=f"Cannot resolve/read attestation_pubkey_ref.storage_ref: {e}",
                    pointers=[pk_storage_ref.strip(), env_ptr],
                    remediation_next_instruction="Do produce envelope attestation evidence under the declared envelope then re-run R.",
                )
            ]

        if sha256_bytes(pk_bytes) != pk_hash.strip():
            return [
                CheckResult(
                    check_id="R6",
                    status="FAIL",
                    category="FR-EVIDENCE-ATTESTATION-MISSING",
                    message="attestation_pubkey_ref sha256(bytes) mismatch (declared != actual).",
                    pointers=[pk_storage_ref.strip(), env_ptr],
                    remediation_next_instruction="Do produce envelope attestation evidence under the declared envelope then re-run R.",
                )
            ]

        sig_alg = payload.get("signature_alg")
        sig_b64 = payload.get("signature")
        if sig_alg != "ed25519" or not isinstance(sig_b64, str) or not sig_b64.strip():
            return [
                CheckResult(
                    check_id="R6",
                    status="FAIL",
                    category="FR-EVIDENCE-ATTESTATION-MISSING",
                    message="Tier requires attestation signature but env_attestation.signature_alg/signature is missing/invalid.",
                    pointers=[storage_ref.strip()],
                    remediation_next_instruction="Do produce envelope attestation evidence under the declared envelope then re-run R.",
                )
            ]

        try:
            sig_bytes = base64.b64decode(sig_b64.strip(), validate=True)
        except Exception:
            return [
                CheckResult(
                    check_id="R6",
                    status="FAIL",
                    category="FR-EVIDENCE-ATTESTATION-MISSING",
                    message="env_attestation.signature is not valid base64.",
                    pointers=[storage_ref.strip()],
                    remediation_next_instruction="Do produce envelope attestation evidence under the declared envelope then re-run R.",
                )
            ]

        # Deterministic signing message: canonical JSON of payload with signature fields removed.
        unsigned_payload = dict(payload)
        unsigned_payload.pop("signature", None)
        unsigned_payload.pop("signature_alg", None)
        msg = _canonical_json(unsigned_payload).encode("utf-8")

        try:
            pub = _load_ed25519_public_key(pk_bytes)
            pub.verify(sig_bytes, msg)
        except Exception as e:
            return [
                CheckResult(
                    check_id="R6",
                    status="FAIL",
                    category="FR-EVIDENCE-ATTESTATION-MISSING",
                    message="env_attestation signature verification failed.",
                    pointers=[storage_ref.strip(), pk_storage_ref.strip()],
                    remediation_next_instruction="Do produce envelope attestation evidence under the declared envelope then re-run R.",
                )
            ]

    return [
        CheckResult(
            check_id="R6",
            status="PASS",
            category=None,
            message="R6 satisfied: attestation required, belgi verify-attestation recorded, envelope_attestation reference present, and env_attestation payload validated and bound.",
            pointers=[em_ptr],
        )
    ]
