from __future__ import annotations

import base64
import json
from typing import Any

from belgi.core.hash import sha256_bytes
from belgi.core.jail import safe_relpath
from belgi.core.schema import validate_schema
from belgi.core.jail import resolve_storage_ref
from chain.logic.base import CheckResult, find_artifacts_by_kind_id

from .context import RCheckContext


def _load_schema(ctx: RCheckContext, rel: str) -> dict[str, Any]:
    obj = ctx.protocol.read_json(rel)
    if not isinstance(obj, dict):
        raise ValueError(f"Schema is not a JSON object: {rel}")
    return obj


def _require_exactly_one(ctx: RCheckContext, kind: str, artifact_id: str) -> tuple[dict[str, Any] | None, str]:
    arts = find_artifacts_by_kind_id(ctx.evidence_manifest.get("artifacts"), kind=kind, artifact_id=artifact_id)
    if len(arts) != 1:
        return None, f"required ({kind},{artifact_id}) does not match exactly one artifact (count={len(arts)})"
    return arts[0], ""


def _read_and_validate_objectref_json(ctx: RCheckContext, artifact: dict[str, Any], *, payload_schema: dict[str, Any], where: str) -> tuple[dict[str, Any] | None, str]:
    storage_ref = artifact.get("storage_ref")
    declared_hash = artifact.get("hash")

    if not isinstance(storage_ref, str) or not storage_ref:
        return None, f"{where}: storage_ref missing/empty"
    if not isinstance(declared_hash, str) or not declared_hash:
        return None, f"{where}: hash missing/empty"

    try:
        p = resolve_storage_ref(ctx.repo_root, storage_ref)
        data = p.read_bytes()
    except Exception as e:
        return None, f"{where}: cannot resolve/read storage_ref: {e}"

    actual_hash = sha256_bytes(data)
    if actual_hash != declared_hash:
        return None, f"{where}: sha256(bytes) mismatch (declared != actual)"

    try:
        obj = json.loads(data.decode("utf-8", errors="strict"))
    except Exception as e:
        return None, f"{where}: payload is not valid UTF-8 JSON: {e}"

    if not isinstance(obj, dict):
        return None, f"{where}: payload must be a JSON object"

    schema_errs = validate_schema(obj, payload_schema, root_schema=payload_schema, path=where)
    if schema_errs:
        first = schema_errs[0]
        return None, f"{where}: payload schema invalid at {first.path}: {first.message}"

    return obj, ""


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

    # Allow either PEM SubjectPublicKeyInfo OR raw 32-byte public key stored as ASCII hex.
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


def _enforce_genesis_seal(ctx: RCheckContext, *, em_ptr: str) -> tuple[bool, list[CheckResult]]:
    """Tier-3 only: require and verify genesis_seal artifact.

    Deterministic contract:
    - Exactly one artifact of kind==genesis_seal.
    - Payload validates against GenesisSealPayload schema.
    - Payload fields match the pinned canonical strings.
    - Signature verifies under a pinned Ed25519 public key.
    """

    if ctx.locked_spec.get("tier", {}).get("tier_id") != "tier-3":
        return True, []

    # Tier-3 already requires the kind via R0 evidence sufficiency; R4 enforces uniqueness + integrity + signature.
    artifacts = ctx.evidence_manifest.get("artifacts")
    if not isinstance(artifacts, list):
        return False, [
            CheckResult(
                check_id="R4",
                status="FAIL",
                category="FR-SCHEMA-ARTIFACT-INVALID",
                message="EvidenceManifest.artifacts must be a list for genesis_seal enforcement.",
                pointers=[em_ptr + "#/artifacts"],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    genesis_arts = [a for a in artifacts if isinstance(a, dict) and a.get("kind") == "genesis_seal"]
    if len(genesis_arts) != 1:
        return False, [
            CheckResult(
                check_id="R4",
                status="FAIL",
                category="FR-SCHEMA-ARTIFACT-INVALID",
                message=f"genesis_seal must be uniquely indexed (count={len(genesis_arts)}).",
                pointers=[em_ptr + "#/artifacts"],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    try:
        genesis_schema = _load_schema(ctx, "schemas/GenesisSealPayload.schema.json")
    except Exception as e:
        return False, [
            CheckResult(
                check_id="R4",
                status="FAIL",
                category="FR-SCHEMA-ARTIFACT-INVALID",
                message=f"Missing/invalid schemas/GenesisSealPayload.schema.json; cannot verify genesis_seal deterministically: {e}",
                pointers=["schemas/GenesisSealPayload.schema.json"],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    payload, perr = _read_and_validate_objectref_json(ctx, genesis_arts[0], payload_schema=genesis_schema, where="genesis_seal")
    if payload is None:
        return False, [
            CheckResult(
                check_id="R4",
                status="FAIL",
                category="FR-SCHEMA-ARTIFACT-INVALID",
                message=f"genesis_seal invalid: {perr}",
                pointers=[str(genesis_arts[0].get("storage_ref") or "")],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    expected_philosophy = "Hayatta en hakiki mürşit ilimdir. (M.K. Atatürk)"
    expected_dedication = "Bilge (8)"
    expected_architect = "Batuhan Turgay"
    if payload.get("philosophy") != expected_philosophy or payload.get("dedication") != expected_dedication or payload.get("architect") != expected_architect:
        return False, [
            CheckResult(
                check_id="R4",
                status="FAIL",
                category="FR-SCHEMA-ARTIFACT-INVALID",
                message="genesis_seal payload fields must match the pinned canonical genesis strings.",
                pointers=[str(genesis_arts[0].get("storage_ref") or "")],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    sig_b64 = payload.get("signature")
    if not isinstance(sig_b64, str) or not sig_b64.strip():
        return False, [
            CheckResult(
                check_id="R4",
                status="FAIL",
                category="FR-SCHEMA-ARTIFACT-INVALID",
                message="genesis_seal signature missing/empty.",
                pointers=[str(genesis_arts[0].get("storage_ref") or "")],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    try:
        sig = base64.b64decode(sig_b64, validate=True)
    except Exception:
        return False, [
            CheckResult(
                check_id="R4",
                status="FAIL",
                category="FR-SCHEMA-ARTIFACT-INVALID",
                message="genesis_seal signature is not valid base64.",
                pointers=[str(genesis_arts[0].get("storage_ref") or "")],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    # Signature is over canonical JSON of the payload with signature fields removed.
    to_verify = dict(payload)
    to_verify.pop("signature", None)
    to_verify.pop("signature_alg", None)
    msg = _canonical_json(to_verify).encode("utf-8")

    # Pinned genesis public key (raw 32-byte Ed25519 public key encoded as hex).
    pinned_pubkey_hex = "6fcedddd158088888bdedb899b51011f3bb82b07e93d07913af8acfcc0ac30ca"
    try:
        pubkey = _load_ed25519_public_key(pinned_pubkey_hex.encode("ascii"))
        pubkey.verify(sig, msg)
    except Exception:
        return False, [
            CheckResult(
                check_id="R4",
                status="FAIL",
                category="FR-SCHEMA-ARTIFACT-INVALID",
                message="genesis_seal signature verification failed under pinned genesis public key.",
                pointers=[str(genesis_arts[0].get("storage_ref") or "")],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    return True, []


def run(ctx: RCheckContext) -> list[CheckResult]:
    """R4 — Schema / contract checks (Gate R)."""

    repo_root = ctx.repo_root
    locked_ptr = safe_relpath(repo_root, ctx.locked_spec_path)
    em_ptr = safe_relpath(repo_root, ctx.evidence_manifest_path)

    try:
        locked_schema = _load_schema(ctx, "schemas/LockedSpec.schema.json")
        evidence_schema = _load_schema(ctx, "schemas/EvidenceManifest.schema.json")
        gate_verdict_schema = _load_schema(ctx, "schemas/GateVerdict.schema.json")
        waiver_schema = _load_schema(ctx, "schemas/Waiver.schema.json")
        docs_compilation_schema = _load_schema(ctx, "schemas/DocsCompilationLogPayload.schema.json")
    except Exception as e:
        return [
            CheckResult(
                check_id="R4",
                status="FAIL",
                category="FR-SCHEMA-ARTIFACT-INVALID",
                message=f"Missing required schema file(s) for deterministic validation: {e}",
                pointers=[
                    "schemas/LockedSpec.schema.json",
                    "schemas/EvidenceManifest.schema.json",
                    "schemas/GateVerdict.schema.json",
                    "schemas/Waiver.schema.json",
                    "schemas/DocsCompilationLogPayload.schema.json",
                ],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    # 1) Validate LockedSpec and EvidenceManifest against their schemas.
    lerrs = validate_schema(ctx.locked_spec, locked_schema, root_schema=locked_schema, path="LockedSpec")
    if lerrs:
        first = lerrs[0]
        return [
            CheckResult(
                check_id="R4",
                status="FAIL",
                category="FR-SCHEMA-ARTIFACT-INVALID",
                message=f"LockedSpec schema invalid at {first.path}: {first.message}",
                pointers=[locked_ptr],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    eerrs = validate_schema(ctx.evidence_manifest, evidence_schema, root_schema=evidence_schema, path="EvidenceManifest")
    if eerrs:
        first = eerrs[0]
        return [
            CheckResult(
                check_id="R4",
                status="FAIL",
                category="FR-SCHEMA-ARTIFACT-INVALID",
                message=f"EvidenceManifest schema invalid at {first.path}: {first.message}",
                pointers=[em_ptr],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    # 2) Verify run_id binding (replay integrity).
    run_id_locked = ctx.locked_spec.get("run_id")
    run_id_em = ctx.evidence_manifest.get("run_id")
    if run_id_locked != run_id_em:
        return [
            CheckResult(
                check_id="R4",
                status="FAIL",
                category="FR-SCHEMA-ARTIFACT-INVALID",
                message="EvidenceManifest.run_id must equal LockedSpec.run_id.",
                pointers=[locked_ptr + "#/run_id", em_ptr + "#/run_id"],
                remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
            )
        ]

    # Publication profile selection enforcement.
    # Fail-closed: if a run declares publishing, it MUST select the public profile.
    pub_intent = ctx.locked_spec.get("publication_intent")
    if isinstance(pub_intent, dict):
        locked_profile = pub_intent.get("profile")
        locked_publish = pub_intent.get("publish")
        if locked_publish is True and locked_profile != "public":
            return [
                CheckResult(
                    check_id="R4",
                    status="FAIL",
                    category="FR-SCHEMA-ARTIFACT-INVALID",
                    message="LockedSpec.publication_intent.profile must be 'public' when publication_intent.publish is true.",
                    pointers=[locked_ptr + "#/publication_intent"],
                    remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
                )
            ]

    # 3) Per-kind producer constraints (role confusion prevention).
    # "LLMs propose; gates dispose" — C2 (proposer) MUST NOT produce trust-critical evidence.
    # Deterministic rule: certain evidence kinds have restricted producer sets.
    PRODUCER_CONSTRAINTS: dict[str, set[str]] = {
        # Trust-critical evidence MUST NOT come from C2 (the LLM proposer)
        "schema_validation": {"C1", "R"},
        "policy_report": {"C1", "R"},
        "test_report": {"C1", "R"},
        "env_attestation": {"C1"},  # attestation MUST be from trusted runner, never proposer
        "command_log": {"C1"},
        # diff can come from C2 (the patch itself is the proposal)
        "diff": {"C1", "C2"},
        # docs_compilation_log is post-R, produced by C3
        "docs_compilation_log": {"C3"},
        # genesis_seal is a trust-critical root-of-trust artifact; must not be produced by C2.
        "genesis_seal": {"C1", "R"},
    }

    artifacts = ctx.evidence_manifest.get("artifacts")
    if isinstance(artifacts, list):
        for idx, art in enumerate(artifacts):
            if not isinstance(art, dict):
                continue
            kind = art.get("kind")
            produced_by = art.get("produced_by")
            if not isinstance(kind, str) or not isinstance(produced_by, str):
                continue
            allowed_producers = PRODUCER_CONSTRAINTS.get(kind)
            if allowed_producers is not None and produced_by not in allowed_producers:
                return [
                    CheckResult(
                        check_id="R4",
                        status="FAIL",
                        category="FR-SCHEMA-ARTIFACT-INVALID",
                        message=f"Artifact kind '{kind}' has invalid produced_by='{produced_by}'; allowed: {sorted(allowed_producers)}.",
                        pointers=[f"{em_ptr}#/artifacts/{idx}/produced_by"],
                        remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
                    )
                ]

    # 4) Each artifact ObjectRef + enums are schema-enforced by EvidenceManifest validation above.

    ok, genesis_results = _enforce_genesis_seal(ctx, em_ptr=em_ptr)
    if not ok:
        return genesis_results

    # 5) Required report artifact integrity + payload validation.
    # R4 validates structure/integrity only (uniqueness + bytes hash + schema).
    # Semantic pass/fail is enforced by dedicated checks (R1/R7/R8/R5) to preserve
    # deterministic failure categorization.
    for report_id in ctx.required_policy_report_ids:

        art, err = _require_exactly_one(ctx, "policy_report", report_id)  # uniqueness enforcement
        if art is None:
            return [
                CheckResult(
                    check_id="R4",
                    status="FAIL",
                    category="FR-EVIDENCE-MISSING",
                    message=err,
                    pointers=[em_ptr + "#/artifacts"],
                    remediation_next_instruction="Do produce required evidence kind policy_report under the declared envelope then re-run R.",
                )
            ]

        payload, perr = _read_and_validate_objectref_json(ctx, art, payload_schema=ctx.policy_payload_schema, where=f"policy_report[{report_id}]")
        if payload is None:
            return [
                CheckResult(
                    check_id="R4",
                    status="FAIL",
                    category="FR-SCHEMA-ARTIFACT-INVALID",
                    message=perr,
                    pointers=[str(art.get("storage_ref") or "")],
                    remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
                )
            ]

    # Required test_report when tier requires tests.
    # NOTE: R4 validates STRUCTURE ONLY (existence, integrity, schema).
    # Semantic sufficiency (pass/fail) is deferred to R5 to ensure deterministic
    # failure categorization under FR-TESTS-POLICY-FAILED.
    if ctx.tier_params.get("test_policy.required") == "yes":
        art, err = _require_exactly_one(ctx, "test_report", ctx.required_test_report_id)  # uniqueness
        if art is None:
            return [
                CheckResult(
                    check_id="R4",
                    status="FAIL",
                    category="FR-SCHEMA-ARTIFACT-INVALID",
                    message=err,
                    pointers=[em_ptr + "#/artifacts"],
                    remediation_next_instruction="Do produce required evidence kind test_report under the declared envelope then re-run R.",
                )
            ]

        payload, terr = _read_and_validate_objectref_json(ctx, art, payload_schema=ctx.test_payload_schema, where=f"test_report[{ctx.required_test_report_id}]")
        if payload is None:
            return [
                CheckResult(
                    check_id="R4",
                    status="FAIL",
                    category="FR-SCHEMA-ARTIFACT-INVALID",
                    message=terr,
                    pointers=[str(art.get("storage_ref") or "")],
                    remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
                )
            ]

        # Validate summary.failed exists and is an integer (schema structure check).
        # The actual pass/fail semantics are enforced by R5.
        summary = payload.get("summary")
        failed = (summary or {}).get("failed") if isinstance(summary, dict) else None

        if not isinstance(failed, int) or isinstance(failed, bool):
            return [
                CheckResult(
                    check_id="R4",
                    status="FAIL",
                    category="FR-SCHEMA-ARTIFACT-INVALID",
                    message="Required test_report payload summary.failed missing/invalid.",
                    pointers=[str(art.get("storage_ref") or "")],
                    remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
                )
            ]

        # NOTE: We intentionally do NOT check `failed != 0` here.
        # Test pass/fail semantics are R5's responsibility (FR-TESTS-POLICY-FAILED).

    # command_log artifact integrity verification (paper-grade).
    # Full crypto binding is deferred to audit-grade (env_attestation signature).
    # For paper-grade, we verify the command_log artifact exists and has valid bytes→hash.
    command_log_arts = [a for a in (ctx.evidence_manifest.get("artifacts") or [])
                        if isinstance(a, dict) and a.get("kind") == "command_log"]
    if not command_log_arts:
        return [
            CheckResult(
                check_id="R4",
                status="FAIL",
                category="FR-EVIDENCE-MISSING",
                message="Required command_log artifact missing.",
                pointers=[em_ptr + "#/artifacts"],
                remediation_next_instruction="Do produce required evidence kind command_log under the declared envelope then re-run R.",
            )
        ]

    for cl_art in command_log_arts:
        cl_storage = cl_art.get("storage_ref")
        cl_hash = cl_art.get("hash")
        if not isinstance(cl_storage, str) or not cl_storage:
            return [
                CheckResult(
                    check_id="R4",
                    status="FAIL",
                    category="FR-SCHEMA-ARTIFACT-INVALID",
                    message="command_log artifact storage_ref missing/empty.",
                    pointers=[em_ptr + "#/artifacts"],
                    remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
                )
            ]
        if not isinstance(cl_hash, str) or not cl_hash:
            return [
                CheckResult(
                    check_id="R4",
                    status="FAIL",
                    category="FR-SCHEMA-ARTIFACT-INVALID",
                    message="command_log artifact hash missing/empty.",
                    pointers=[em_ptr + "#/artifacts"],
                    remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
                )
            ]
        try:
            cl_path = resolve_storage_ref(repo_root, cl_storage)
            cl_bytes = cl_path.read_bytes()
            actual_hash = sha256_bytes(cl_bytes)
        except Exception as e:
            return [
                CheckResult(
                    check_id="R4",
                    status="FAIL",
                    category="FR-SCHEMA-ARTIFACT-INVALID",
                    message=f"command_log artifact cannot be resolved/read: {e}.",
                    pointers=[cl_storage],
                    remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
                )
            ]
        if actual_hash != cl_hash:
            return [
                CheckResult(
                    check_id="R4",
                    status="FAIL",
                    category="FR-SCHEMA-ARTIFACT-INVALID",
                    message="command_log artifact sha256(bytes) mismatch.",
                    pointers=[cl_storage],
                    remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
                )
            ]

    # Optional docs_compilation_log validation (post-R evidence).
    # Gate R MUST NOT require docs_compilation_log (it is produced by C3 post-R),
    # but when present it MUST be schema-valid, integrity-bound, and (for public publishing)
    # MUST not represent internal/secret prompt content as bytes.
    docs_arts = [
        a for a in (ctx.evidence_manifest.get("artifacts") or [])
        if isinstance(a, dict) and a.get("kind") == "docs_compilation_log"
    ]
    if docs_arts:
        if len(docs_arts) != 1:
            return [
                CheckResult(
                    check_id="R4",
                    status="FAIL",
                    category="FR-SCHEMA-ARTIFACT-INVALID",
                    message=f"docs_compilation_log must be uniquely indexed (count={len(docs_arts)}).",
                    pointers=[em_ptr + "#/artifacts"],
                    remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
                )
            ]

        d_art = docs_arts[0]
        d_storage = str(d_art.get("storage_ref") or "")
        payload, derr = _read_and_validate_objectref_json(
            ctx,
            d_art,
            payload_schema=docs_compilation_schema,
            where="docs_compilation_log",
        )
        if payload is None:
            return [
                CheckResult(
                    check_id="R4",
                    status="FAIL",
                    category="FR-SCHEMA-ARTIFACT-INVALID",
                    message=derr,
                    pointers=[d_storage],
                    remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
                )
            ]

        if payload.get("run_id") != run_id_locked:
            return [
                CheckResult(
                    check_id="R4",
                    status="FAIL",
                    category="FR-SCHEMA-ARTIFACT-INVALID",
                    message="docs_compilation_log.run_id must bind to LockedSpec.run_id.",
                    pointers=[locked_ptr + "#/run_id", d_storage],
                    remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
                )
            ]

        pub_intent = ctx.locked_spec.get("publication_intent")
        if isinstance(pub_intent, dict):
            locked_profile = pub_intent.get("profile")
            locked_publish = pub_intent.get("publish")

            if isinstance(locked_profile, str) and payload.get("profile") != locked_profile:
                return [
                    CheckResult(
                        check_id="R4",
                        status="FAIL",
                        category="FR-SCHEMA-ARTIFACT-INVALID",
                        message="docs_compilation_log.profile must match LockedSpec.publication_intent.profile.",
                        pointers=[locked_ptr + "#/publication_intent/profile", d_storage],
                        remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
                    )
                ]

            if locked_publish is True and locked_profile == "public":
                blocks = payload.get("prompt_blocks")
                if isinstance(blocks, list):
                    for b in blocks:
                        if not isinstance(b, dict):
                            continue
                        sens = b.get("sensitivity")
                        form = b.get("published_form")
                        if sens in ("internal", "secret") and form != "hash_only":
                            return [
                                CheckResult(
                                    check_id="R4",
                                    status="FAIL",
                                    category="FR-SCHEMA-ARTIFACT-INVALID",
                                    message="Public-safe redaction violated: internal/secret prompt blocks must be published as hashes only.",
                                    pointers=[d_storage],
                                    remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
                                )
                            ]

    # Optional binding check: when GateVerdict is provided, validate schema + evidence_manifest_ref binding.
    if ctx.gate_verdict is not None:
        gerrs = validate_schema(ctx.gate_verdict, gate_verdict_schema, root_schema=gate_verdict_schema, path="GateVerdict")
        if gerrs:
            first = gerrs[0]
            return [
                CheckResult(
                    check_id="R4",
                    status="FAIL",
                    category="FR-SCHEMA-ARTIFACT-INVALID",
                    message=f"GateVerdict input schema invalid at {first.path}: {first.message}",
                    pointers=[safe_relpath(repo_root, ctx.gate_verdict_path) if ctx.gate_verdict_path else "GateVerdict"],
                    remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
                )
            ]

        gv_run_id = ctx.gate_verdict.get("run_id")
        if gv_run_id != run_id_locked:
            return [
                CheckResult(
                    check_id="R4",
                    status="FAIL",
                    category="FR-SCHEMA-ARTIFACT-INVALID",
                    message="GateVerdict.run_id must equal LockedSpec.run_id.",
                    pointers=[locked_ptr + "#/run_id"],
                    remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
                )
            ]

        em_ref = ctx.gate_verdict.get("evidence_manifest_ref")
        if not isinstance(em_ref, dict):
            return [
                CheckResult(
                    check_id="R4",
                    status="FAIL",
                    category="FR-SCHEMA-ARTIFACT-INVALID",
                    message="GateVerdict.evidence_manifest_ref missing/invalid.",
                    pointers=[],
                    remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
                )
            ]

        ref_hash = em_ref.get("hash")
        ref_storage = em_ref.get("storage_ref")
        if not isinstance(ref_hash, str) or not isinstance(ref_storage, str):
            return [
                CheckResult(
                    check_id="R4",
                    status="FAIL",
                    category="FR-SCHEMA-ARTIFACT-INVALID",
                    message="GateVerdict.evidence_manifest_ref fields missing/invalid.",
                    pointers=[],
                    remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
                )
            ]

        try:
            p = resolve_storage_ref(repo_root, ref_storage)
            data = p.read_bytes()
            actual = sha256_bytes(data)
        except Exception as e:
            return [
                CheckResult(
                    check_id="R4",
                    status="FAIL",
                    category="FR-SCHEMA-ARTIFACT-INVALID",
                    message=f"GateVerdict.evidence_manifest_ref.storage_ref cannot be resolved/read: {e}",
                    pointers=[ref_storage],
                    remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
                )
            ]

        if actual != ref_hash:
            return [
                CheckResult(
                    check_id="R4",
                    status="FAIL",
                    category="FR-SCHEMA-ARTIFACT-INVALID",
                    message="GateVerdict.evidence_manifest_ref.hash does not match EvidenceManifest bytes.",
                    pointers=[ref_storage],
                    remediation_next_instruction="Do fix schema validation errors in required artifact then re-run R.",
                )
            ]

    return [
        CheckResult(
            check_id="R4",
            status="PASS",
            category=None,
            message="R4 satisfied: schemas valid, run_id bound, producer constraints enforced, required reports unique + integrity/payload validated, command_log integrity verified, optional GateVerdict binding satisfied.",
            pointers=[locked_ptr, em_ptr],
        )
    ]
