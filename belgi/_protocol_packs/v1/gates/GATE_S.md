# Gate S — Verify SealManifest (Stage S)

Stage S produces a `SealManifest.json` that binds the core run artifacts and their hashes into a single deterministic manifest.

Stage S has two entrypoints with different roles:
- Producer: `chain/seal_bundle.py` (creates `SealManifest.json` and may embed a cryptographic signature)
- Verifier (Gate S): `chain/gate_s_verify.py` (verifies schema, ObjectRef hash binding, seal_hash, and signature)

Important: the producer can return NO-GO without producing a `SealManifest.json` (for example, when given an invalid or non-verifying `--seal-signature-file`). Gate S verification applies when a `SealManifest.json` exists and must be audited/verified.

This document defines the MUST-level requirements for the Seal tool (producer) and the MUST-level verification obligations for replay/audit.

Grounding (normative):
 Evidence bundle + seal algorithms: [docs/operations/evidence-bundles.md](https://github.com/belgi-protocol/belgi/blob/main/docs/operations/evidence-bundles.md)

## 1. Inputs (Required)
 requirement: The seal producer tool MUST compute `SealManifest.seal_hash` exactly as defined in [docs/operations/evidence-bundles.md](https://github.com/belgi-protocol/belgi/blob/main/docs/operations/evidence-bundles.md) ("Seal hash computation").
- `LockedSpec.json`
- `GateVerdict.Q.json` (gate_id = `Q`)
 requirement: For tier `tier-2` and `tier-3`, the seal producer tool MUST include and verify a detached Ed25519 signature over the normative anchor payload as defined in [docs/operations/evidence-bundles.md](https://github.com/belgi-protocol/belgi/blob/main/docs/operations/evidence-bundles.md) ("Cryptographic Seal (Tier 2–3, Normative)").

Seal (producer) MAY read:
- one or more waiver JSON files (when `LockedSpec.waivers_applied[]` is non-empty)
- replay instructions JSON

## 2. Output (Required)

Seal (producer) MUST produce:
- `SealManifest.json`
  - MUST validate against [../schemas/SealManifest.schema.json](../schemas/SealManifest.schema.json)
  - MUST be serialized deterministically (stable key order, no incidental whitespace; LF newline)

## 3. Deterministic Checks (Executable Contract)

### S-PROTOCOL-IDENTITY-001 — Protocol pack identity binding

Gate S MUST verify that the active protocol context matches the protocol identity pinned into `LockedSpec.protocol_pack`.

- requirement: `LockedSpec.protocol_pack.pack_id`, `manifest_sha256`, and `pack_name` MUST match the active protocol pack used by verification.
- note: `LockedSpec.protocol_pack.source` is metadata and MUST NOT be used as an identity check (the same pack content may be loaded from different sources).
- failure condition: Any missing/invalid `LockedSpec.protocol_pack` fields, or any identity mismatch, is **NO-GO**.

### S-SCHEMA-001 — Schema validity + minimal binding contract

- requirement: The verifier MUST validate `LockedSpec`, `SealManifest`, and `EvidenceManifest` against their schemas.
- binding requirements (non-exhaustive):
  - `SealManifest.run_id` MUST equal `LockedSpec.run_id`.
  - The `EvidenceManifest` referenced by `SealManifest.evidence_manifest_ref.storage_ref` MUST be the same artifact passed to the verifier.
  - `SealManifest.gate_q_verdict_ref` / `gate_r_verdict_ref` MUST resolve to schema-valid `GateVerdict` objects with matching `gate_id` and `run_id`.
- failure condition: Any schema or binding mismatch is **NO-GO**.

### S-SEALHASH-001 — seal_hash matches the normative algorithm
- requirement: The tool MUST compute `SealManifest.seal_hash` exactly as defined in [docs/operations/evidence-bundles.md](https://github.com/belgi-protocol/belgi/blob/main/docs/operations/evidence-bundles.md) ("Seal hash computation").
- failure condition: If the computed hash does not match `SealManifest.seal_hash` (case-insensitive hex), the run is **NO-GO**.

### S-SIGNATURE-001 — Tier 2–3 cryptographic seal verification
- requirement: For tier `tier-2` and `tier-3`, Gate S MUST include and verify a detached Ed25519 signature over the normative anchor payload as defined in [docs/operations/evidence-bundles.md](https://github.com/belgi-protocol/belgi/blob/main/docs/operations/evidence-bundles.md) ("Cryptographic Seal (Tier 2–3, Normative)").
- key pinning rule:
  - The verifier MUST use the pinned public key reference in `LockedSpec.environment_envelope.seal_pubkey_ref`.
  - The verifier MUST resolve `seal_pubkey_ref.storage_ref` to bytes, hash them with SHA-256, and require equality with `seal_pubkey_ref.hash`.
- signature rule:
  - `SealManifest.signature_alg` MUST equal `"ed25519"`.
  - `SealManifest.signature` MUST be present and base64-decodable to exactly 64 bytes.
  - The Ed25519 signature MUST verify over the normative `anchor_payload_bytes`.
- failure condition: Any missing/invalid signature fields, missing/invalid pinned key reference, or signature verification failure is **NO-GO**.

Tier `tier-0` and `tier-1`:
- `SealManifest.signature_alg`/`signature` MAY be absent.
- If present, they MUST verify as above (fail-closed).

### S-OBJECTREF-001 — ObjectRef hash binding is valid
- requirement: For every `ObjectRef` in the `SealManifest` (and the pinned key reference used for signature verification), the verifier MUST resolve `storage_ref` to bytes within the bundle root and verify the SHA-256 digest equals the declared `hash`.
- requirement: If `SealManifest.replay_instructions_ref` is present, the verifier MUST parse the referenced JSON, validate it against `ReplayInstructionsPayload.schema.json`, and verify the nested `source_archive_ref` hash binding.
- failure condition: Any resolution/read/hash mismatch is **NO-GO**.

### Mapping to executable check IDs

Gate S is implemented by `chain/gate_s_verify.py` and emits deterministic check IDs. This mapping is normative for interpreting `GateVerdict.S.failures[*].rule_id`.

| Spec label | Verifier check_id |
|---|---|
| S-PROTOCOL-IDENTITY-001 | `PROTOCOL-IDENTITY-001` |
| S-SCHEMA-001 | `S1` |
| S-OBJECTREF-001 | `S2` |
| S-SEALHASH-001 | `S3` |
| S-SIGNATURE-001 | `S4` |

## 4. GO / NO-GO

Gate S is **GO** iff:
- the `SealManifest` validates against schema, AND
- `seal_hash` verifies, AND
- all referenced `ObjectRef` hashes verify, AND
- for Tier 2–3, the cryptographic signature verifies.

Otherwise Gate S is **NO-GO**.
