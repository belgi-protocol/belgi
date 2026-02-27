# Evidence Bundles (Replay)

DEFAULT: **NO-GO** unless a third party can replay verification from the bundle alone within the declared Environment Envelope.

This document is grounded in:
- Canonical evidence definitions: `../../CANONICALS.md#evidence-bundle` and `../../CANONICALS.md#evidence-sufficiency`
- Trust boundaries and envelope assumptions: `../../trust-model.md` and `../../CANONICALS.md#environment-envelope`
- Gate R evidence sufficiency rule: `../../gates/GATE_R.md`
- Evidence schema: `../../schemas/EvidenceManifest.schema.json`
- Seal schema: `../../schemas/SealManifest.schema.json`

## Replay Levels

BELGI supports two operational replay levels. Both are performed within the declared Environment Envelope and use the same schema artifacts, but they differ in what claims they support.

### Execution-Only Replay (non-audit)
Execution-Only Replay demonstrates that a third party can:
- validate schemas and hash references for bundle artifacts, and
- reconstruct the declared Environment Envelope well enough to re-run verification (Gate R) deterministically.

Execution-Only Replay does **not** constitute a valid audit of bundle integrity end-to-end unless the seal is verified cryptographically.

### Audit-Grade Replay (valid audit)
Audit-Grade Replay is the level required for audit validity. It requires:
- the full hash-chain verification of referenced artifacts, and
- deterministic re-run of Gate R within the declared Environment Envelope, and
- **cryptographic seal verification** using the normative algorithm in this document.

Without seal verification, the replay is **Execution-Only** and does not constitute a valid audit.

## Seal Verification (Normative)

This section defines public-safe, implementable algorithms for:
- verifying `SealManifest.seal_hash` (content hash binding), and
- verifying the Tier 2–3 **cryptographic seal** (`SealManifest.signature`) when present.

Scope note:
- `seal_hash` provides deterministic, content-hash binding between the SealManifest and the referenced artifact hashes.
- Tier 2–3 audit validity additionally requires a cryptographic seal signature.

### Inputs
- A parsed `SealManifest` object that validates against `../../schemas/SealManifest.schema.json`.

### Canonical JSON serialization
Define `canonical_json(obj)` as:
- UTF-8 encoding.
- JSON object keys serialized in **lexicographic order**.
- **No insignificant whitespace** (no extra spaces, no newlines except those explicitly defined by this algorithm).
- Array element order preserved.
- Numbers and strings serialized per standard JSON (no alternate encodings).

### Seal hash computation
1) Construct `SealManifestUnsigned` as a copy of the SealManifest object with the following top-level fields removed:
  - `seal_hash`
  - `signature_alg` (if present)
  - `signature` (if present)

2) Build `ref_hashes` as a list of SHA-256 hex strings taken from the `hash` field of each ObjectRef included in the SealManifest, in this exact order:
  - `locked_spec_ref.hash`
  - `gate_q_verdict_ref.hash`
  - `gate_r_verdict_ref.hash`
  - `evidence_manifest_ref.hash`
  - each entry of `waivers[i].hash` in array order (if any)
  - `replay_instructions_ref.hash` (only if `replay_instructions_ref` is present)

3) Define `payload_bytes` as UTF-8 bytes of the exact concatenation:

  `canonical_json(SealManifestUnsigned) + "\n" + join(ref_hashes, "\n") + "\n"`

4) Compute:

  `seal_hash = sha256_hex(payload_bytes)`

Where `sha256_hex` outputs the lowercase hexadecimal SHA-256 digest of the bytes.

### Verification rule
Verification passes iff the computed `seal_hash` matches `SealManifest.seal_hash` as a SHA-256 hex value (hex comparison MUST be case-insensitive).

## Cryptographic Seal (Tier 2–3, Normative)

Tier 2–3 audit validity requires a detached Ed25519 signature that binds the SealManifest’s **content-hash anchor fields**.

### Inputs
- A schema-valid `LockedSpec` object (`../../schemas/LockedSpec.schema.json`).
- A schema-valid `SealManifest` object (`../../schemas/SealManifest.schema.json`).

### Key pinning rule
The verifier MUST use the pinned public key reference:
- `LockedSpec.environment_envelope.seal_pubkey_ref` (an ObjectRef to a local bundle file).

The verifier MUST:
1) Resolve `seal_pubkey_ref.storage_ref` to bytes included in the bundle.
2) Compute `sha256(bytes)` and verify it equals `seal_pubkey_ref.hash`.

### Anchor object
1) Construct `SealManifestAnchorUnsigned` as a copy of SealManifest with the following top-level fields removed:
  - `seal_hash`
  - `signature_alg`
  - `signature`
  - `final_commit_sha` (informational; not part of the cryptographic anchor)

2) Define `anchor_payload_bytes` as UTF-8 bytes of the exact concatenation:

  `canonical_json(SealManifestAnchorUnsigned) + "\n"`

Note: ObjectRef hash verification is a separate verifier responsibility; the signature binds only the anchor JSON bytes.

### Signature verification rule
For Tier 2–3:
- `SealManifest.signature_alg` MUST equal `"ed25519"`.
- `SealManifest.signature` MUST be present and base64-decodable.
- The verifier MUST verify the Ed25519 signature over `anchor_payload_bytes` using the pinned public key.

If signature verification fails, replay is **NO-GO**.

## Seal Verifier Tool (Reference Implementation, non-normative)

Seal verification MUST be performed according to the normative algorithm above.

Tier-based requirements for deterministic auditability:
- **Tier 0–1:** strict adherence to the published algorithm is required. Shipping a pinned, executable verifier tool in the declared Environment Envelope is RECOMMENDED (SHOULD) but not mandatory.
- **Tier 2–3:** a pinned, executable verifier tool MUST be included in the declared Environment Envelope (`LockedSpec.environment_envelope.pinned_toolchain_refs[]`) so an independent auditor can execute the same verifier deterministically.

If a verifier tool is used during the original run (e.g., as part of sealing), the run SHOULD record the invocation in `EvidenceManifest.commands_executed` (subject to the tier’s `command_log_mode`). A third-party replay MUST NOT mutate any sealed bundle artifacts to “record” replay commands.

Any command names shown below are **EXAMPLE COMMAND (non-normative)**:
- `seal-verify --seal SealManifest.json`

The verifier tool is an implementation convenience; audit validity still depends on equivalence to the normative algorithm.

## Evidence Mutability, R-Snapshot, and Replay Integrity (Normative)

This section defines the chain of custody between Gate R and Seal (S) in a way that remains compatible with schema-level hash references.

### Definitions
- **R-Snapshot EvidenceManifest**: the schema-valid EvidenceManifest object referenced by `GateVerdict (R).evidence_manifest_ref`.
- **Final EvidenceManifest**: the schema-valid EvidenceManifest object referenced by `SealManifest.evidence_manifest_ref`.

### Mutability rules
- The R-Snapshot EvidenceManifest MUST be treated as immutable after Gate R evaluation, because it is referenced by hash from the Gate R verdict.
- C3 (Docs) appends to the evidence record by producing a Final EvidenceManifest that is an **append-only extension** of the R-Snapshot EvidenceManifest.
  - “Append-only extension” means: all R-Snapshot entries remain present and byte-for-byte identical as referenced (same `storage_ref` bytes, same hashes), and C3-only evidence is added without rewriting prior evidence.

### Replay Integrity Rule
To claim Audit-Grade Replay, a replay MUST confirm that artifacts verified by Gate R are present and unmodified within the final (larger) sealed evidence set:

1) Resolve and verify the R-Snapshot EvidenceManifest from `GateVerdict (R).evidence_manifest_ref`.
2) Resolve and verify the Final EvidenceManifest from `SealManifest.evidence_manifest_ref`.
3) Verify the Final EvidenceManifest is a superset of the R-Snapshot EvidenceManifest:
   - For every entry in `R_snapshot.artifacts[]`, there MUST exist an entry in `final.artifacts[]` with the same `id`, `kind`, `hash`, `media_type`, `storage_ref`, and `produced_by`.
   - `final.envelope_attestation` MUST equal `R_snapshot.envelope_attestation`.
   - `final.commands_executed` MUST preserve the R-Snapshot command log without modification (i.e., the R-Snapshot command list MUST appear as an exact prefix of the Final command list, for both string and structured CommandRecord forms).

If the Replay Integrity Rule fails, the replay is **NO-GO** (post-R evidence has overwritten or invalidated the verified subset).

## 1) Evidence Bundle definition

An Evidence Bundle is the minimal set of artifacts required to justify a GO decision and to enable deterministic replay *within the declared Environment Envelope*.

### 1.1 Mandatory artifacts (minimum replay set)
The bundle MUST include the following schema-valid JSON documents:

1) `LockedSpec.json`
- Schema: `LockedSpec.schema.json`
- Purpose: locks intent, tier, envelope, constraints, and waiver identifiers.

2) Gate Q verdict: `GateVerdict.Q.json`
- Schema: `GateVerdict.schema.json`
- Must have `gate_id: "Q"`

3) Gate R verdict: `GateVerdict.R.json`
- Schema: `GateVerdict.schema.json`
- Must have `gate_id: "R"`

4) EvidenceManifests (one or more)
- Schema: `EvidenceManifest.schema.json`
- Purpose: index of evidence artifacts and execution records.
- The bundle MUST include at least:
  - the EvidenceManifest referenced by `GateVerdict.Q.evidence_manifest_ref` (Q-snapshot), and
  - the EvidenceManifest referenced by `GateVerdict.R.evidence_manifest_ref` (R-snapshot), and
  - the EvidenceManifest referenced by `SealManifest.evidence_manifest_ref` (final, sealed manifest).
- These MAY be the same physical file only if no later phase adds evidence (see “Evidence Mutability, R-Snapshot, and Replay Integrity (Normative)”).

5) `SealManifest.json`
- Schema: `SealManifest.schema.json`
- Purpose: binds LockedSpec, both verdicts, evidence ref, waivers (if any), and final commit SHA.

6) Waivers (if any)
- For each waiver referenced by `LockedSpec.waivers_applied[]`, include the waiver document.
- Schema: `Waiver.schema.json`

7) All referenced artifacts by `storage_ref`
- For every ObjectRef in:
  - `SealManifest.locked_spec_ref`, `SealManifest.gate_q_verdict_ref`, `SealManifest.gate_r_verdict_ref`, `SealManifest.evidence_manifest_ref`, and `SealManifest.waivers[]`
  - and for every entry in `artifacts[]` for each included EvidenceManifest (each artifact has `storage_ref`)
  - include the corresponding bytes addressed by `storage_ref`.

NOTE: Schemas define `storage_ref` as an opaque string; the bundle MUST make it resolvable (e.g., by shipping files in a directory that mirrors the `storage_ref` naming scheme).

## 2) Evidence kind requirements

Evidence artifacts are categorized by `EvidenceManifest.artifacts[].kind` (enum in `EvidenceManifest.schema.json`).

### 2.1 Allowed evidence kinds (schema enum)
- `diff`
- `test_report`
- `command_log`
- `env_attestation`
- `policy_report`
- `schema_validation`
- `docs_compilation_log`
- `hotl_approval`
- `seal_manifest`
- `genesis_seal`

### 2.2 Tier-driven minimums (Gate R evidence sufficiency)
Gate R deterministically enforces that the EvidenceManifest contains the tier’s `required_evidence_kinds` (see `../../gates/GATE_R.md` and `../../tiers/tier-packs.json`).

- Tier 0 (`tier-0`) minimums:
  - `diff`, `command_log`, `schema_validation`, `policy_report`
- Tier 1–2 (`tier-1`, `tier-2`) minimums:
  - `diff`, `command_log`, `schema_validation`, `policy_report`, `test_report`, `env_attestation`

Tier 3 addendum (Tier 3 ONLY):
- Tier 3 (`tier-3`) minimums:
  - Tier 1–2 minimums **plus** `genesis_seal`

Important: `docs_compilation_log` exists but is produced after Gate R (C3). Gate R MUST NOT require it (`../../tiers/tier-packs.json`).

### 2.3 Evidence kinds used by specific gate checks
This mapping is derived from gate specs:

- Gate Q:
  - Q1 uses `schema_validation`, `command_log`
  - Q2–Q4 use `policy_report` and/or `schema_validation`
  - Q5 uses `schema_validation`, `policy_report`
  - Q6 uses `schema_validation`, `policy_report`

- Gate R:
  - Evidence sufficiency (rule_id `R0.evidence_sufficiency`) uses tier required evidence kinds
  - R1 uses `command_log`, `policy_report`
  - R2 uses `diff`, `command_log`
  - R3 uses `diff`, `policy_report`, `command_log`
  - R4 uses `schema_validation`, `command_log`
  - R5 uses `test_report`, `command_log`
  - R6 uses `env_attestation`, `command_log`
  - R7 uses `policy_report`, `command_log`
  - R8 uses `policy_report`, `command_log`

## 3) Replay procedure (third party)

### Step 1 — Validate schemas for the core JSON artifacts
Validate each JSON document against its schema:
- `LockedSpec.json` → `LockedSpec.schema.json`
- `GateVerdict.Q.json` and `GateVerdict.R.json` → `GateVerdict.schema.json`
- Each EvidenceManifest referenced by `GateVerdict.Q.evidence_manifest_ref`, `GateVerdict.R.evidence_manifest_ref`, and `SealManifest.evidence_manifest_ref` → `EvidenceManifest.schema.json`
- `SealManifest.json` → `SealManifest.schema.json`
- Each waiver document (if any) → `Waiver.schema.json`

Expected outcomes:
- If any schema validation fails, replay is **NO-GO** (evidence is invalid).

### Step 2 — Verify ObjectRef hashes (SHA-256)
Schemas define SHA-256 hex digests as `^[A-Fa-f0-9]{64}$`.

For every ObjectRef in the bundle:
- Resolve its `storage_ref` to bytes included in the bundle.
- Compute SHA-256 digest of those exact bytes.
- Verify it equals the ObjectRef `hash`.

Expected outcomes:
- Any mismatch => **NO-GO** (tamper or mismatch).

### Step 3 — Verify seal (Audit-Grade requirement)
Perform seal verification using the normative algorithm in “Seal Verification (Normative)”.

Expected outcomes:
- If seal verification passes: the replay remains eligible for **Audit-Grade Replay**.
- If seal verification cannot be performed (e.g., missing SealManifest, missing referenced ObjectRefs, or no implementation available): the replay is categorized as **Execution-Only Replay**.
- If seal verification is performed and fails: replay is **NO-GO** (integrity binding failed).

### Step 4 — Verify cross-document consistency
Deterministic consistency checks grounded in schemas/specs:
- Verify each referenced EvidenceManifest has `run_id == LockedSpec.run_id` (required by R4 in `../../gates/GATE_R.md`).
- Verify `GateVerdict.Q.evidence_manifest_ref`, `GateVerdict.R.evidence_manifest_ref`, and `SealManifest.evidence_manifest_ref` each resolve to schema-valid EvidenceManifest documents in the bundle.
- Verify `SealManifest.run_id` equals `LockedSpec.run_id`.
- Verify `SealManifest.final_commit_sha` matches the repo revision being claimed.
- Verify the Replay Integrity Rule (R-Snapshot is preserved within the final sealed evidence set).

Pinned source bytes (pinned archive) — **not enforced in v1**:
- If `SealManifest.replay_instructions_ref` is present, the referenced JSON MUST include `source_archive_ref` as an ObjectRef.
- The bundle MUST include the bytes addressed by `source_archive_ref.storage_ref`, and the verifier MUST check `sha256(bytes)` equals `source_archive_ref.hash`.
- Gate S enforces both the replay instructions payload schema and the `source_archive_ref` hash binding when `replay_instructions_ref` is present.

Expected outcomes:
- Any inconsistency => **NO-GO**.

### Step 5 — Reconstruct the Environment Envelope (determinism boundary)
The envelope is declared in `LockedSpec.environment_envelope` and includes `pinned_toolchain_refs[]` (required).

Replay assumption:
- The third party must be able to obtain and use the referenced pinned toolchain objects (using their `storage_ref` values) and execute within that envelope.

Expected outcomes:
- If the pinned toolchain references are not resolvable from the bundle (or not otherwise available), replay is **NO-GO** because the determinism boundary cannot be reconstructed.
- For Tier 2–3, if the envelope does not include a pinned, executable seal verifier tool, the replay MUST NOT be represented as Audit-Grade (treat as Execution-Only at best).

### Step 6 — Re-run verification (Gate R) against the same base and proposed revision
Gate R requires:
- LockedSpec
- R-Snapshot EvidenceManifest (the EvidenceManifest referenced by `GateVerdict (R).evidence_manifest_ref`)
- The evaluated repo revision must be deterministically diffable against `LockedSpec.upstream_state.commit_sha`.

Procedure:
1) Check out the base commit `LockedSpec.upstream_state.commit_sha`.
2) Check out the final commit `SealManifest.final_commit_sha` (or the proposed revision under evaluation).
3) Execute Gate R verification under the declared Environment Envelope.

Command logging requirement (tier-driven):
- For tiers where `command_log_mode == "structured"` (tiers 1–3), the R-Snapshot `EvidenceManifest.commands_executed` must be structured command records.

Commands required by Gate R are specified as evidence obligations in `../../gates/GATE_R.md` (examples include `belgi invariant-eval`, `belgi run-tests`, `belgi verify-attestation`, `belgi supplychain-scan`, `belgi adversarial-scan`).

Any command invocations listed here are **EXAMPLE COMMAND (non-normative)** unless the exact argv is present in the R-Snapshot EvidenceManifest being replayed.

Expected outcomes:
- The replayed Gate R decision should match the bundled Gate R verdict (GO/NO-GO), assuming the same locked inputs and envelope.

### Audit vs execution-only outcomes (summary)
- Audit-Grade Replay requires: schema validity + ObjectRef hash verification + deterministic Gate R replay within envelope + **seal verification passes**.
- Execution-Only Replay may validate schemas/hashes and replay Gate R, but without seal verification it MUST NOT be represented as a valid audit.

## 4) Determinism caveats

Replay can fail (or produce materially different evidence) if:
- Toolchain drift: pinned toolchain references cannot be obtained or differ from what the run used.
- Nondeterministic tests: evidence differs across reruns (tier policies treat unstable evidence as insufficient or NO-GO).
- Missing or nonconforming command logs: Gate R enforces `command_log_mode` and required commands as evidence obligations.

Tier packs mitigate replay issues via:
- stricter evidence requirements at higher tiers,
- structured command logs (tiers 1–3), and
- required envelope attestation (tiers 1–3).

## 5) Minimal example evidence bundle directory (tree)

This is a directory-structured example; exact names may vary, but everything referenced by `storage_ref` MUST be resolvable from the bundle.

```text
evidence-bundle/
  LockedSpec.json
  GateVerdict.Q.json
  GateVerdict.R.json
  EvidenceManifest.Q.snapshot.json
  EvidenceManifest.R.snapshot.json
  EvidenceManifest.final.json
  SealManifest.json
  replay_instructions.json
  waivers/
    waiver-001.json
  artifacts/
    diff-001.patch
    test-report-001.json
    env-attest-001.json
    policy-invariant-eval.json
    policy-supplychain.json
    policy-adversarial-scan.json
    schema-validation-lockedspec.json
    docs-compilation-log.txt

Tier 3 addendum (Tier 3 ONLY):

```text
  artifacts/
    genesis-seal-001.json
```

Pinned source bytes (example):

```text
  artifacts/
    source-archive-final.tgz
```
```
