# BELGI Failure Taxonomy

## 0. Rule of Use (Canonical Pointer)
This file defines **failure category IDs** for gate outputs. It MUST NOT define or redefine canonical terms.
Canonical meanings live in [CANONICALS.md#failure-taxonomy-interface](https://github.com/belgi-protocol/belgi/blob/main/CANONICALS.md#failure-taxonomy-interface) (see also [CANONICALS.md#go](https://github.com/belgi-protocol/belgi/blob/main/CANONICALS.md#go) and [CANONICALS.md#no-go](https://github.com/belgi-protocol/belgi/blob/main/CANONICALS.md#no-go)).

## 1. Category IDs (Stable)

### 1.1 Remediation string constraints (schema-aligned)
Per [../schemas/GateVerdict.schema.json](../schemas/GateVerdict.schema.json), any `GateVerdict.remediation.next_instruction`:
- MUST be a single string.
- MUST start with `Do `.
- MUST end with `then re-run Q.`, `then re-run R.`, or `then re-run S.`

### 1.2 Remediation token conventions (deterministic)
To preserve determinism across tools and platforms, v1 remediation strings follow these rules:

**A) Literal tokens (not substituted):**
- `missing_field`: used when the tool does not deterministically choose a single schema-field to name.
- `intent_spec`: used when the tool deterministically refers to the whole intent object instead of a specific field (e.g., when parsed YAML is not an object/mapping).
- `waiver_id`: used when the tool does not deterministically choose a single waiver id to name.
- `belgi <subcommand>`: used when the tool does not deterministically choose a single subcommand token to name.
- `evidence_kind`: used when the tool does not deterministically choose a single evidence kind to name.
- `<path>`: (deprecated) do not emit as a placeholder; gates SHOULD substitute the concrete repo-relative path when deterministically known.

**B) Deterministic substitutions (tool inserts a concrete value):**
- Gate Q: `Do produce required evidence kind <missing_kind> ...` where `<missing_kind>` is the first missing kind in tier `required_evidence_kinds_q` order.
- Gate Q: `Do select a supported tier_id (<tier_id_value>) ...` where `<tier_id_value>` is the observed tier id string.
- Gate R: `Do revert changes to forbidden path <path> ...` where `<path>` is the deterministically identified forbidden changed path.
- Gate R (canonical verifier): `Do modify the change so invariant <rule_id> is satisfied ...` where `<rule_id>` is the failing check_id/rule_id.

Unless a gate explicitly declares a deterministic substitution above, tokens are treated as literal text.

---

## 2. Gate Q Categories

### FQ-SCHEMA-LOCKEDSPEC-INVALID
- category_id: `FQ-SCHEMA-LOCKEDSPEC-INVALID`
- gate_id: `Q`
- severity: `blocker`
- description: Candidate LockedSpec is invalid for deterministic use (schema-invalid and/or violates MUST-level deterministic mapping/normalization contracts required by Gate Q).
- remediation.next_instruction templates (canonical set):
	- `Do fix LockedSpec schema validation errors for missing_field then re-run Q.`
	- `Do fix C1 compilation so LockedSpec fields match the deterministic IntentSpec mapping rules then re-run Q.`
	- `Do normalize LockedSpec.constraints path prefixes to repo-relative POSIX form then re-run Q.`
	- `Do fix doc_impact.required_paths to be repo-relative and wildcard-free then re-run Q.`
	- `Do add required doc_impact (including note_on_empty when required_paths is empty) then re-run Q.`

### FQ-SCHEMA-EVIDENCEMANIFEST-INVALID
- category_id: `FQ-SCHEMA-EVIDENCEMANIFEST-INVALID`
- gate_id: `Q`
- severity: `blocker`
- description: EvidenceManifest does not validate against the EvidenceManifest schema.
- remediation.next_instruction template: `Do fix EvidenceManifest schema validation errors for missing_field then re-run Q.`

### FQ-PROMPT-SOURCE-INVALID
- category_id: `FQ-PROMPT-SOURCE-INVALID`
- gate_id: `Q`
- severity: `blocker`
- description: Prompt bundle source is not allowed by the declared allowlist (prompt injection prevention).
- remediation.next_instruction template: `Do update prompt_bundle_ref to reference allowed repo or update allowed_repo_refs then re-run Q.`

### FQ-EVIDENCE-MISSING
- category_id: `FQ-EVIDENCE-MISSING`
- gate_id: `Q`
- severity: `blocker`
- description: Minimum required evidence kinds for Gate Q are missing from EvidenceManifest.
- remediation.next_instruction template: `Do produce required evidence kind <missing_kind> under the declared envelope then re-run Q.`

### FQ-INTENT-INSUFFICIENT
- category_id: `FQ-INTENT-INSUFFICIENT`
- gate_id: `Q`
- severity: `blocker`
- description: IntentSpec is missing, unparseable, schema-invalid, or insufficiently specific to support deterministic compilation/locking.
- remediation.next_instruction templates (canonical set):
	- `Do fix IntentSpec.core.md so it contains exactly one parseable YAML block then re-run Q.`
	- `Do fix IntentSpec schema validation errors for missing_field then re-run Q.`
	- `Do amend intent to make scope and success criteria unambiguous then re-run Q.`

### FQ-INVARIANTS-EMPTY
- category_id: `FQ-INVARIANTS-EMPTY`
- gate_id: `Q`
- severity: `blocker`
- description: No compiled invariants are present, or invariants are structurally unusable.
- remediation.next_instruction template: `Do update C1 compilation so invariants are non-empty and specific then re-run Q.`

### FQ-CONSTRAINTS-MISSING
- category_id: `FQ-CONSTRAINTS-MISSING`
- gate_id: `Q`
- severity: `blocker`
- description: Required constraints (e.g., allowed/forbidden paths) are missing.
- remediation.next_instruction template: `Do add required constraints (missing_field) to LockedSpec then re-run Q.`

### FQ-ENVELOPE-MISSING
- category_id: `FQ-ENVELOPE-MISSING`
- gate_id: `Q`
- severity: `blocker`
- description: Environment Envelope is missing or incomplete for a lockable run contract.
- remediation.next_instruction template: `Do declare a complete environment_envelope (including pinned_toolchain_refs) then re-run Q.`

### FQ-WAIVER-INVALID
- category_id: `FQ-WAIVER-INVALID`
- gate_id: `Q`
- severity: `blocker`
- description: One or more waivers are invalid (schema invalid, expired, wrong gate, or inconsistent with the run).
- remediation.next_instruction template: `Do fix or remove waiver waiver_id then re-run Q.`

### FQ-TIER-UNKNOWN
- category_id: `FQ-TIER-UNKNOWN`
- gate_id: `Q`
- severity: `blocker`
- description: Tier selection is missing or not recognized by the declared Tier Pack set.
- remediation.next_instruction template: `Do select a supported tier_id (<tier_id_value>) then re-run Q.`

### FQ-HOTL-MISSING
- category_id: `FQ-HOTL-MISSING`
- gate_id: `Q`
- severity: `blocker`
- description: Required human-on-the-loop approval evidence is missing or invalid for the selected tier/policy (e.g., missing HOTL artifact, schema invalid, hash mismatch, or non-human approver).
- remediation.next_instruction template: `Do produce hotl_approval artifact with valid human approver then re-run Q.`

### FQ-PROTOCOL-IDENTITY-MISMATCH
- category_id: `FQ-PROTOCOL-IDENTITY-MISMATCH`
- gate_id: `Q`
- severity: `blocker`
- description: LockedSpec.protocol_pack does not match the active protocol pack identity (pack_id, manifest_sha256, pack_name, or source mismatch).
- remediation.next_instruction template: `Do ensure the same protocol pack is used for C1 compilation and gate verification then re-run Q.`

---

## 3. Gate R Categories

### FR-COMMAND-FAILED
- category_id: `FR-COMMAND-FAILED`
- gate_id: `R`
- severity: `blocker`
- description: A required command record is missing/failed (non-zero exit code) OR the EvidenceManifest command log does not satisfy the tier-required `command_log_mode` shape obligation.
- remediation.next_instruction template: `Do ensure required command record belgi <subcommand> exists with exit_code 0 in EvidenceManifest.commands_executed then re-run R.`

### FR-INVARIANT-EVAL-MISSING
- category_id: `FR-INVARIANT-EVAL-MISSING`
- gate_id: `R`
- severity: `blocker`
- description: Required invariant evaluation evidence obligation is missing (command and/or invariant-eval policy report).
- remediation.next_instruction template: `Do run belgi invariant-eval and record policy report policy.invariant_eval then re-run R.`

### FR-ADVERSARIAL-SCAN-MISSING
- category_id: `FR-ADVERSARIAL-SCAN-MISSING`
- gate_id: `R`
- severity: `blocker`
- description: Required adversarial scan evidence obligation is missing (command and/or adversarial scan policy report).
- remediation.next_instruction template: `Do run belgi adversarial-scan and record policy report policy.adversarial_scan then re-run R.`

### FR-SUPPLYCHAIN-SCAN-MISSING
- category_id: `FR-SUPPLYCHAIN-SCAN-MISSING`
- gate_id: `R`
- severity: `blocker`
- description: Required supply chain scan evidence obligation is missing (command and/or supplychain policy report).
- remediation.next_instruction template: `Do run belgi supplychain-scan and record policy report policy.supplychain then re-run R.`

### FR-EVIDENCE-MISSING
- category_id: `FR-EVIDENCE-MISSING`
- gate_id: `R`
- severity: `blocker`
- description: Required evidence kinds are missing for the selected Tier Pack.
- remediation.next_instruction template: `Do produce required evidence kind evidence_kind under the declared envelope then re-run R.`

### FR-EVIDENCE-ATTESTATION-MISSING
- category_id: `FR-EVIDENCE-ATTESTATION-MISSING`
- gate_id: `R`
- severity: `blocker`
- description: Envelope attestation required by tier is missing, null, or fails deterministic id-binding (EvidenceManifest.envelope_attestation.id must match an env_attestation artifact id).
- remediation.next_instruction template: `Do produce envelope attestation evidence under the declared envelope then re-run R.`

### FR-INVARIANT-FAILED
- category_id: `FR-INVARIANT-FAILED`
- gate_id: `R`
- severity: `blocker`
- description: One or more LockedSpec invariants are not satisfied by the verified repo state.
- remediation.next_instruction template: `Do modify the change so invariant <rule_id> is satisfied then re-run R.`

### FR-SCOPE-BUDGET-EXCEEDED
- category_id: `FR-SCOPE-BUDGET-EXCEEDED`
- gate_id: `R`
- severity: `blocker`
- description: Blast Radius / scope budgets exceeded (touched files and/or LOC delta).
- remediation.next_instruction template: `Do reduce scope to within limits (tier scope budgets) or adjust tier/constraints with HOTL then re-run R.`

### FR-POLICY-FORBIDDEN-PATH
- category_id: `FR-POLICY-FORBIDDEN-PATH`
- gate_id: `R`
- severity: `blocker`
- description: Change touches forbidden paths under LockedSpec constraints.
- remediation.next_instruction template: `Do revert changes to forbidden path <path> then re-run R.`

### FR-SCHEMA-ARTIFACT-INVALID
- category_id: `FR-SCHEMA-ARTIFACT-INVALID`
- gate_id: `R`
- severity: `blocker`
- description: A required run artifact fails schema validation OR required deterministic configuration (e.g., tier parsing) fails, preventing Gate R from enforcing derived obligations.
- remediation.next_instruction template: `Do fix schema validation errors in required artifact then re-run R.`

### FR-TESTS-POLICY-FAILED
- category_id: `FR-TESTS-POLICY-FAILED`
- gate_id: `R`
- severity: `blocker`
- description: Tests are missing or failing under the tier’s test policy.
- remediation.next_instruction template: `Do run required tests and resolve failures then re-run R.`

### FR-SUPPLYCHAIN-CHANGE-UNACCOUNTED
- category_id: `FR-SUPPLYCHAIN-CHANGE-UNACCOUNTED`
- gate_id: `R`
- severity: `major`
- description: Dependency/toolchain changes are detected but not accounted for in the run’s declared constraints/evidence.
- remediation.next_instruction template: `Do account for supply chain changes with updated envelope refs or an approved waiver then re-run R.`

### FR-ADVERSARIAL-DIFF-SUSPECT
- category_id: `FR-ADVERSARIAL-DIFF-SUSPECT`
- gate_id: `R`
- severity: `major`
- description: Diff triggers category-level adversarial indicators (no signature details published).
- remediation.next_instruction template: `Do remove suspicious primitive categories from the change or obtain an approved waiver then re-run R.`

Note (v1 deterministic emission):
- `FR-SUPPLYCHAIN-CHANGE-UNACCOUNTED` is emitted deterministically when the required `policy.supplychain` report is present, schema-valid, and has `summary.failed != 0`.
- `FR-ADVERSARIAL-DIFF-SUSPECT` is emitted deterministically when the required `policy.adversarial_scan` report is present, schema-valid, and has `summary.failed != 0`.
- Consumers MUST treat these categories as NO-GO when they appear.

### FR-PROTOCOL-IDENTITY-MISMATCH
- category_id: `FR-PROTOCOL-IDENTITY-MISMATCH`
- gate_id: `R`
- severity: `blocker`
- description: LockedSpec.protocol_pack does not match the active protocol pack identity (pack_id, manifest_sha256, pack_name, or source mismatch).
- remediation.next_instruction template: `Do ensure the same protocol pack is used for C1 compilation and gate verification then re-run R.`

---

## 4. Seal (S) Categories

Seal verification failures are emitted by the Seal verifier tooling (S) and are **NO-GO**.

### FS-SCHEMA-ARTIFACT-INVALID
- category_id: `FS-SCHEMA-ARTIFACT-INVALID`
- gate_id: `S`
- severity: `blocker`
- description: One or more required Seal artifacts are schema-invalid, preventing deterministic verification.
- remediation.next_instruction template: `Do fix SealManifest or LockedSpec schema validation errors then re-run S.`

### FS-BINDING-MISMATCH
- category_id: `FS-BINDING-MISMATCH`
- gate_id: `S`
- severity: `blocker`
- description: SealManifest claims do not bind to the LockedSpec run identity (e.g., run_id mismatch).
- remediation.next_instruction template: `Do regenerate SealManifest for the correct LockedSpec then re-run S.`

### FS-OBJECTREF-HASH-MISMATCH
- category_id: `FS-OBJECTREF-HASH-MISMATCH`
- gate_id: `S`
- severity: `blocker`
- description: One or more SealManifest ObjectRefs (or the pinned seal_pubkey_ref) does not hash-match the referenced bytes.
- remediation.next_instruction template: `Do restore the correct referenced artifact bytes (hash binding) then re-run S.`

### FS-SEALHASH-MISMATCH
- category_id: `FS-SEALHASH-MISMATCH`
- gate_id: `S`
- severity: `blocker`
- description: SealManifest.seal_hash does not match the normative algorithm.
- remediation.next_instruction template: `Do regenerate SealManifest so seal_hash matches the normative algorithm then re-run S.`

### FS-SIGNATURE-MISSING
- category_id: `FS-SIGNATURE-MISSING`
- gate_id: `S`
- severity: `blocker`
- description: Tier-2/3 requires a cryptographic seal signature but SealManifest.signature fields are missing.
- remediation.next_instruction template: `Do produce a Tier-2/3 cryptographic seal signature then re-run S.`

### FS-SIGNATURE-INVALID
- category_id: `FS-SIGNATURE-INVALID`
- gate_id: `S`
- severity: `blocker`
- description: SealManifest signature fields are present but invalid (base64, length, pinned key mismatch, or verification failure).
- remediation.next_instruction template: `Do regenerate SealManifest with a valid cryptographic seal signature then re-run S.`

### FS-SIGNATURE-VERIFY-UNAVAILABLE
- category_id: `FS-SIGNATURE-VERIFY-UNAVAILABLE`
- gate_id: `S`
- severity: `blocker`
- description: Seal signature verification cannot be performed in the declared Environment Envelope (missing required crypto dependency).
- remediation.next_instruction template: `Do include the required crypto dependency in the declared Environment Envelope then re-run S.`

### FS-PROTOCOL-IDENTITY-MISMATCH
- category_id: `FS-PROTOCOL-IDENTITY-MISMATCH`
- gate_id: `S`
- severity: `blocker`
- description: LockedSpec.protocol_pack does not match the active protocol pack identity (pack_id, manifest_sha256, pack_name, or source mismatch).
- remediation.next_instruction template: `Do ensure the same protocol pack is used for C1 compilation and gate verification then re-run S.`

---

## 5. Failure Object Contract (GateVerdict.failures[])
This section maps directly to [../schemas/GateVerdict.schema.json](../schemas/GateVerdict.schema.json).

For every item in `GateVerdict.failures[]`:
- `id`: stable within the verdict (e.g., `Q-Q1-001`, `R-R5-002`).
- `category`: MUST be one of the `category_id` tokens defined in this file.
- `rule_id`: MUST identify the failing gate check (e.g., `Q1`, `R5`) or a more specific sub-rule token (e.g., `R2.max_touched_files`).
- `message`: human-readable explanation.
- `evidence_refs`: one or more ObjectRefs pointing at supporting evidence artifacts (see [../schemas/EvidenceManifest.schema.json](../schemas/EvidenceManifest.schema.json) ObjectRef shape).
