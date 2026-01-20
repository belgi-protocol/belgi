# Gate Q — Lock & Verify (Pre-LLM)

## 1. Purpose
Gate Q is the first deterministic gate in the canonical chain (P → C1 → **Q** → C2 → R → C3 → S). Its job is to **reject runs that cannot be deterministically verified later** and to **lock** the run’s controlling inputs into a schema-valid LockedSpec. Canonical meaning and constraints are defined in [CANONICALS.md#q-gate-1-lock-verify](https://github.com/belgi-protocol/belgi/blob/main/CANONICALS.md#q-gate-1-lock-verify).

### 1.1 Pre-LLM input validity (mandatory)
Gate Q MUST validate the presence and schema-validity of the IntentSpec input (or its canonical equivalent object) **before any LLM / C2 step is permitted**.

Operationally in v1, this means Q MUST evaluate `Q-INTENT-001` and `Q-INTENT-002` successfully before the run may proceed to C2.

## 2. Inputs (Required)
Gate Q is strictly **pre-LLM** and MUST NOT assume code changes exist.

### 2.1 IntentSpec (core intent contract)
- Input artifact: `IntentSpec.core.md`
- MUST be authored using: [belgi/templates/IntentSpec.core.template.md](https://github.com/belgi-protocol/belgi/blob/main/belgi/templates/IntentSpec.core.template.md)
- MUST contain exactly one fenced YAML block (` ```yaml ... ``` `) which is the ONLY machine-parsed section.
- Parsed YAML MUST validate against: [../schemas/IntentSpec.schema.json](../schemas/IntentSpec.schema.json)

#### 2.1.1 doc_impact contract (IntentSpec → LockedSpec → Gate R)
The core IntentSpec schema requires `doc_impact` to be present.

Deterministic semantics (v1):
- `doc_impact` is always present in IntentSpec (schema-enforced by [../schemas/IntentSpec.schema.json](../schemas/IntentSpec.schema.json) and checked by `Q-INTENT-002`).
- For Tier 2–3 runs: if `doc_impact.required_paths` is empty `[]`, then `doc_impact.note_on_empty` MUST be present and non-empty (enforced by schema and defense-in-depth by `Q-DOC-002`).
- Contract to Gate R (post-proposal): for Tier 2–3 runs, if `doc_impact.required_paths` is non-empty, Gate R MUST fail the run if none of the declared required paths are touched in the evaluated diff (enforced by `R-DOC-001`; Gate Q only locks the declaration).

### 2.2 Candidate LockedSpec (from C1)
- Input artifact: `LockedSpec.json`
- MUST validate against: [../schemas/LockedSpec.schema.json](../schemas/LockedSpec.schema.json)
- Gate Q reads (minimum):
  - `schema_version`, `belgi_version`, `run_id`
  - `intent.*`
  - `tier.tier_id`, `tier.tolerances_ref`
  - `environment_envelope.*`
  - `invariants[]`
  - `constraints.allowed_paths`, `constraints.forbidden_paths`, optional `constraints.max_touched_files`, `constraints.max_loc_delta`
  - `prompt_bundle_ref`
  - `protocol_pack.*`
  - `upstream_state.repo_ref`, `upstream_state.commit_sha`, `upstream_state.dirty_flag`
  - optional `waivers_applied[]`
  - optional `doc_impact` (may be required by tier)

### 2.3 Optional waiver documents (human-authored)
If `LockedSpec.waivers_applied` is present and non-empty, Gate Q requires the corresponding waiver documents as inputs.
- Each waiver MUST validate against: [../schemas/Waiver.schema.json](../schemas/Waiver.schema.json)

### 2.4 Policy/tier references (read-only)
Gate Q enforcement procedures reference:
- Failure categories: [failure-taxonomy.md](failure-taxonomy.md)
- Tier parameter defaults (canonical SSOT): [../tiers/tier-packs.json](../tiers/tier-packs.json)
  - Generated view (must match canonical): [../tiers/tier-packs.md](../tiers/tier-packs.md)

v1 scope note (deterministic, schema-only): policy inputs are assumed to be fully represented by the candidate LockedSpec fields that Gate Q can validate (`constraints`, `invariants`, `environment_envelope`, `tier`, and waiver references). Gate Q does not consume any other policy-pack schema in v1.

## 3. Outputs (Required)
Gate Q produces:

### 3.0 How to run (v1 CLI runner)

Run Gate Q deterministically using the public runner:

```bash
python chain/gate_q_verify.py \
  --repo . \
  --intent-spec IntentSpec.core.md \
  --locked-spec LockedSpec.json \
  --evidence-manifest EvidenceManifest.json \
  --out GateVerdict.json
```

Exit codes (deterministic):
- `0`: GO
- `2`: NO-GO
- `3`: tool usage/internal errors (I/O, parse errors)

### 3.1 GateVerdict (gate_id = Q)
- Output artifact: `GateVerdict.json`
- MUST validate against: [../schemas/GateVerdict.schema.json](../schemas/GateVerdict.schema.json)

**GO semantics (schema-enforced):**
- `verdict = "GO"`
- `failure_category = null`
- `failures = []`
- `remediation` MUST be absent

**NO-GO semantics (schema-enforced):**
- `verdict = "NO-GO"`
- `failure_category` MUST be a non-null category token
- `failures` MUST be non-empty
- `remediation.next_instruction` MUST match: `^Do .+ then re-run Q\.$`

Remediation loop (operator contract):
- If Gate Q returns **NO-GO**, the operator MUST follow `remediation.next_instruction` exactly and then re-run Gate Q.
- The run MUST NOT proceed to C2 until Gate Q returns **GO**.

Deterministic selection rule for `GateVerdict.failure_category`:
- Set it to the category of the **first failing check** in the ordered check list (PROTOCOL-IDENTITY-001 → Q-INTENT-001 → Q-INTENT-002 → Q-INTENT-003 → Q1 → Q-PROMPT-001 → Q-EVIDENCE-001 → Q-EVIDENCE-002 → Q2 → Q3 → Q4 → Q-CONSTRAINT-001 → Q5 → Q6 → Q7 → Q-HOTL-001 → Q-DOC-001 → Q-DOC-002).

### 3.2 LockedSpec (locked)
Gate Q MUST emit (or reference) the locked, immutable LockedSpec used for later stages.
- Output artifact: the validated `LockedSpec.json` (identical bytes to the candidate LockedSpec that passed Q).

### 3.3 EvidenceManifest reference
Gate Q MUST output `GateVerdict.evidence_manifest_ref` (ObjectRef shape) pointing to an EvidenceManifest.
- EvidenceManifest MUST validate against: [../schemas/EvidenceManifest.schema.json](../schemas/EvidenceManifest.schema.json)

**Minimum required evidence kinds at Q** (EvidenceManifest.artifacts[].kind enum):
- `command_log` (C1): compilation/validation command transcript for Q inputs
- `policy_report` (C1): category-level summary of policy compilation inputs/outputs (no bypass details)
- `schema_validation` (C1): schema validation outputs for LockedSpec and waiver docs

Note: EvidenceManifest.artifacts[].produced_by does not include `Q`; Q-required evidence MUST be recorded as produced by `C1`.

## 4. What Gate Q MUST NOT do
Gate Q MUST NOT:
- run tests or build code (no patch exists yet)
- accept or evaluate diffs
- modify the repo beyond producing/locking the LockedSpec and producing evidence artifacts

## 5. Deterministic Checks (Executable Doc)
All checks below are evaluated in order PROTOCOL-IDENTITY-001 → Q-INTENT-001 → Q-INTENT-002 → Q-INTENT-003 → Q1 → Q-PROMPT-001 → Q-EVIDENCE-001 → Q-EVIDENCE-002 → Q2 → Q3 → Q4 → Q-CONSTRAINT-001 → Q5 → Q6 → Q7 → Q-HOTL-001 → Q-DOC-001 → Q-DOC-002.

Each check specifies: `check_id`, required inputs, deterministic procedure, failure category, required evidence kinds, and remediation template.

### PROTOCOL-IDENTITY-001 — Protocol pack identity matches LockedSpec.protocol_pack
- check_id: `PROTOCOL-IDENTITY-001`
- required inputs:
  - `LockedSpec.protocol_pack.pack_id` (LockedSpec schema)
  - `LockedSpec.protocol_pack.manifest_sha256` (LockedSpec schema)
  - `LockedSpec.protocol_pack.pack_name` (LockedSpec schema)
  - `LockedSpec.protocol_pack.source` (LockedSpec schema)
  - Active protocol context identity (from the executing verifier): `pack_id`, `manifest_sha256`, `pack_name`, `source`
- deterministic procedure (v1, deterministic):
  1) FAIL if `LockedSpec` is missing or not an object.
  2) FAIL if `LockedSpec.protocol_pack` is missing or not an object.
  3) Compare the following fields for exact string equality; record any mismatches:
     - `LockedSpec.protocol_pack.pack_id` vs active `pack_id`
     - `LockedSpec.protocol_pack.manifest_sha256` vs active `manifest_sha256`
     - `LockedSpec.protocol_pack.pack_name` vs active `pack_name`
     - `LockedSpec.protocol_pack.source` vs active `source`
  4) FAIL if any mismatch exists.
- failure category: `FQ-PROTOCOL-IDENTITY-MISMATCH`
- required evidence kinds: `schema_validation`, `policy_report`
- remediation.next_instruction template: `Do ensure the same protocol pack is used for C1 compilation and gate verification then re-run Q.`

### Q-INTENT-001 — IntentSpec file present and YAML block parseable
- check_id: `Q-INTENT-001`
- required inputs:
  - `IntentSpec.core.md`
- deterministic procedure (v1, deterministic):
  1) Read `IntentSpec.core.md` as UTF-8 text.
  2) Identify fenced YAML blocks using exact fence lines:
     - start fence: a line that is exactly ```yaml
     - end fence: a line that is exactly ```
  3) FAIL if the file contains zero YAML fenced blocks.
  4) FAIL if the file contains more than one YAML fenced block.
  5) Parse the YAML contents of the single block into an object.
     - The parser MUST reject invalid YAML.
     - The parser MUST treat duplicate mapping keys as an error (FAIL).
     - The parser MUST interpret the scalar tokens `true` and `false` as booleans (not strings).
- failure category: `FQ-INTENT-INSUFFICIENT`
- required evidence kinds: `schema_validation`, `policy_report`
- remediation.next_instruction template: `Do fix IntentSpec.core.md so it contains exactly one parseable YAML block then re-run Q.`

### Q-INTENT-002 — IntentSpec validates against IntentSpec.schema.json
- check_id: `Q-INTENT-002`
- required inputs:
  - Parsed YAML object from `IntentSpec.core.md`
  - Schema: [../schemas/IntentSpec.schema.json](../schemas/IntentSpec.schema.json)
- deterministic procedure (v1, deterministic):
  1) Validate the parsed YAML object against the IntentSpec schema.
  2) FAIL if validation errors exist.
- failure category: `FQ-INTENT-INSUFFICIENT`
- required evidence kinds: `schema_validation`, `policy_report`
- remediation.next_instruction template: `Do fix IntentSpec schema validation errors for missing_field then re-run Q.`

Note (deterministic tokenization):
- If the parsed YAML value is not an object/mapping, Gate Q MUST use the literal token `intent_spec` in place of `missing_field`.
- Otherwise (parsed YAML is an object/mapping but schema-invalid), Gate Q MUST use the literal token `missing_field`.

### Q-INTENT-003 — Deterministic mapping rules from IntentSpec → LockedSpec inputs
- check_id: `Q-INTENT-003`
- required inputs:
  - Parsed + schema-valid IntentSpec object
  - Candidate LockedSpec: [../schemas/LockedSpec.schema.json](../schemas/LockedSpec.schema.json)
  - Tier defaults (canonical SSOT): [../tiers/tier-packs.json](../tiers/tier-packs.json)
- deterministic procedure (v1, deterministic):
  Gate Q recomputes the expected LockedSpec inputs from the IntentSpec and requires exact matches:

  1) Intent field mapping (LockedSpec.intent.*):
     - `LockedSpec.intent.intent_id` MUST equal `IntentSpec.intent_id`.
     - `LockedSpec.intent.title` MUST equal `IntentSpec.title`.
     - `LockedSpec.intent.narrative` MUST equal `IntentSpec.goal`.
     - `LockedSpec.intent.success_criteria` MUST equal:
       - a newline-joined list with prefix "- " for each entry in `IntentSpec.acceptance.success_criteria`, preserving order.
       - Example: "- item1\n- item2".
     - `LockedSpec.intent.scope` MUST equal this deterministic summary string, preserving array order:
       - `allowed_dirs: [<allowed_dirs joined by ', '>]; forbidden_dirs: [<forbidden_dirs joined by ', '>]; max_touched_files: <value or null>; max_loc_delta: <value or null>`

  2) Scope/constraint mapping (LockedSpec.constraints.*):
     - `LockedSpec.constraints.allowed_paths` MUST equal `IntentSpec.scope.allowed_dirs` exactly (array equality; preserve order).
     - `LockedSpec.constraints.forbidden_paths` MUST equal `IntentSpec.scope.forbidden_dirs` exactly.
     - If `IntentSpec.scope.max_touched_files` is present, `LockedSpec.constraints.max_touched_files` MUST equal it.
     - If `IntentSpec.scope.max_loc_delta` is present, `LockedSpec.constraints.max_loc_delta` MUST equal it.

  3) Tier mapping (LockedSpec.tier.*):
     - `LockedSpec.tier.tier_id` MUST equal `IntentSpec.tier.tier_pack_id`.
     - The remaining tier fields (`tier_name`, `tolerances_ref`) are populated by C1 from tier packs and MUST remain schema-valid.

  4) doc_impact semantics alignment:
     - From tier-packs, read `doc_impact_required` for the selected tier.
     - If `doc_impact_required == true`, `LockedSpec.doc_impact` MUST be present (not null).
     - If `LockedSpec.doc_impact` is present, it MUST be exactly equal to `IntentSpec.doc_impact`.
      - `required_paths` MAY be empty `[]` to explicitly indicate “no doc updates required”, but then `note_on_empty` MUST be present and non-empty.

  4b) publication_intent semantics alignment:
     - For tiers `tier-2` and `tier-3` (audit-grade): `LockedSpec.publication_intent` MUST be present.
     - If `LockedSpec.publication_intent` is present, it MUST be exactly equal to `IntentSpec.publication_intent`.
     - Notes:
       - This field is explicit (no `project_extension` fallback).
       - Profile selection enforcement is deferred to dedicated policy/gate checks; Gate Q only locks the declaration.

  5) Non-core fields:
     - `IntentSpec.waivers_requested` and `IntentSpec.project_extension` are **not** interpreted by core gates unless explicitly mapped by policy; they MUST NOT be assumed to authorize waivers.

  6) Non-authoritative field enforcement:
     - For tiers `tier-1`, `tier-2`, `tier-3` (audit-grade):
       - FAIL if `IntentSpec.project_extension` is non-empty (schema drift prevention).
       - FAIL if `IntentSpec.waivers_requested` is non-empty (schema drift prevention).
     - For tier `tier-0` (paper-grade): non-authoritative fields are permitted but still not interpreted.
     - Rationale: prevents reviewers from assuming policy controls are enforced when they are not.

- failure category: `FQ-SCHEMA-LOCKEDSPEC-INVALID` or `FQ-INTENT-INSUFFICIENT` (for non-authoritative field violations)
- required evidence kinds: `schema_validation`, `policy_report`
- remediation.next_instruction template: `Do fix C1 compilation so LockedSpec fields match the deterministic IntentSpec mapping rules then re-run Q.`

### Q1 — LockedSpec schema validation
- check_id: `Q1`
- required inputs:
  - Candidate LockedSpec: [../schemas/LockedSpec.schema.json](../schemas/LockedSpec.schema.json)
- deterministic procedure:
  1) Validate the candidate LockedSpec JSON against the LockedSpec schema (Draft 2020-12).
  2) Fail if validation errors exist.
- failure category: `FQ-SCHEMA-LOCKEDSPEC-INVALID`
- required evidence kinds: `schema_validation`, `command_log`
- remediation.next_instruction template: `Do fix LockedSpec schema validation errors for missing_field then re-run Q.`

### Q-PROMPT-001 — Prompt bundle source allowlist (prompt injection prevention)
- check_id: `Q-PROMPT-001`
- required inputs:
  - `LockedSpec.allowed_repo_refs[]` (optional; LockedSpec schema)
  - `LockedSpec.prompt_bundle_ref` (LockedSpec schema)
- deterministic procedure (v1, deterministic):
  1) If `allowed_repo_refs` is absent or empty: pass (allowlist not declared; no enforcement).
  2) If `allowed_repo_refs` is non-empty:
     - FAIL if `prompt_bundle_ref` is missing or malformed.
     - FAIL if `prompt_bundle_ref.storage_ref` is missing or empty.
     - Verify `prompt_bundle_ref.storage_ref` starts with `<owner>/<repo>/` for at least one entry in `allowed_repo_refs`.
     - FAIL if no match found (prompt bundle from unlisted source).
- failure category: `FQ-PROMPT-SOURCE-INVALID`
- required evidence kinds: `schema_validation`, `policy_report`
- remediation.next_instruction template: `Do update prompt_bundle_ref to reference allowed repo or update allowed_repo_refs then re-run Q.`

### Q-EVIDENCE-001 — EvidenceManifest schema validation
- check_id: `Q-EVIDENCE-001`
- required inputs:
  - EvidenceManifest: [../schemas/EvidenceManifest.schema.json](../schemas/EvidenceManifest.schema.json)
- deterministic procedure:
  1) Validate the EvidenceManifest JSON against the EvidenceManifest schema (Draft 2020-12).
  2) Fail if validation errors exist.
- failure category: `FQ-SCHEMA-EVIDENCEMANIFEST-INVALID`
- required evidence kinds: `schema_validation`, `policy_report`
- remediation.next_instruction template: `Do fix EvidenceManifest schema validation errors for missing_field then re-run Q.`

### Q-EVIDENCE-002 — Minimum required evidence kinds present at Q
- check_id: `Q-EVIDENCE-002`
- required inputs:
  - EvidenceManifest (`EvidenceManifest.artifacts[]`)
  - Tier policy reference (canonical SSOT): [../tiers/tier-packs.json](../tiers/tier-packs.json) (`required_evidence_kinds_q`)
- deterministic procedure:
  1) Verify EvidenceManifest contains at least one artifact for each required kind:
     - `command_log`
     - `policy_report`
     - `schema_validation`
  2) Fail if any required kind is missing.
- failure category: `FQ-EVIDENCE-MISSING`
- required evidence kinds: `schema_validation`, `policy_report`
- remediation.next_instruction template: `Do produce required evidence kind <missing_kind> under the declared envelope then re-run Q.`

Note (deterministic selection): `<missing_kind>` is the first missing kind from the tier’s `required_evidence_kinds_q`, preserving that declared order.

### Q2 — Intent completeness (reject vague P at Q)
- check_id: `Q2`
- required inputs:
  - `LockedSpec.intent.*` (LockedSpec schema)
  - `LockedSpec.constraints.allowed_paths` (LockedSpec schema)
  - `LockedSpec.invariants[]` (LockedSpec schema)
- deterministic procedure (v1, deterministic):
  Gate Q returns NO-GO with `FQ-INTENT-INSUFFICIENT` if **any** of the following are true:
  1) Any required intent field is empty:
    - `intent.intent_id`, `intent.title`, `intent.narrative`, `intent.scope`, `intent.success_criteria`.
  2) `constraints.allowed_paths` is empty.
  3) `invariants` is empty.
- failure category: `FQ-INTENT-INSUFFICIENT`
- required evidence kinds: `policy_report`, `schema_validation`
- remediation.next_instruction template: `Do amend intent to make scope and success criteria unambiguous then re-run Q.`

### Q3 — Invariants compiled and structurally usable
- check_id: `Q3`
- required inputs:
  - `LockedSpec.invariants[]` (LockedSpec schema)
- deterministic procedure:
  1) Verify `invariants` is non-empty.
  2) Verify each invariant has non-empty `id`, `description`, `severity`.
  3) Verify invariant `id` values are unique.
- failure category: `FQ-INVARIANTS-EMPTY`
- required evidence kinds: `policy_report`, `schema_validation`
- remediation.next_instruction template: `Do update C1 compilation so invariants are non-empty and specific then re-run Q.`

### Q4 — Constraints present (paths + budgets)
- check_id: `Q4`
- required inputs:
  - `LockedSpec.constraints.allowed_paths` and `LockedSpec.constraints.forbidden_paths` (LockedSpec schema)
- deterministic procedure:
  1) Verify `constraints.allowed_paths` is non-empty.
  2) Verify `constraints.forbidden_paths` is present (may be empty).
  3) Record `constraints.max_touched_files` and `constraints.max_loc_delta` if present; these become the locked run constraints.
- failure category: `FQ-CONSTRAINTS-MISSING`
- required evidence kinds: `policy_report`, `schema_validation`
- remediation.next_instruction template: `Do add required constraints (missing_field) to LockedSpec then re-run Q.`

### Q-CONSTRAINT-001 — Constraints path prefixes are normalized (repo-relative)
- check_id: `Q-CONSTRAINT-001`
- required inputs:
  - `LockedSpec.constraints.allowed_paths[]`, `LockedSpec.constraints.forbidden_paths[]`
  - Schema: [../schemas/LockedSpec.schema.json](../schemas/LockedSpec.schema.json) `#/$defs/RepoRelPathPrefix`
- deterministic procedure:
  1) For each entry in `constraints.allowed_paths[]` and `constraints.forbidden_paths[]`, validate it against `LockedSpec.schema.json#/$defs/RepoRelPathPrefix`.
  2) FAIL if any entry is non-normalized (e.g., contains `..`, `\\`, `//`, `./`, `*`, or `?`, or starts with `/`).
- failure category: `FQ-SCHEMA-LOCKEDSPEC-INVALID`
- required evidence kinds: `policy_report`, `schema_validation`
- remediation.next_instruction template: `Do normalize LockedSpec.constraints path prefixes to repo-relative POSIX form then re-run Q.`

### Q5 — Environment Envelope declared and lockable
- check_id: `Q5`
- required inputs:
  - `LockedSpec.environment_envelope.*` (LockedSpec schema)
- deterministic procedure:
  1) Verify `environment_envelope.id`, `description`, `expected_runner` are non-empty (schema-enforced).
  2) Verify `pinned_toolchain_refs` is present and non-empty (schema-enforced).
- failure category: `FQ-ENVELOPE-MISSING`
- required evidence kinds: `schema_validation`, `policy_report`
- remediation.next_instruction template: `Do declare a complete environment_envelope (including pinned_toolchain_refs) then re-run Q.`

### Q6 — Waivers validity (if present)
- check_id: `Q6`
- required inputs:
  - `LockedSpec.waivers_applied[]` (LockedSpec schema, optional)
  - Waiver documents for each waiver_id: [../schemas/Waiver.schema.json](../schemas/Waiver.schema.json)
  - Tier policy reference (canonical SSOT): [../tiers/tier-packs.json](../tiers/tier-packs.json)
- deterministic procedure (v1, deterministic):
  1) If `waivers_applied` is absent or empty: pass.
  2) If present:
    - Verify tier allows waivers (per [../tiers/tier-packs.json](../tiers/tier-packs.json)). If not allowed: fail.
     - Verify the count of active waivers does not exceed `max_active_waivers`.
     - For each waiver document:
       - Validate it against Waiver schema.
       - Verify `status == "active"`.
       - Verify `gate_id` is either `"Q"` or `"R"` (schema-enforced) and is consistent with the referenced waived rule’s gate.
       - Verify `expires_at` is after Gate Q `evaluated_at`.
       - Enforce v1 human-authorship heuristic:
         - `approver` MUST NOT contain the substrings `llm` or `agent` (case-insensitive).
         - `audit_trail_ref.id` and `audit_trail_ref.storage_ref` MUST be non-empty (schema-required; Gate Q MUST treat any schema failure as NO-GO).
- failure category: `FQ-WAIVER-INVALID`
- required evidence kinds: `schema_validation`, `policy_report`
- remediation.next_instruction template: `Do fix or remove waiver waiver_id then re-run Q.`

### Q7 — Tier ID supported
- check_id: `Q7`
- required inputs:
  - `LockedSpec.tier.tier_id` (LockedSpec schema)
  - Supported tier IDs (canonical SSOT): [../tiers/tier-packs.json](../tiers/tier-packs.json)
- deterministic procedure:
  1) Verify `tier_id` is one of: `tier-0`, `tier-1`, `tier-2`, `tier-3`.
  2) If not: fail.
- failure category: `FQ-TIER-UNKNOWN`
- required evidence kinds: `policy_report`, `schema_validation`
- remediation.next_instruction template: `Do select a supported tier_id (<tier_id_value>) then re-run Q.`

Note (deterministic substitution): `<tier_id_value>` is the observed unsupported `tier_id` string from `LockedSpec.tier.tier_id`, serialized exactly as-is.

### Q-HOTL-001 — Human-on-the-Loop approval artifact (role confusion prevention)
- check_id: `Q-HOTL-001`
- required inputs:
  - `LockedSpec.tier.tier_id` (LockedSpec schema)
  - EvidenceManifest (`EvidenceManifest.artifacts[]`)
- deterministic procedure (v1, deterministic):
  1) Determine tier enforcement level from `tier_id`:
     - `tier-2`, `tier-3` (audit-grade): HOTL artifact REQUIRED.
     - `tier-1`: HOTL artifact RECOMMENDED (warning only if missing).
     - `tier-0`: No HOTL requirement.
  2) If HOTL required or recommended:
     - Search `EvidenceManifest.artifacts[]` for an artifact with `kind == "hotl_approval"`.
     - For tier-2/3: FAIL if no `hotl_approval` artifact found.
     - For tier-1: WARN if missing (do not fail; allow run to proceed).
  3) If `hotl_approval` artifact is found:
     - Verify artifact references a document that validates against [../schemas/HOTLApproval.schema.json](../schemas/HOTLApproval.schema.json).
     - Verify `approver` matches pattern `^human:[A-Za-z0-9_.@+-]+$` (role confusion prevention).
- failure category: `FQ-HOTL-MISSING`
- required evidence kinds: `hotl_approval` (for tier-2/3)
- remediation.next_instruction template: `Do produce hotl_approval artifact with valid human approver then re-run Q.`

### Q-DOC-001 — doc_impact.required_paths format validation (if present)
- check_id: `Q-DOC-001`
- required inputs:
  - Optional `LockedSpec.doc_impact` (LockedSpec schema)
  - Schema: [../schemas/LockedSpec.schema.json](../schemas/LockedSpec.schema.json) `#/$defs/RepoRelPathPrefix`
- deterministic procedure (v1, deterministic):
  1) If `doc_impact` is absent: pass.
  2) If present:
     - Verify `doc_impact.required_paths` is present (defense-in-depth; schema also enforces this).
     - For each entry in `required_paths`, validate it against `LockedSpec.schema.json#/$defs/RepoRelPathPrefix`.
     - FAIL if any entry is non-normalized (e.g., contains `..`, `.`, `\`, `//`, `./`, `*`, `?`, `:`/`://`, or starts with `/`).
- failure category: `FQ-SCHEMA-LOCKEDSPEC-INVALID`
- required evidence kinds: `schema_validation`, `policy_report`
- remediation.next_instruction template: `Do fix doc_impact.required_paths to be repo-relative and wildcard-free then re-run Q.`

### Q-DOC-002 — doc_impact tier enforcement (presence + note-on-empty)
- check_id: `Q-DOC-002`
- required inputs:
  - `LockedSpec.tier.tier_id` (LockedSpec schema)
  - Tier defaults (canonical SSOT): [../tiers/tier-packs.json](../tiers/tier-packs.json)
  - Optional `LockedSpec.doc_impact` (LockedSpec schema)
- deterministic procedure (v1, deterministic):
  1) From [../tiers/tier-packs.json](../tiers/tier-packs.json), read `doc_impact_required` for the selected `tier_id`.
  2) If `doc_impact_required == false`: pass.
  3) If `doc_impact_required == true`:
     - FAIL if `doc_impact` is missing or null.
     - FAIL if `doc_impact.required_paths` is missing.
     - If `doc_impact.required_paths` is `[]`:
       - FAIL if `doc_impact.note_on_empty` is missing.
       - FAIL if `trim(doc_impact.note_on_empty)` is empty.
- failure category: `FQ-SCHEMA-LOCKEDSPEC-INVALID`
- required evidence kinds: `schema_validation`, `policy_report`
- remediation.next_instruction template: `Do add required doc_impact (including note_on_empty when required_paths is empty) then re-run Q.`
