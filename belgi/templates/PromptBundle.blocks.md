# PromptBundle Block Registry (Public-Safe)

DEFAULT: **NO-GO** unless prompt assembly is public-safe, deterministic, and reproducible within the declared Environment Envelope.

## A1) Purpose + scope
This document is a **public-safe registry of prompt blocks** used by the C1 Prompt Compiler to deterministically assemble a PromptBundle artifact referenced by `LockedSpec.prompt_bundle_ref`.

Scope constraints:
- This file **does not contain** full prompt text for internal/secret blocks.
- This file **does not redefine canonicals**. Canonical terms and the canonical chain are defined in `../../CANONICALS.md`.
- This file specifies **only**: block metadata, deterministic selection + ordering rules, and evidence hooks.

Grounding (authoritative references):
- Canonicals: `../../CANONICALS.md` (especially `#c1-prompt-compiler`, `#publication-posture`, `#deterministic-belgi`)
- Gate Q: `../../gates/GATE_Q.md` (LockedSpec inputs, `prompt_bundle_ref`)
- Gate R: `../../gates/GATE_R.md` (evidence obligations and deterministic verification)
- Tier defaults: `../../tiers/tier-packs.json` (canonical SSOT; generated view: `../../tiers/tier-packs.md`)
- Schemas: `../../schemas/LockedSpec.schema.json`, `../../schemas/EvidenceManifest.schema.json`

---

## A2) Block registry (metadata only)

Registry rules:
- `block_id` is stable and never reused.
- `sensitivity` controls publication posture for block **content** (metadata remains publishable).
- `source_inputs` uses only: LockedSpec fields, static text, or repo context references.

> NOTE: “repo context refs” means references to files/anchors in this repo. It does **not** mean free-form model browsing.

| block_id | block_name | content_type | source_inputs | inclusion_rule | sensitivity | notes (public-safe) |
|---|---|---|---|---|---|---|
| PB-001 | Bundle Preamble | output_contract | Static text | always | public | Defines how the assembled PromptBundle must be interpreted (untrusted C2; gates authoritative). |
| PB-002 | Canonical Chain Pointer | policy | Repo context refs: `../../CANONICALS.md#canonical-chain`, `#principle` | always | public | Reminds proposer: “LLMs propose; gates dispose.” |
| PB-003 | Publication Posture Pointer | safety | Repo context ref: `../../CANONICALS.md#publication-posture` | always | public | Category-level safety posture; no bypass details. |
| PB-004 | LockedSpec Summary (Header Only) | context | LockedSpec fields: `run_id`, `intent.*`, `tier.tier_id`, `constraints.*`, `environment_envelope.*`, `upstream_state.*` | always | internal | Block content may include a structured summary of locked fields. Metadata is public-safe. |
| PB-005 | Constraints: Allowed/Forbidden Paths | constraints | LockedSpec fields: `constraints.allowed_paths[]`, `constraints.forbidden_paths[]` | always | internal | Expresses permitted change surface deterministically. |
| PB-006 | Constraints: Scope Budgets | constraints | LockedSpec fields: `constraints.max_touched_files`, `constraints.max_loc_delta`; Tier defaults: `../../tiers/tier-packs.json` | always | internal | Provides explicit numeric budgets as locked constraints (or tier defaults). |
| PB-007 | Invariants Contract | output_contract | LockedSpec fields: `invariants[]` | always | internal | Requires proposer to treat invariants as acceptance checks; content does not include bypass patterns. |
| PB-008 | Evidence Obligations (Category Level) | output_contract | Tier defaults: `../../tiers/tier-packs.json` (`required_evidence_kinds`); Gate R refs: `../../gates/GATE_R.md#4-evidence-sufficiency-rule-deterministic` | always | public | States evidence kinds must exist for verification; does not describe private detection logic. |
| PB-009 | Command Log Mode Reminder | constraints | LockedSpec field: `tier.tier_id` (for deriving `command_log_mode` via `../../tiers/tier-packs.json`) | tier>=tier-1 | public | Reminds structured command records are required at higher tiers. |
| PB-010 | Tests Policy Reminder | constraints | Tier defaults: `../../tiers/tier-packs.json` (`test_policy`); Gate R ref: `../../gates/GATE_R.md#r5--tests-policy-satisfied` | tier>=tier-1 | public | Category-level: tests required at tiers 1–3. |
| PB-011 | Envelope Attestation Reminder | constraints | Tier defaults: `../../tiers/tier-packs.json` (`envelope_policy`); Gate R ref: `../../gates/GATE_R.md#r6--envelope-attestation-satisfied` | tier>=tier-1 | public | Category-level: attestation required at tiers 1–3. |
| PB-012 | Supply Chain Evidence Obligation | safety | Gate R ref: `../../gates/GATE_R.md#r7--supply-chain-changes-detected-and-accounted-for` | tier>=tier-0 | public | Category-level: require scan command + policy report; no signatures or patterns published. |
| PB-013 | Adversarial Scan Evidence Obligation | safety | Gate R ref: `../../gates/GATE_R.md#r8--adversarial-diff-scan-category-level` | tier>=tier-0 | public | Category-level: require scan command + policy report; no signatures or patterns published. |
| PB-014 | Output Format Contract | output_contract | Static text; schema pointer: `../../schemas/GateVerdict.schema.json` (format awareness only) | always | public | Requires proposer outputs to be structured and auditable (plans, file lists, no hidden steps). |
| PB-015 | Optional Examples Pack | examples | Static text | optional | secret | If examples exist, they may contain sensitive internal patterns; publish hashes only. |

---

## A3) Deterministic assembly rules

### A3.1 Full inputs (must be complete to claim determinism)
The C1 Prompt Compiler’s PromptBundle output is deterministic **iff** it is a pure function of the following inputs (and nothing else):

1) LockedSpec bytes (schema-valid JSON)
- `LockedSpec.json` as exact bytes referenced by the run (see `../../schemas/LockedSpec.schema.json`).

2) Tier pack defaults
- `../../tiers/tier-packs.json` as exact bytes at the evaluated repo revision.

3) Block registry metadata (this file)
- `../templates/PromptBundle.blocks.md` as exact bytes.

4) Block content bytes for each selected block
- The literal bytes of each block’s content as stored by the build system (even if those bytes are not published).

5) Compiler identity
- `compiler_id` and `compiler_version` MUST be recorded in the `policy_report` artifact payload (see A5).

If any additional inputs affect assembly (environment variables, timestamps, model outputs), the run is **NO-GO** for “deterministic compiler” claims.

### A3.2 Deterministic selection (no model discretion)
Compute `tier_id = LockedSpec.tier.tier_id`.

Selection function `selected_blocks(tier_id)`:
- Always include: PB-001, PB-002, PB-003, PB-004, PB-005, PB-006, PB-007, PB-008, PB-012, PB-013, PB-014.
- If `tier_id` is one of `tier-1`, `tier-2`, `tier-3`, additionally include: PB-009, PB-010, PB-011.
- Optional blocks (e.g., PB-015) MUST NOT be included unless the compiler invocation includes an explicit, recorded flag (see A5) that deterministically selects them.

If `tier_id` is unknown or unsupported, C1 must fail and the run must be **NO-GO** at Gate Q (see `../../gates/GATE_Q.md` Q7).

### A3.3 Explicit block ordering key (no discretion)
Ordering is fixed by ascending `block_id` numeric suffix (e.g., PB-001 before PB-010).

For a selected set S:
1) Sort S by `block_id` using numeric order on the three-digit suffix.
2) Concatenate block contents with a single separator:

`"\n\n---\n\n"`

No other separators are permitted.

### A3.4 Canonical PromptBundle hash
Define `sha256_hex(bytes)` as lowercase hex SHA-256 digest.

For each block `b` in sorted selected set S:
- `block_hash[b] = sha256_hex(block_content_bytes[b])`

Define the **PromptBundle input manifest bytes** (UTF-8, LF line endings) as the exact concatenation of lines:

`<block_id> <block_hash>\n`

for each selected block in sorted order.

Define two hashes (both REQUIRED):

a) `prompt_bundle_manifest_hash = sha256_hex(manifest_bytes)`

b) `prompt_bundle_bytes_hash = sha256_hex(prompt_bundle_bytes)`

Where `prompt_bundle_bytes` are the literal bytes of the assembled PromptBundle produced by concatenating block contents per A3.3.

Determinism requirements:
- Recomputing `block_hash[*]` from block bytes MUST yield the same `prompt_bundle_manifest_hash`.
- Assembling blocks per A3.2/A3.3 MUST yield the same `prompt_bundle_bytes_hash`.
- Both hashes MUST be recorded in the `policy_report` artifact payload (see A5).

---

## A4) Public release redaction policy

Publication posture (aligned to `../../CANONICALS.md#publication-posture`):

MUST publish:
- The block registry metadata table (A2): block IDs, names, types, inclusion rules, and sensitivity labels.
- The deterministic selection rules (A3.2) and ordering rules (A3.3).
- Content hashes for every block that exists in the registry (including internal/secret blocks).

MAY withhold (redact) from public release:
- The literal bytes of any block whose `sensitivity` is `internal` or `secret`.

Integrity without disclosure:
- Even when block content is redacted, publish:
  - `block_id`
  - `block_hash` (SHA-256 of the block bytes)
  - the final `prompt_bundle_manifest_hash`
  - the final `prompt_bundle_bytes_hash`

Prohibited:
- Publishing bypass-oriented rule details (e.g., exploit signatures, allowlists/denylists, regex logic, thresholds) in any block content marked for public release.

---

## A5) Evidence hooks (no new schema fields)

### A5.1 Required evidence artifact (policy_report)
C1 MUST produce an evidence artifact whose bytes contain, at minimum:
- selected `block_ids` (in order)
- `block_hashes` for each selected block
- `prompt_bundle_manifest_hash`
- `prompt_bundle_bytes_hash`
- the compiler identity used to compute it (`compiler_id`, `compiler_version`)
- a pointer to the LockedSpec used (e.g., `LockedSpec.run_id` and the LockedSpec ObjectRef if available)

This artifact MUST be referenced in `EvidenceManifest.artifacts[]` using existing schema fields only:
- `kind`: `"policy_report"` (enum in `../../schemas/EvidenceManifest.schema.json`)
- `id`: recommended `"policy.prompt_bundle"`
- `hash`: SHA-256 of the artifact bytes
- `media_type`: recommended `"application/json"` (or `"text/markdown"` if human-readable)
- `storage_ref`: opaque location string
- `produced_by`: `"C1"`

### A5.2 Relationship to LockedSpec.prompt_bundle_ref
- The assembled PromptBundle bytes (even if unpublished) MUST be stored as an object and referenced by `LockedSpec.prompt_bundle_ref` (ObjectRef).
- The `policy.prompt_bundle` policy_report is the **public-safe disclosure surface**: it proves which block IDs/hashes were used without disclosing secret content.

### A5.3 Gate R verification expectations (evidence obligations, not heuristics)
Gate R does not parse prompt content. It verifies deterministically via evidence obligations and schema contracts, including:
- Evidence sufficiency: required evidence kinds exist for the tier (`../../gates/GATE_R.md` §4).
- Schema validation and run_id consistency (`../../gates/GATE_R.md` R4).

If a run claims deterministic prompt compilation, but the EvidenceManifest lacks `policy.prompt_bundle` as a `policy_report`, the run MUST be treated as **NO-GO** for the deterministic prompt compilation claim (policy-level), even if other evidence suffices for code verification.

---

## A6) Failure modes + remediation (public-safe)

This section defines deterministic, public-safe failure conditions for PromptBundle assembly. It does not disclose any bypass-oriented prompt content.

### FM-PB-001 — Unknown or unsupported tier_id
- Condition: `LockedSpec.tier.tier_id` is not one of `tier-0`..`tier-3`.
- Outcome: **NO-GO** at Gate Q (see `../../gates/GATE_Q.md` Q7).
- Remediation: select a supported tier_id and re-run Gate Q.

### FM-PB-002 — Missing prompt bundle integrity evidence
- Condition: EvidenceManifest does not include a `policy_report` artifact with `id == "policy.prompt_bundle"`.
- Outcome: **NO-GO** for reproducibility posture (policy-level).
- Remediation: have C1 emit the policy report containing `block_ids`, `block_hashes`, `prompt_bundle_manifest_hash`, `prompt_bundle_bytes_hash`, and `compiler_id`/`compiler_version`, then re-run C1/Q.

### FM-PB-003 — Non-deterministic selection or ordering
- Condition: selected blocks differ from A3.2 for the same `tier_id`, or ordering differs from A3.3.
- Outcome: **NO-GO** for deterministic compiler claims.
- Remediation: fix C1 selection/ordering implementation and re-run C1/Q.

### FM-PB-004 — Hash mismatch between declared and produced artifacts
- Condition: `LockedSpec.prompt_bundle_ref.hash` does not match the SHA-256 of the stored PromptBundle bytes (i.e., `prompt_bundle_bytes_hash`), or the `policy.prompt_bundle` payload’s `prompt_bundle_manifest_hash` does not match the recomputed value from declared block hashes.
- Outcome: **NO-GO** (integrity / determinism failure).
- Remediation: rebuild PromptBundle from blocks deterministically and re-emit ObjectRefs and evidence.

### FM-PB-005 — Forbidden disclosure in public outputs
- Condition: any published block content includes bypass-oriented rule details (signatures, patterns, allowlists/denylists, regexes, thresholds).
- Outcome: **NO-GO** for publication posture.
- Remediation: redact the content, publish only metadata + hashes, and re-run C1/Q.
