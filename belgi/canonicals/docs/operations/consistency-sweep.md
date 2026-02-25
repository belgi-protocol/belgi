# Consistency Sweep

DEFAULT: **NO-GO** unless every invariant below has an explicit deterministic check procedure. Evidence pointers are required in the generated Sweep Report for every PASS invariant result (see Section D).

This document is the operator-facing, checkable **cross-file invariants stabilization** spec for BELGI.

## A) Sweep Overview

### What a sweep is
A consistency sweep is a deterministic review pass that verifies **cross-file invariants** remain aligned across:
- Canonicals (single source of truth for definitions)
- Gates (executable verification specs)
- Schemas (strict JSON contracts)
- Manuals/runbooks (operator procedures)
- Templates (evidence-producing compilers)

A sweep does **not** “interpret intent” or “decide policy.” It checks that:
- Every referenced term/ID/kind exists and matches its source of truth.
- Every contract is checkable (deterministic procedures exist).
- Evidence obligations are satisfiable using existing schema fields (no implicit schema extensions).

### When the sweep runs
Run this sweep:
- **Before producing a closure pack** (especially when editing canonicals, gates, schemas, templates, or manuals)
- **Before release / publication**

Canonical trigger:
- CANONICALS.md#propagation-consistency-sweep: “Whenever canonicals, templates, or manuals change, a propagation/consistency sweep MUST be performed across all of them…”

### Inputs (authoritative, read-only)
- CANONICALS.md
- README.md
- CHANGELOG.md
- VERSION
- terminology.md
- trust-model.md
- gates/GATE_Q.md
- gates/GATE_R.md
- gates/failure-taxonomy.md
- .github/workflows/ci.yml
- tiers/tier-packs.json
- tiers/tier-packs.template.md
- tiers/tier-packs.md (generated view, MUST match canonical)
- wrapper/gate_Q.py
- wrapper/gate_R.py
- wrapper/comp_C1.py
- wrapper/comp_C3.py
- wrapper/seal_S.py
- chain/gate_q_verify.py
- chain/gate_r_verify.py
- chain/gate_s_verify.py
- chain/seal_bundle.py
- chain/compiler_c3_docs.py
- tools/normalize.py
- tools/rehash.py
- tools/render.py
- tools/sweep.py
- policy/fixtures/public/gate_q/cases.json
- policy/fixtures/public/gate_r/cases.json
- belgi/templates/IntentSpec.core.template.md
- schemas/IntentSpec.schema.json
- docs/research/experiment-design.md
- docs/operations/running-belgi.md
- docs/operations/evidence-bundles.md
- docs/operations/waivers.md
- docs/operations/security.md
- belgi/templates/PromptBundle.blocks.md
- belgi/templates/DocsCompiler.template.md
- schemas/*.schema.json
- schemas/README.md
- chain/logic/r_checks/context.py
- chain/logic/r_checks/registry.py
- chain/logic/r_checks/r0_evidence_sufficiency.py
- chain/logic/r_checks/r_doc_001_doc_impact.py
- chain/logic/r_checks/r4_schema_contract.py

### Output of the sweep
- A completed **Sweep Report** (Section D) with:
  - PASS/FAIL for each invariant_id
  - Evidence pointer(s) for PASS
  - One-sentence remediation for FAIL

---

## B) Invariant Catalog (REQUIRED)

**Conventions used in this catalog**
- Evidence kinds are values from EvidenceManifest.schema.json `artifacts[].kind`:
  - `diff`, `test_report`, `command_log`, `env_attestation`, `policy_report`, `schema_validation`, `docs_compilation_log`, `hotl_approval`, `seal_manifest`, `genesis_seal`
- “Schema artifacts” are schema-valid JSON documents:
  - `LockedSpec.json` (LockedSpec.schema.json)
  - `GateVerdict.json` (GateVerdict.schema.json)
  - `EvidenceManifest.json` (EvidenceManifest.schema.json)
  - `SealManifest.json` (SealManifest.schema.json)
  - `Waiver.json` (Waiver.schema.json)

### 1) Canonical semantics invariants
#### CS-CAN-001 — Terminology is pointers-only
- invariant_id: CS-CAN-001
- statement: terminology.md MUST NOT define or redefine canonical terms; it MUST only point to CANONICALS.md anchors.
- source-of-truth (file/section):
  - terminology.md#0-rule-of-use-canonical-pointer
  - CANONICALS.md#anchor-registry-stable-ids
- check procedure (deterministic):
  1) Confirm terminology.md contains the Rule of Use statement: “MUST NOT define or redefine terms.”
  2) Confirm every entry in terminology.md “Term Map” links to CANONICALS.md#<anchor>.
  3) Confirm terminology.md contains no sections that introduce new normative definitions.
  Filter scope:
  - Exclude table rows: any line that starts with `|`.
  - Exclude fenced code blocks: toggle exclusion when a line starts with ``` (any language tag allowed); stop excluding when the line is exactly ```.
  Reject if any remaining non-excluded line matches the case-insensitive regex:
  `^\s*[^\n]{1,120}\s+is\s+(a|an|the)\s+[^\n]{1,200}\.?\s*$`
- required evidence/artifacts (schema kinds): none (repo-doc sweep)
- pass/fail criteria:
  - PASS if steps 1–2 succeed and step 3 finds no matches.
  - FAIL otherwise.

#### CS-CAN-004 — No duplicate non-canonical spec trees
- invariant_id: CS-CAN-004
- statement: There MUST be exactly one canonical copy of each gate/schema/tier spec file. Non-canonical duplicates under `belgi/gates/` and `belgi/schemas/` MUST NOT exist.
- source-of-truth (file/section):
  - Canonical tree decision (operator rule): repo-root `gates/`, `schemas/`, `tiers/`; under `belgi/` only `docs/operations/`, `belgi/templates/`, `docs/research/` are canonical.
- check procedure (deterministic):
  1) FAIL if any file exists under `belgi/gates/`.
  2) FAIL if any file exists under `belgi/schemas/`.
  3) PASS otherwise.
- required evidence/artifacts (schema kinds): none (repo-doc sweep)
- pass/fail criteria:
  - PASS if steps 1–3 pass.
  - FAIL otherwise.

#### CS-CAN-002 — Canonical chain matches everywhere
- invariant_id: CS-CAN-002
- statement: The canonical chain MUST be exactly `P → C1 → Q → C2 → R → C3 → S` wherever stated.
- source-of-truth (file/section):
  - CANONICALS.md#2-canonical-chain-canonical
  - docs/operations/running-belgi.md#1-overview-what-happens-in-p--c1--q--c2--r--c3--s
- check procedure (deterministic):
  1) Search these files for the chain string.
  2) Confirm all occurrences match the exact stage order and labels.
- required evidence/artifacts (schema kinds): none (repo-doc sweep)
- pass/fail criteria:
  - PASS if all occurrences match.
  - FAIL if any file claims a different order or stage set.

#### CS-CAN-003 — Publication posture is enforced in public-safe docs
- invariant_id: CS-CAN-003
- statement: Public-safe docs MUST prohibit bypass-oriented specifics and allow only category-level descriptions.
- source-of-truth (file/section):
  - CANONICALS.md#publication-posture
  - docs/operations/security.md (preamble + §3)
- check procedure (deterministic):
  1) Confirm CANONICALS.md#publication-posture contains the prohibition on “exploit signatures, evasion thresholds… only categories.”
  2) Confirm docs/operations/security.md contains the exact substring: `It MUST NOT include exploit signatures, detection regexes, secret allowlists, or bypass-oriented thresholds.`
  3) Confirm templates reiterate public-safe constraints:
     - belgi/templates/PromptBundle.blocks.md#A4-public-release-redaction-policy
     - belgi/templates/DocsCompiler.template.md (B3.1 “Prohibited non-determinism” and checklist “No bypass-friendly…”) 
- required evidence/artifacts (schema kinds): none (repo-doc sweep)
- pass/fail criteria:
  - PASS if all confirmations hold.
  - FAIL if any public-safe doc includes bypass-oriented rule details or lacks the prohibition.

#### CS-TERM-001 — Terminology Drift Guard (Verification vs Validation)
- invariant_id: CS-TERM-001
- statement: Public/normative docs MUST keep BELGI umbrella language as **verification**; `validation` terms are reserved for mechanical conformance only.
- source-of-truth (file/section):
  - CANONICALS.md#bounded-claim
  - CANONICALS.md#terminology-boundaries
- check procedure (deterministic):
  1) Enumerate tracked files in this sweep scope:
     - `README.md`, `CANONICALS.md`, `WHITEPAPER.md`, `terminology.md`, `trust-model.md`
     - `docs/**/*.md`
     - `gates/**/*.md`
     - `tiers/**/*.md`
     - `schemas/README.md`
     - `belgi/_protocol_packs/v1/gates/**/*.md`
     - `belgi/_protocol_packs/v1/tiers/**/*.md`
     - `belgi/_protocol_packs/v1/schemas/README.md`
  2) Scan in deterministic order (path asc, line asc).
  3) FAIL if any line contains:
     - `deterministic validation`
     - `validation posture`
     - `probabilistic execution`
  4) For tokens `validation|validate|validated`, FAIL unless the same line contains one of the allowed mechanical contexts:
     - `schema` or `schema_validation` or `.schema.json`
     - `format validation`
     - `parse validation`
     - `input validation`
- required evidence/artifacts (schema kinds): none (repo-doc sweep)
- pass/fail criteria:
  - PASS if all checks above hold.
  - FAIL with deterministic, sorted `file:line` entries and remediation pointing to canonical boundaries.

### 2) Gate-schema invariants

#### CS-GS-001 — GateVerdict GO/NO-GO semantics match schema and gate specs
- invariant_id: CS-GS-001
- statement: GO/NO-GO semantics described in gate docs MUST match GateVerdict.schema.json conditional requirements.
- source-of-truth (file/section):
  - schemas/GateVerdict.schema.json (allOf conditions)
  - gates/GATE_Q.md#3-outputs-required (GO/NO-GO semantics)
  - gates/GATE_R.md#31-go--no-go-semantics-schema-enforced
- check procedure (deterministic):
  1) Verify the schema requires:
     - GO => `failure_category == null`, `failures == []`, and `remediation` absent.
     - NO-GO => `failure_category` non-null, `failures` non-empty, and `remediation.next_instruction` required.
  2) Confirm Gate Q and Gate R docs restate the same constraints.
- required evidence/artifacts (schema kinds): GateVerdict.json
- pass/fail criteria:
  - PASS if docs and schema agree.
  - FAIL if docs allow a state forbidden by schema, or schema allows a state forbidden by docs.

#### CS-GS-002 — Remediation instruction format is consistent
- invariant_id: CS-GS-002
- statement: Any NO-GO remediation instruction MUST match the fixed machine-parseable format in CANONICALS + GateVerdict schema + failure taxonomy.
- source-of-truth (file/section):
  - CANONICALS.md#failure-taxonomy-interface
  - schemas/GateVerdict.schema.json (remediation.next_instruction pattern)
  - gates/failure-taxonomy.md#11-remediation-string-constraints-schema-aligned
- check procedure (deterministic):
  1) Confirm GateVerdict schema regex: `^Do .+ then re-run (Q|R)\.$`.
  2) Confirm failure-taxonomy.md restates “start with Do” and “end with then re-run Q./R.”
  3) Confirm gate docs’ remediation templates end in “then re-run Q.” or “then re-run R.”
- required evidence/artifacts (schema kinds): GateVerdict.json
- pass/fail criteria:
  - PASS if all three sources align.
  - FAIL if any source contradicts the format.

#### CS-GS-003 — Failure category tokens used by gates exist in failure taxonomy
- invariant_id: CS-GS-003
- statement: All failure category tokens referenced by Gate Q/R MUST be defined in gates/failure-taxonomy.md.
- source-of-truth (file/section):
  - gates/failure-taxonomy.md#1-category-ids-stable
- check procedure (deterministic):
  1) Extract all failure category tokens from gates/GATE_Q.md and gates/GATE_R.md using the case-sensitive regex: `\bF(Q|R)-[A-Z0-9-]+\b`.
  2) Extract taxonomy tokens from gates/failure-taxonomy.md using the regex: ``category_id:\s*`([^`]+)` ``.
  3) Confirm every extracted gate token is present in the extracted taxonomy token set.
- required evidence/artifacts (schema kinds): GateVerdict.json
- pass/fail criteria:
  - PASS if every referenced token is defined.
  - FAIL if any token is missing or mismatched.

#### CS-GS-004 — doc_impact contract is schema- and gate-consistent
- invariant_id: CS-GS-004
- statement: LockedSpec `doc_impact` MUST exist in schema and MUST match gate semantics for Tier 2–3, including the “note-on-empty” rule.
- source-of-truth (file/section):
  - schemas/LockedSpec.schema.json (doc_impact + tier-2/3 requirement)
  - gates/GATE_Q.md#5-deterministic-checks-executable-doc (Q-DOC-001, Q-DOC-002)
  - gates/GATE_R.md#5-deterministic-checks-executable-doc (R-DOC-001)
- check procedure (deterministic):
  1) Confirm schemas/LockedSpec.schema.json defines `doc_impact` as an object with:
     - `required_paths` present (may be empty `[]`)
     - `note_on_empty` present and non-empty when `required_paths` is `[]`
  2) Confirm schemas/LockedSpec.schema.json requires `doc_impact` for tier-2 and tier-3 (tier-0/1 optional).
  3) Confirm Gate Q includes `Q-DOC-001` (format validation) and `Q-DOC-002` (tier enforcement + note-on-empty).
  4) Confirm Gate R includes `R-DOC-001` enforcing that for non-empty `required_paths`, at least one declared required path is touched in the evaluated diff, and that empty `required_paths` passes only with non-empty `note_on_empty`.
- required evidence/artifacts (schema kinds): LockedSpec.json; GateVerdict.json (Q); GateVerdict.json (R)
- pass/fail criteria:
  - PASS if steps 1–4 agree on the same semantics and check IDs.
  - FAIL if schema permits a state that gates forbid, or gates require a state schema cannot represent.

#### CS-GS-005 — No spec fiction: doc_impact claimed implies schema field exists
- invariant_id: CS-GS-005
- statement: If any gate doc or tier pack claims `LockedSpec.doc_impact` exists or is enforced, then schemas/LockedSpec.schema.json MUST define `doc_impact`.
- source-of-truth (file/section):
  - schemas/LockedSpec.schema.json#/properties/doc_impact
  - gates/GATE_Q.md (doc_impact references)
  - gates/GATE_R.md (doc_impact references)
  - tiers/tier-packs.json (canonical SSOT; generated view: tiers/tier-packs.md#27-doc_impact_required)
- check procedure (deterministic):
  1) Search these files for the literal token `doc_impact`:
     - gates/GATE_Q.md
     - gates/GATE_R.md
     - tiers/tier-packs.json
      - tiers/tier-packs.md (generated view)
  2) If none of the four files contain `doc_impact`: PASS this invariant.
  3) If any of the four files contain `doc_impact`: FAIL unless schemas/LockedSpec.schema.json contains a top-level `properties.doc_impact` definition.
- required evidence/artifacts (schema kinds): none (repo-doc sweep)
- pass/fail criteria:
  - PASS if the implication holds.
  - FAIL otherwise.

#### CS-IS-001 — IntentSpec core template is machine-parseable and field-complete
- invariant_id: CS-IS-001
- statement: IntentSpec.core.md MUST be representable as a single fenced YAML block (the only machine-parsed section) containing all core fields required by the IntentSpec schema.
- source-of-truth (file/section):
  - belgi/templates/IntentSpec.core.template.md
  - schemas/IntentSpec.schema.json
- check procedure (deterministic):
  1) Confirm belgi/templates/IntentSpec.core.template.md contains exactly one fenced YAML block (```yaml ... ```).
  2) Confirm the YAML block includes the core keys: `intent_id`, `title`, `goal`, `scope`, `acceptance`, `tier`, `doc_impact`.
  3) Confirm there is no second ```yaml block in the file.
- required evidence/artifacts (schema kinds): none (repo-doc sweep)
- pass/fail criteria:
  - PASS if steps 1–3 hold.
  - FAIL otherwise.

#### CS-IS-002 — IntentSpec schema matches required fields and note-on-empty rule
- invariant_id: CS-IS-002
- statement: schemas/IntentSpec.schema.json MUST validate the IntentSpec core YAML object and MUST enforce the note-on-empty rule for doc_impact.
- source-of-truth (file/section):
  - schemas/IntentSpec.schema.json
- check procedure (deterministic):
  1) Confirm schema requires the core fields: `intent_id`, `title`, `goal`, `scope`, `acceptance`, `tier`, `doc_impact`.
  2) Confirm schema enforces: if `doc_impact.required_paths` is `[]`, then `doc_impact.note_on_empty` is required and non-empty.
  3) Confirm schema forbids wildcards in path fields via pattern and/or explicit description (`*`, `?`).
- required evidence/artifacts (schema kinds): none (repo-doc sweep)
- pass/fail criteria:
  - PASS if steps 1–3 hold.
  - FAIL otherwise.

#### CS-IS-003 — Gate Q enforces IntentSpec parse/schema-validate/compile deterministically
- invariant_id: CS-IS-003
- statement: Gate Q MUST define deterministic checks for IntentSpec presence/parseability, schema validation, and deterministic compilation into LockedSpec inputs, without inventing new LockedSpec fields.
- source-of-truth (file/section):
  - gates/GATE_Q.md (Q-INTENT-001, Q-INTENT-002, Q-INTENT-003)
  - schemas/IntentSpec.schema.json
  - schemas/LockedSpec.schema.json
- check procedure (deterministic):
  1) Confirm Gate Q includes check IDs `Q-INTENT-001`, `Q-INTENT-002`, `Q-INTENT-003`.
  2) Confirm Q-INTENT-001 requires exactly one fenced YAML block and parse failure is NO-GO.
  3) Confirm Q-INTENT-002 validates the parsed object against schemas/IntentSpec.schema.json.
  4) Confirm Q-INTENT-003 specifies explicit field mappings into existing LockedSpec fields and references schemas/LockedSpec.schema.json.
  5) Confirm Gate Q aligns tier semantics with tier-packs `doc_impact_required` (presence required vs non-empty paths).
- required evidence/artifacts (schema kinds): LockedSpec.json; GateVerdict.json (Q)
- pass/fail criteria:
  - PASS if steps 1–5 hold.
  - FAIL otherwise.

#### CS-IS-004 — IntentSpec is consistently referenced across gates, schemas docs, runbook, and templates (NEW)
- invariant_id: CS-IS-004
- statement: IntentSpec MUST be referenced with consistent canonical filenames/paths across Gate Q, the operator runbook, schemas documentation, and the core template.
- source-of-truth (file/section):
  - belgi/templates/IntentSpec.core.template.md (canonical template filename)
  - schemas/IntentSpec.schema.json (canonical schema filename)
  - gates/GATE_Q.md (IntentSpec input and checks)
  - docs/operations/running-belgi.md (operator inputs)
  - schemas/README.md (schema docs index/explanation)
- check procedure (deterministic):
  1) Confirm gates/GATE_Q.md references BOTH:
     - belgi/templates/IntentSpec.core.template.md
     - schemas/IntentSpec.schema.json
  2) Confirm docs/operations/running-belgi.md references BOTH:
     - belgi/templates/IntentSpec.core.template.md
     - schemas/IntentSpec.schema.json
     and states the input artifact name exactly as `IntentSpec.core.md`.
  3) Confirm schemas/README.md includes IntentSpec.schema.json in its Index and explains that it validates the machine-parsed YAML from `IntentSpec.core.md`.
  4) Confirm belgi/templates/IntentSpec.core.template.md contains exactly one fenced YAML block and includes `doc_impact` with the note-on-empty rule described.
- required evidence/artifacts (schema kinds): none (repo-doc sweep)
- pass/fail criteria:
  - PASS if steps 1–4 hold.
  - FAIL otherwise.

### 3) Evidence bundle invariants

#### CS-EV-001 — Evidence kind enum is the single allowed vocabulary
- invariant_id: CS-EV-001
- statement: Every evidence kind referenced by gates/manuals/templates MUST exist in EvidenceManifest.schema.json `artifacts[].kind` enum, and no doc may invent new kinds.
- source-of-truth (file/section):
  - schemas/EvidenceManifest.schema.json (artifacts[].kind enum)
  - docs/operations/evidence-bundles.md#21-allowed-evidence-kinds-schema-enum
  - tiers/tier-packs.json (canonical SSOT; generated view: tiers/tier-packs.md#21-required_evidence_kinds)
  - docs/operations/running-belgi.md#consistency-sweep
  - belgi/templates/DocsCompiler.template.md#consistency-sweep-checklist-mandatory
- check procedure (deterministic):
  1) Record the schema enum set from EvidenceManifest.schema.json.
  2) Search the authoritative docs for backticked evidence kind tokens.
  3) Confirm the doc set is a subset of the schema enum set.
- required evidence/artifacts (schema kinds): EvidenceManifest.json
- pass/fail criteria:
  - PASS if no doc references a non-enum kind.
  - FAIL if any doc references a kind not in the enum.

#### CS-EV-002 — Gate Q minimum required evidence kinds are consistent
- invariant_id: CS-EV-002
- statement: Gate Q MUST require (at minimum) `command_log`, `policy_report`, and `schema_validation`, and these must be representable as EvidenceManifest artifacts.
- source-of-truth (file/section):
  - gates/GATE_Q.md#33-evidencemanifest-reference
- check procedure (deterministic):
  1) Confirm gates/GATE_Q.md lists the minimum required evidence kinds at Q.
  2) Confirm those kinds exist in EvidenceManifest.schema.json enum.
- required evidence/artifacts (schema kinds): EvidenceManifest.json; evidence kinds: command_log, policy_report, schema_validation
- pass/fail criteria:
  - PASS if the set matches and is schema-supported.
  - FAIL otherwise.

#### CS-EV-003 — Gate R evidence sufficiency rule is tier-driven
- invariant_id: CS-EV-003
- statement: Gate R MUST implement the deterministic evidence sufficiency rule by comparing the tier’s `required_evidence_kinds` to EvidenceManifest `artifacts[].kind`.
- source-of-truth (file/section):
  - gates/GATE_R.md#4-evidence-sufficiency-rule-deterministic
  - tiers/tier-packs.json (canonical SSOT; generated view: tiers/tier-packs.md#21-required_evidence_kinds)
- check procedure (deterministic):
  1) Confirm Gate R describes the 4-step procedure using tier required_evidence_kinds.
  2) Confirm tier-packs defines required_evidence_kinds per tier.
- required evidence/artifacts (schema kinds): LockedSpec.json; EvidenceManifest.json
- pass/fail criteria:
  - PASS if procedures and parameter sources align.
  - FAIL if Gate R requires evidence in a way not derived from tier-packs.

#### CS-EV-004 — Post-R evidence must be append-only and preserve the R-snapshot
- invariant_id: CS-EV-004
- statement: Evidence added after Gate R (e.g., by C3) MUST be recorded via an append-only extension of the R-Snapshot EvidenceManifest; R-Snapshot must remain immutable.
- source-of-truth (file/section):
  - docs/operations/evidence-bundles.md#evidence-mutability-r-snapshot-and-replay-integrity-normative
  - docs/operations/running-belgi.md (Step 4 and Step 5 “R-Snapshot / Final EvidenceManifest integrity”)
  - belgi/templates/DocsCompiler.template.md#b5-verification-expectations-gate-r--replay
- check procedure (deterministic):
  1) Confirm evidence-bundles.md defines the R-Snapshot and Final EvidenceManifest and the “append-only extension” rule.
  2) Confirm running-belgi.md reiterates immutability + append-only extension requirement.
  3) Confirm DocsCompiler.template.md states post-R evidence is append-only and does not affect Gate R.
- required evidence/artifacts (schema kinds): GateVerdict.json (R); EvidenceManifest.json; SealManifest.json
- pass/fail criteria:
  - PASS if all three documents agree on immutability + append-only semantics.
  - FAIL if any document suggests rewriting R-Snapshot evidence.

#### CS-EV-005 — Seal binds the core replay set (including waivers)
- invariant_id: CS-EV-005
- statement: SealManifest MUST bind LockedSpec, both gate verdicts, an EvidenceManifest, and all applied waivers (if any) via ObjectRefs.
- source-of-truth (file/section):
  - schemas/SealManifest.schema.json (required fields)
  - docs/operations/evidence-bundles.md#11-mandatory-artifacts-minimum-replay-set
  - CANONICALS.md#s-seal
  - CANONICALS.md#waivers
- check procedure (deterministic):
  1) Confirm SealManifest schema includes required ObjectRefs for locked_spec_ref, gate_q_verdict_ref, gate_r_verdict_ref, evidence_manifest_ref, and waivers[].
  2) Confirm evidence-bundles mandates SealManifest and waiver inclusion.
  3) Confirm CANONICALS requires waivers be visible in the final seal.
- required evidence/artifacts (schema kinds): SealManifest.json; Waiver.json (if any)
- pass/fail criteria:
  - PASS if schema + docs align.
  - FAIL if any required binding is missing from schema or required docs.

### 4) Tier parameter invariants

#### CS-TIER-001 — Tier IDs are consistent and bounded
- invariant_id: CS-TIER-001
- statement: The only supported tier IDs are `tier-0`, `tier-1`, `tier-2`, `tier-3` and every spec that references tiers MUST use exactly these IDs.
- source-of-truth (file/section):
  - tiers/tier-packs.json (canonical SSOT; generated view: tiers/tier-packs.md#1-tier-ids)
  - gates/GATE_Q.md#q7--tier-id-supported
  - belgi/templates/PromptBundle.blocks.md#fm-pb-001--unknown-or-unsupported-tier_id
- check procedure (deterministic):
  1) Confirm tiers/tier-packs.json defines the four tier IDs (and tiers/tier-packs.md lists them as the generated view).
  2) Confirm Gate Q Q7 enforces membership in that set.
  3) Confirm PromptBundle template treats unknown tier_id as NO-GO at Gate Q.
- required evidence/artifacts (schema kinds): LockedSpec.json
- pass/fail criteria:
  - PASS if all agree on the same supported set.
  - FAIL if any document introduces a tier outside the set.

#### CS-TIER-002 — Tier required_evidence_kinds are consistent across docs
- invariant_id: CS-TIER-002
- statement: Tier evidence requirements must match across tier-packs.json (canonical), evidence-bundles.md, and running-belgi.md.
- source-of-truth (file/section):
  - tiers/tier-packs.json (canonical SSOT; generated view: tiers/tier-packs.md#3-tier-parameter-sets)
  - docs/operations/evidence-bundles.md#22-tier-driven-minimums-gate-r-evidence-sufficiency
  - docs/operations/running-belgi.md#step-4--run-gate-r-verify
- check procedure (deterministic):
  1) For tier-0: confirm all three sources require exactly `diff`, `command_log`, `schema_validation`, `policy_report`.
  2) For tier-1..3: confirm all three sources require exactly `diff`, `command_log`, `schema_validation`, `policy_report`, `test_report`, `env_attestation`.
- required evidence/artifacts (schema kinds): LockedSpec.json; EvidenceManifest.json
- pass/fail criteria:
  - PASS if the sets match.
  - FAIL if any source deviates.

#### CS-TIER-003 — docs_compilation_log exists but is not a Gate R requirement
- invariant_id: CS-TIER-003
- statement: `docs_compilation_log` MUST exist as an allowed evidence kind, but Gate R MUST NOT require it because it is produced post-R.
- source-of-truth (file/section):
  - tiers/tier-packs.json (canonical SSOT; generated view note: tiers/tier-packs.md#21-required_evidence_kinds)
  - docs/operations/evidence-bundles.md#23-evidence-kinds-used-by-specific-gate-checks (note)
  - belgi/templates/DocsCompiler.template.md#b5-verification-expectations-gate-r--replay
- check procedure (deterministic):
  1) Confirm EvidenceManifest schema includes `docs_compilation_log` in the kind enum.
  2) Confirm tier-packs explicitly states Gate R MUST NOT require it.
  3) Confirm evidence-bundles reiterates the same boundary.
- required evidence/artifacts (schema kinds): EvidenceManifest.json
- pass/fail criteria:
  - PASS if all three align.
  - FAIL if Gate R requirements imply `docs_compilation_log` is required.

#### CS-TIER-004 — command_log_mode is enforceable with the current schema
- invariant_id: CS-TIER-004
- statement: Tier `command_log_mode` MUST be enforceable using EvidenceManifest.commands_executed, and Gate R MUST define deterministic matching rules for both modes.
- source-of-truth (file/section):
  - tiers/tier-packs.json (canonical SSOT; generated view: tiers/tier-packs.md#25-command_log_mode)
  - gates/GATE_R.md#4-evidence-sufficiency-rule-deterministic (command_log_mode enforcement)
  - gates/GATE_R.md#51-command-matching-rule-used-by-r1r5r6r7r8
  - schemas/EvidenceManifest.schema.json (commands_executed oneOf)
- check procedure (deterministic):
  1) Confirm EvidenceManifest schema allows either list-of-strings or list-of-CommandRecord.
  2) Confirm tier-packs defines mode strings vs structured.
  3) Confirm Gate R defines matching rules for both modes.
- required evidence/artifacts (schema kinds): EvidenceManifest.json
- pass/fail criteria:
  - PASS if the schema supports both shapes and Gate R defines deterministic checks for each.
  - FAIL if any tier mode cannot be represented or checked deterministically.

#### CS-TIER-005 — doc_impact_required parameter is consistent across tier-packs, gates, and runbook
- invariant_id: CS-TIER-005
- statement: The tier parameter name `doc_impact_required` and its Tier 0–3 mapping MUST be consistent across tier-packs, Gate Q/R docs, and the operator runbook.
- source-of-truth (file/section):
  - tiers/tier-packs.json (canonical SSOT; generated view: tiers/tier-packs.md#27-doc_impact_required and #3-tier-parameter-sets)
  - gates/GATE_Q.md (Q-DOC-002 reads doc_impact_required)
  - gates/GATE_R.md (R-DOC-001 reads doc_impact_required)
  - docs/operations/running-belgi.md#23-doc_impact-operator-requirement-for-tier-23
- check procedure (deterministic):
  1) Confirm tiers/tier-packs.json defines `doc_impact_required` as a boolean and sets:
     - tier-0: false
     - tier-1: false
     - tier-2: true
     - tier-3: true
  2) Confirm Gate Q `Q-DOC-002` refers to exactly `doc_impact_required` (same spelling).
  3) Confirm Gate R `R-DOC-001` refers to exactly `doc_impact_required` (same spelling).
  4) Confirm running-belgi.md states Tier 2–3 require `doc_impact` and describes the empty list + note rule.
- required evidence/artifacts (schema kinds): none (repo-doc sweep)
- pass/fail criteria:
  - PASS if all four sources agree.
  - FAIL if any source uses a different name, different tier mapping, or contradicts the enforcement semantics.

### 5) Waiver invariants (LLM-closed)

#### CS-WVR-001 — Waivers are human-controlled (LLM-closed)
- invariant_id: CS-WVR-001
- statement: Waivers MUST be human-authored and MUST NOT be created/edited/applied by the proposer (C2/LLM).
- source-of-truth (file/section):
  - CANONICALS.md#waivers
  - docs/operations/waivers.md#1-policy-principles-non-negotiable and #24-proposer-llm--forbidden
  - schemas/Waiver.schema.json (approver description)
- check procedure (deterministic):
  1) Confirm CANONICALS states “Waivers MUST NOT be created by an LLM.”
  2) Confirm waivers.md explicitly forbids C2 from waiver actions.
  3) Confirm Waiver schema requires `approver` and describes it as human identity class.
- required evidence/artifacts (schema kinds): Waiver.json; LockedSpec.json
- pass/fail criteria:
  - PASS if all three agree.
  - FAIL if any doc or schema implies waiver creation/application by C2 is allowed.

#### CS-WVR-002 — Waivers are time-bounded and auditable
- invariant_id: CS-WVR-002
- statement: A waiver MUST be time-bounded (`expires_at`) and auditable (`audit_trail_ref`), and gates MUST enforce these properties deterministically.
- source-of-truth (file/section):
  - CANONICALS.md#waivers (expiry + audit trail)
  - schemas/Waiver.schema.json (required fields)
  - gates/GATE_Q.md#q6--waivers-validity-if-present
  - docs/operations/waivers.md#34-apply-to-a-run-lockedspecwaivers_applied
- check procedure (deterministic):
  1) Confirm Waiver schema requires `expires_at` and `audit_trail_ref`.
  2) Confirm Gate Q Q6 requires `status == "active"` and `expires_at` after Q evaluated_at.
  3) Confirm waivers.md lists the same required fields and enforcement point.
- required evidence/artifacts (schema kinds): Waiver.json; GateVerdict.json (Q); EvidenceManifest.json (schema_validation)
- pass/fail criteria:
  - PASS if schema requires the fields and gate docs enforce them.
  - FAIL otherwise.

#### CS-WVR-003 — Tier waiver policy is consistent and enforced
- invariant_id: CS-WVR-003
- statement: Tier waiver allowances/limits MUST match tier-packs and be enforced by Gate Q (and used by Gate R where applicable).
- source-of-truth (file/section):
  - tiers/tier-packs.json (canonical SSOT; generated view: tiers/tier-packs.md#24-waiver_policy and #3-tier-parameter-sets)
  - gates/GATE_Q.md#q6--waivers-validity-if-present
  - docs/operations/waivers.md#51-limits-per-tier
- check procedure (deterministic):
  1) Confirm tiers/tier-packs.json defines `waiver_policy.allowed` and `max_active_waivers` per tier (tier-3 disallows waivers).
  2) Confirm Gate Q Q6 references tier policy and enforces count and allowance.
  3) Confirm waivers.md repeats the same limits.
- required evidence/artifacts (schema kinds): LockedSpec.json; Waiver.json
- pass/fail criteria:
  - PASS if all three sources agree.
  - FAIL if any tier’s allowance/limit differs across sources.

#### CS-WVR-004 — Waivers are visible in sealing and replay bundles
- invariant_id: CS-WVR-004
- statement: If LockedSpec references waivers, the bundle and seal MUST include the waiver documents and SealManifest MUST reference them.
- source-of-truth (file/section):
  - docs/operations/evidence-bundles.md#11-mandatory-artifacts-minimum-replay-set
  - schemas/SealManifest.schema.json (waivers[])
  - docs/operations/waivers.md#15-waivers-must-be-visible-in-sealing
- check procedure (deterministic):
  1) Confirm evidence-bundles mandates including waiver documents when LockedSpec.waivers_applied is non-empty.
  2) Confirm SealManifest schema includes `waivers` array of ObjectRefs.
  3) Confirm waivers.md states “Waivers must be visible in sealing.”
- required evidence/artifacts (schema kinds): LockedSpec.json; SealManifest.json; Waiver.json
- pass/fail criteria:
  - PASS if all three agree.
  - FAIL otherwise.

#### CS-WVR-005 — doc_impact enforcement does not introduce a waiver bypass
- invariant_id: CS-WVR-005
- statement: doc_impact enforcement MUST NOT be waivable in v1, and this patch MUST NOT change waiver semantics or introduce a waiver-based bypass for doc_impact checks.
- source-of-truth (file/section):
  - gates/GATE_Q.md (Q-DOC-001, Q-DOC-002)
  - gates/GATE_R.md (R-DOC-001)
  - tiers/tier-packs.json (canonical SSOT; generated view: tiers/tier-packs.md#24-waiver_policy and #3-tier-parameter-sets)
- check procedure (deterministic):
  1) Confirm Q-DOC-001 and Q-DOC-002 do not reference waivers and do not contain any waiver-allowance branch.
  2) Confirm R-DOC-001 does not reference waivers and does not contain any waiver-allowance branch.
  3) Confirm tier waiver policy remains unchanged (notably: tier-3 still has `waiver_policy.allowed: no`).
- required evidence/artifacts (schema kinds): none (repo-doc sweep)
- pass/fail criteria:
  - PASS if steps 1–3 hold.
  - FAIL if any doc_impact check claims a waiver can override doc_impact enforcement or if tier waiver policy changed.

### 6) Template invariants (PromptBundle + DocsCompiler)

#### CS-TPL-001 — PromptBundle policy_report payload includes required hashes and block identifiers
- invariant_id: CS-TPL-001
- statement: The PromptBundle policy_report MUST include `block_ids` + `block_hashes` + `prompt_bundle_manifest_hash` + `prompt_bundle_bytes_hash` (and compiler identity), and MUST be representable using existing EvidenceManifest fields.
- source-of-truth (file/section):
  - belgi/templates/PromptBundle.blocks.md#A51-required-evidence-artifact-policy_report
  - belgi/templates/PromptBundle.blocks.md#A34-canonical-promptbundle-hash
  - schemas/EvidenceManifest.schema.json (kind enum includes policy_report; artifact fields)
- check procedure (deterministic):
  1) Confirm PromptBundle.blocks.md A5.1 lists the required fields.
  2) Confirm PromptBundle.blocks.md A3.4 defines the two hashes and requires recording both in policy_report.
  3) Confirm EvidenceManifest schema supports indexing the artifact without new fields (`kind`, `id`, `hash`, `media_type`, `storage_ref`, `produced_by`).
- required evidence/artifacts (schema kinds): EvidenceManifest.json; evidence kind: policy_report
- pass/fail criteria:
  - PASS if required fields are present in the template and schema supports indexing.
  - FAIL if the template references fields that cannot be represented/indexed with existing schemas.

#### CS-TPL-002 — PromptBundle integrity binds LockedSpec.prompt_bundle_ref
- invariant_id: CS-TPL-002
- statement: PromptBundle integrity MUST be checkable by comparing `LockedSpec.prompt_bundle_ref.hash` to the SHA-256 of stored PromptBundle bytes (and by recomputing the manifest hash from declared block hashes).
- source-of-truth (file/section):
  - belgi/templates/PromptBundle.blocks.md#A52-relationship-to-lockedspecprompt_bundle_ref
  - belgi/templates/PromptBundle.blocks.md#fm-pb-004--hash-mismatch-between-declared-and-produced-artifacts
  - schemas/LockedSpec.schema.json (prompt_bundle_ref ObjectRef)
- check procedure (deterministic):
  1) Resolve `LockedSpec.prompt_bundle_ref.storage_ref` to the PromptBundle bytes.
  2) Compute SHA-256 over those bytes and compare to `LockedSpec.prompt_bundle_ref.hash`.
  3) Resolve the `policy.prompt_bundle` policy_report artifact bytes and recompute `prompt_bundle_manifest_hash` from the declared block hashes (per A3.4) and compare.
- required evidence/artifacts (schema kinds): LockedSpec.json; EvidenceManifest.json; evidence kind: policy_report
- pass/fail criteria:
  - PASS if the check is fully specified and uses existing schema references.
  - FAIL if any required reference or hash is undefined.

#### CS-TPL-003 — DocsCompiler emits docs_compilation_log via existing schema fields
- invariant_id: CS-TPL-003
- statement: C3 MUST produce a `docs_compilation_log` evidence artifact and index it in EvidenceManifest.artifacts[] without requiring any schema changes.
- source-of-truth (file/section):
  - belgi/templates/DocsCompiler.template.md#b42-required-evidence-artifact-docs_compilation_log
  - schemas/EvidenceManifest.schema.json (kind enum includes docs_compilation_log; produced_by includes C3)
- check procedure (deterministic):
  1) Confirm DocsCompiler.template.md requires a docs_compilation_log artifact and specifies EvidenceManifest indexing fields.
  2) Confirm EvidenceManifest schema kind enum includes docs_compilation_log.
  3) Confirm EvidenceManifest schema produced_by enum includes C3.
- required evidence/artifacts (schema kinds): EvidenceManifest.json; evidence kind: docs_compilation_log
- pass/fail criteria:
  - PASS if schema supports indexing exactly as described.
  - FAIL otherwise.

#### CS-TPL-004 — Gate R obligations rely on existing evidence artifact indexing (no new schema fields)
- invariant_id: CS-TPL-004
- statement: Gate R’s evidence obligations MUST be satisfiable by EvidenceManifest indexing (kind + id + command log) plus local artifact resolution by `storage_ref`, without requiring any new schema fields.
- source-of-truth (file/section):
  - gates/GATE_R.md#52-policy-report-naming-convention-used-by-r1r7r8
  - gates/GATE_R.md#r1--intent-invariants-satisfied
  - gates/GATE_R.md#r7--supply-chain-changes-detected-and-accounted-for
  - gates/GATE_R.md#r8--adversarial-diff-scan-category-level
  - schemas/EvidenceManifest.schema.json (artifact fields)
- check procedure (deterministic):
  1) Confirm Gate R requires policy reports by `kind == policy_report` and specific `id` values.
  2) Confirm Gate R requires command evidence via `commands_executed` matching rules.
  3) Confirm EvidenceManifest schema supports artifact indexing fields and both command log representations.
  4) Confirm Gate R’s required report integrity rule (resolve bytes by `storage_ref`, verify `sha256(bytes)` equals declared `hash`, and validate required payload schemas) does not require any new EvidenceManifest fields.
- required evidence/artifacts (schema kinds): EvidenceManifest.json; evidence kinds: policy_report, command_log
- pass/fail criteria:
  - PASS if Gate R checks are satisfiable with existing schema fields.
  - FAIL if Gate R requires information that cannot be represented in schemas.

#### CS-TPL-005 — Docs compilation does not change verification outcomes
- invariant_id: CS-TPL-005
- statement: C3 (DocsCompiler) is post-verification and MUST NOT be required by Gate R nor change Gate R outcomes; it must only document/package what was verified.
- source-of-truth (file/section):
  - belgi/templates/DocsCompiler.template.md#b1-purpose and #b5-verification-expectations-gate-r--replay
  - CANONICALS.md#c3-docs-compiler
  - tiers/tier-packs.json (canonical SSOT; generated view note: tiers/tier-packs.md#21-required_evidence_kinds)
- check procedure (deterministic):
  1) Confirm DocsCompiler.template.md states “C3 is post-verification (after Gate R)” and “must not change verification outcomes.”
  2) Confirm tier-packs note: Gate R MUST NOT require docs_compilation_log.
  3) Confirm CANONICALS describes C3 as deterministic documentation from the verified state.
- required evidence/artifacts (schema kinds): GateVerdict.json (R); EvidenceManifest.json; evidence kind: docs_compilation_log (post-R)
- pass/fail criteria:
  - PASS if all sources agree on post-R boundary and non-interference.
  - FAIL if any source implies C3 is required for R.

#### CS-VERIFY_BUNDLE-001 — Canonical verifier entrypoint exists
- invariant_id: CS-VERIFY_BUNDLE-001
- statement: The repo MUST contain the single canonical deterministic verification entrypoint at `chain/gate_r_verify.py`.
- source-of-truth (file/section):
  - gates/GATE_R.md#522-canonical-deterministic-verifier-must
  - docs/operations/running-belgi.md#step-4--run-gate-r-verify
- check procedure (deterministic):
  1) Confirm `chain/gate_r_verify.py` exists.
- required evidence/artifacts (schema kinds): none (repo-doc sweep)
- pass/fail criteria:
  - PASS if the file exists.
  - FAIL otherwise.

#### CS-GATE_R-MANDATES-VERIFY_BUNDLE-001 — Gate R mandates canonical verifier
- invariant_id: CS-GATE_R-MANDATES-VERIFY_BUNDLE-001
- statement: Gate R MUST explicitly mandate running `chain/gate_r_verify.py` as the MUST-level enforcement mechanism for:
  - required `(kind,id)` uniqueness (must match exactly one)
  - bytes→hash verification (compute `sha256(bytes)`)
  - required report payload schema validation
- source-of-truth (file/section):
  - gates/GATE_R.md#522-canonical-deterministic-verifier-must
- check procedure (deterministic):
  1) Confirm Gate R text includes an explicit reference to `chain/gate_r_verify.py`.
  2) Confirm the Gate R text includes MUST-level clauses for uniqueness, `sha256(bytes)`, and payload schema validation.
- required evidence/artifacts (schema kinds): none (repo-doc sweep)
- pass/fail criteria:
  - PASS if Gate R mandates the verifier and the mandated obligations.
  - FAIL otherwise.

#### CS-VERIFY_BUNDLE-GATEVERDICT-BINDING-001 — GateVerdict binding is specified when used
- invariant_id: CS-VERIFY_BUNDLE-GATEVERDICT-BINDING-001
- statement: When a GateVerdict is provided for verification, Gate R MUST specify that `GateVerdict.evidence_manifest_ref` resolves under repo root and that `sha256(bytes)` matches the declared hash for the EvidenceManifest bytes used by Gate R.
- source-of-truth (file/section):
  - gates/GATE_R.md#522-canonical-deterministic-verifier-must
- check procedure (deterministic):
  1) Confirm Gate R includes the optional binding requirement text for `GateVerdict.evidence_manifest_ref`.
- required evidence/artifacts (schema kinds): none (repo-doc sweep)
- pass/fail criteria:
  - PASS if the binding requirement is explicitly stated.
  - FAIL otherwise.

## B.7) Orchestration invariants (sweep tooling)

These invariants anchor the protocol’s "Mechanical Truth" posture in the orchestration layer.

### CS-BYTE-001 — Byte Integrity (Byte Guard)
- invariant_id: CS-BYTE-001
- statement: Repository text bytes MUST be normalized such that `tools/normalize.py --check` returns exit code 0.
- source-of-truth (file/section):
  - tools/normalize.py (Project Byte Guard)
- check procedure (deterministic):
  1) Run `python -m tools.normalize --check --tracked-only`.
  2) FAIL if the command exits non-zero.
- required evidence/artifacts (schema kinds): policy_report (policy.consistency_sweep) MUST record PASS/FAIL.
- pass/fail criteria:
  - PASS if normalize --check exits 0.
  - FAIL otherwise.

### CS-EV-006 — Manifest Completeness (Tier>=1)
- invariant_id: CS-EV-006
- statement: Any EvidenceManifest associated with a Tier 1+ PASS case MUST index the sweep policy report (`policy.consistency_sweep`) as a `policy_report` artifact.
- source-of-truth (file/section):
  - docs/operations/consistency-sweep.md#d11-evidence-pointer-format-mechanically-checkable
  - docs/operations/consistency-sweep.md#d12-sweep-report-artifact-mandatory-machine-readable
- check procedure (deterministic):
  1) Enumerate governed public Gate R fixtures from `policy/fixtures/public/gate_r/cases.json`.
  2) For each case with `expected_exit_code == 0`:
     - Load `LockedSpec.json` and read `tier.tier_id`.
     - If `tier_id` is `tier-1`, `tier-2`, or `tier-3`, then the case’s `EvidenceManifest.json` MUST include exactly one artifact entry with:
       - `kind: "policy_report"`
       - `id: "policy.consistency_sweep"`
       - `storage_ref: "policy/consistency_sweep.json"`
       - `hash` equal to the sweep artifact hash.
  3) FAIL on any missing/ambiguous entry or hash mismatch.
- required evidence/artifacts (schema kinds): EvidenceManifest.json; LockedSpec.json
- pass/fail criteria:
  - PASS if every Tier>=1 PASS case’s EvidenceManifest indexes `policy.consistency_sweep` correctly.
  - FAIL otherwise.

Implementation note (deterministic fixed-point):
- On PASS, the CS-EV-006 result SHOULD omit `details` to avoid self-referential hash drift.

Operational convenience (deterministic, optional):
- Bootstrap note (canonical, deterministic): a first-run CS-EV-006 FAIL can be expected due to self-referential hash pinning.
- Converge deterministically with: `python -m tools.sweep consistency --repo . --fix-fixtures`.
- Fixtures MUST pin the hash printed as `SHA-256 (fixtures should declare)`.

- `python -m tools.sweep consistency --repo . --fix-fixtures` MAY be used to deterministically patch governed Gate R fixture EvidenceManifest.json files to include/update the required `policy.consistency_sweep` artifact entry.
- When `--fix-fixtures` is used, any fixture EvidenceManifest files that may be patched MUST NOT be counted as authoritative sweep inputs (to avoid `inputs[].sha256` becoming self-invalidating mid-run). The sweep MUST fail closed if a modified file overlaps the reported `inputs[].path` set.

Seal-related fixture drift note (deterministic, fail-closed):
- If `--fix-fixtures` touches any **seal-related** fixture directories (under `policy/fixtures/**/(gate_s|seal)/**` that contain a `SealManifest*.json` payload file), the sweep MUST treat any resulting SealManifest drift as **NO-GO**.
- Default behavior (no regen): the sweep runs a minimal Gate S precheck for those touched fixture dirs; on mismatch it returns exit code `2` and prints the deterministic remediation:
  - `python -m tools.sweep consistency --repo . --fix-fixtures --regen-seals`
- Remediation behavior (regen enabled): `--regen-seals` (only valid with `--fix-fixtures`) regenerates SealManifest payloads **only** for the touched seal-related fixture dirs and then immediately re-verifies them via Gate S.

Operational note (avoids CS-EV-006 “hash ping-pong”):
- The sweep report is self-referential: CS-EV-006 depends on the sweep hash, and the sweep hash depends on whether CS-EV-006 is PASS/FAIL.
- When `python -m tools.sweep consistency` prints two hashes, fixture manifests MUST copy the one labeled `SHA-256 (fixtures should declare)`.
- Once CS-EV-006 is PASS, `SHA-256 (report)` and `SHA-256 (fixtures should declare)` become equal, and the fixture hash also equals SHA-256(bytes) of `policy/consistency_sweep.json`.
- Normalization rule (deterministic): when evaluating CS-EV-006, any EvidenceManifest artifact entry with `id == policy.consistency_sweep` is treated as if its `hash` were `000...000` for purposes of computing the expected hash. If the entry is missing, it is treated as present with that zero hash. Verifier mode MUST NOT mutate fixture files.

### CS-PACK-IDENTITY-001 — Fixture protocol pack pins match builtin
- invariant_id: CS-PACK-IDENTITY-001
- statement: Every fixture `LockedSpec.json` under `policy/fixtures/**` MUST pin the active builtin protocol pack identity.
- source-of-truth (file/section):
  - `belgi/_protocol_packs/v1/ProtocolPackManifest.json` (pack_id + manifest bytes hash)
- check procedure (deterministic):
  1) Load and verify `belgi/_protocol_packs/v1/ProtocolPackManifest.json` against its pack tree.
  2) Compute `manifest_sha256 = sha256(bytes(manifest))`.
  3) Enumerate all `policy/fixtures/**/LockedSpec.json` (fail-closed on symlinks).
  4) For each LockedSpec, require `protocol_pack.pack_id == manifest.pack_id` and `protocol_pack.manifest_sha256 == manifest_sha256`.
  5) FAIL on any mismatch or missing protocol_pack.
- required evidence/artifacts (schema kinds): LockedSpec.json
- pass/fail criteria:
  - PASS if every fixture pin matches the active builtin pack.
  - FAIL otherwise.
- remediation (single-command):
  - `python -m tools.belgi fixtures sync-pack-identity --repo . --pack-dir belgi/_protocol_packs/v1`

### CS-SEAL-KEYPAIR-001 — SEAL fixture keypair + pubkey ref binding
- invariant_id: CS-SEAL-KEYPAIR-001
- statement: For every SEAL fixture under `policy/fixtures/public/seal/*`, `seal_pubkey.hex` MUST be an Ed25519 public key derived from an in-repo `seal_private_key.hex` (preferably the fixture’s own, if present), and `LockedSpec.environment_envelope.seal_pubkey_ref` MUST bind to that pubkey’s bytes hash.
- source-of-truth (file/section):
  - `policy/fixtures/public/seal/cases.json` (fixture set)
  - `chain/seal_bundle.py` (Ed25519 signing/verification)
- check procedure (deterministic):
  1) Enumerate SEAL fixture case_ids from `policy/fixtures/public/seal/cases.json`.
  2) Build a set of derived pubkeys from any present, valid `policy/fixtures/public/seal/*/seal_private_key.hex` (64 hex chars).
  3) For each fixture dir, require files:
    - `seal_pubkey.hex`
    - `LockedSpec.json`
    If `seal_private_key.hex` is present and valid, derive the Ed25519 public key bytes from it and require it matches `seal_pubkey.hex`.
    If `seal_private_key.hex` is absent, require `seal_pubkey.hex` still matches one of the derived pubkeys from step 2.
  4) Require `LockedSpec.environment_envelope.seal_pubkey_ref.storage_ref` equals `policy/fixtures/public/seal/<case_id>/seal_pubkey.hex`.
  5) Require `LockedSpec.environment_envelope.seal_pubkey_ref.hash == sha256(bytes(seal_pubkey.hex))`.
  6) FAIL on any mismatch.
- required evidence/artifacts (schema kinds): LockedSpec.json
- pass/fail criteria:
  - PASS if every SEAL fixture is internally consistent.
  - FAIL otherwise.
- remediation (single-command):
  - `python -m tools.belgi fixtures fix-all --repo . --create-missing-private-keys`

### CS-SWEEP-001 — Input Authority
- invariant_id: CS-SWEEP-001
- statement: The sweep report’s `inputs[]` list MUST reflect the authoritative current protocol surface, including the full current set of `schemas/*.schema.json` and the canonical tooling entrypoints.
- source-of-truth (file/section):
  - This document’s Inputs list (Section A)
- check procedure (deterministic):
  1) Enumerate all files matching `schemas/*.schema.json`.
  2) Confirm the sweep report includes each schema file path in `inputs[].path`.
  3) Confirm the sweep report includes tooling entrypoints `tools/normalize.py`, `tools/rehash.py`, and `tools/sweep.py`.
- required evidence/artifacts (schema kinds): policy_report (policy.consistency_sweep)
- pass/fail criteria:
  - PASS if the dynamic schema surface and tool entrypoints are included.
  - FAIL otherwise.

### CS-GV-001 — GateVerdict schema requires run_id
- invariant_id: CS-GV-001
- statement: schemas/GateVerdict.schema.json MUST require a non-empty `run_id`.
- source-of-truth (file/section):
  - schemas/GateVerdict.schema.json
- check procedure (deterministic):
  1) Confirm `run_id` is present in the top-level `required` list.
  2) Confirm `properties.run_id` is a non-empty string (`type: string`, `minLength >= 1`).
- required evidence/artifacts (schema kinds): none (repo-doc sweep)
- pass/fail criteria:
  - PASS if both checks succeed.
  - FAIL otherwise.

### CS-LS-001 — LockedSpec constraints use RepoRelPathPrefix normalization
- invariant_id: CS-LS-001
- statement: schemas/LockedSpec.schema.json MUST enforce a traversal-safe, repo-relative path prefix pattern for constraints.
- source-of-truth (file/section):
  - schemas/LockedSpec.schema.json#/$defs/RepoRelPathPrefix
- check procedure (deterministic):
  1) Confirm `constraints.allowed_paths[].items` and `constraints.forbidden_paths[].items` enforce RepoRelPathPrefix (inline or via `$ref`).
  2) Confirm RepoRelPathPrefix forbids `..` and forbids absolute / drive / backslash / wildcards (`*`, `?`) / `./` / `//`.
- required evidence/artifacts (schema kinds): none (repo-doc sweep)
- pass/fail criteria:
  - PASS if the schema patterns enforce the safety constraints.
  - FAIL otherwise.

### CS-REF-001 — ObjectRef storage_ref is constrained in schemas
- invariant_id: CS-REF-001
- statement: Every schema definition of an ObjectRef-like `storage_ref` MUST be constrained to repo-relative local paths (no absolute paths, no schemes, no drive, no traversal).
- source-of-truth (file/section):
  - schemas/* (ObjectRef and AuditTrailRef definitions)
- check procedure (deterministic):
  1) Confirm each relevant schema has a `pattern` on `storage_ref` that forbids:
     - absolute paths, `..`, `://`, `:` (drive/scheme), `//`, `./`, and backslashes.
- required evidence/artifacts (schema kinds): none (repo-doc sweep)
- pass/fail criteria:
  - PASS if all referenced schemas include the required constraints.
  - FAIL otherwise.

### CS-R0-ENFORCEMENT-WIRED-001 — Gate R R0 evidence sufficiency is wired
- invariant_id: CS-R0-ENFORCEMENT-WIRED-001
- statement: Gate R’s canonical check registry MUST include the R0 evidence sufficiency check.
- source-of-truth (file/section):
  - chain/logic/r_checks/registry.py
- check procedure (deterministic):
  1) Confirm `chain/logic/r_checks/registry.py` references `r0_evidence_sufficiency` and wires its `run` function.
- required evidence/artifacts (schema kinds): none (repo-doc sweep)
- pass/fail criteria:
  - PASS if the registry wiring is present.
  - FAIL otherwise.
### CS-RENDER-001 — Render targets must not drift
- invariant_id: CS-RENDER-001
- statement: All registered render targets (JSON canonical → Markdown generated view) MUST have no drift between the canonical JSON and the generated Markdown file.
- source-of-truth (file/section):
  - tools/render.py (RENDER_REGISTRY)
  - tiers/tier-packs.json (canonical SSOT for tier-packs)
  - tiers/tier-packs.md (generated view, MUST match canonical)
- check procedure (deterministic):
  1) Import `tools/render.py` and enumerate all registered render targets via `get_all_target_names()`.
  2) For each target, invoke `check_target_drift(repo_root, target_name)` which:
     a) Loads the canonical JSON from `target.canonical_json`.
     b) Loads the target template and applies deterministic placeholder substitution via `target.compute_mapping`.
     c) Reads the existing file at `target.default_output`.
     d) Compares normalized content: CRLF→LF, trailing whitespace stripped per line, exactly one trailing newline at EOF.
  3) If any target has drift, FAIL with remediation command.
- required evidence/artifacts (schema kinds): none (repo-doc sweep)
- pass/fail criteria:
  - PASS if all registered targets have no drift.
  - FAIL if any target's generated file differs from the canonical rendering.
- remediation: `python -m tools.render <target_name> --repo .` for each drifted target.
---

## C) Checklist (operator-friendly)

- [ ] CS-CAN-001: terminology.md is pointers-only to CANONICALS anchors.
- [ ] CS-CAN-002: canonical chain string matches everywhere.
- [ ] CS-CAN-003: publication posture prohibition present and respected.
- [ ] CS-TERM-001: verification/validation boundaries are enforced across public docs.
- [ ] CS-BYTE-001: Byte Guard passes (no CRLF / byte drift).
- [ ] CS-GS-001: GateVerdict GO/NO-GO semantics match schema and gate specs.
- [ ] CS-GS-002: remediation instruction format matches schema + taxonomy.
- [ ] CS-GS-003: all gate failure categories exist in failure-taxonomy.
- [ ] CS-GS-004: doc_impact schema and gate semantics align (tier requirement + note-on-empty + check IDs).
- [ ] CS-GS-005: no spec fiction — doc_impact claimed implies schema field exists.
- [ ] CS-EV-001: every evidence kind referenced exists in EvidenceManifest enum.
- [ ] CS-EV-002: Gate Q minimum evidence kinds are consistent + schema-supported.
- [ ] CS-EV-003: Gate R evidence sufficiency is tier-driven (no hardcoded extras).
- [ ] CS-EV-004: R-Snapshot immutability + append-only final manifest is consistent.
- [ ] CS-EV-005: Seal binds core replay set + waivers via ObjectRefs.
- [ ] CS-EV-006: Tier>=1 PASS manifests index policy.consistency_sweep.
- [ ] CS-TIER-001: tier IDs are exactly tier-0..tier-3 everywhere.
- [ ] CS-TIER-002: tier required_evidence_kinds match across tier-packs/evidence-bundles/running-belgi.
- [ ] CS-TIER-003: docs_compilation_log allowed but not required by Gate R.
- [ ] CS-TIER-004: command_log_mode is representable + deterministically enforced.
- [ ] CS-TIER-005: doc_impact_required name + tier mapping consistent across tier-packs/gates/runbook.
- [ ] CS-WVR-001: waiver lifecycle is LLM-closed (human-only actions).
- [ ] CS-WVR-002: waivers are time-bounded + auditable and gate-enforced.
- [ ] CS-WVR-003: tier waiver policy limits match everywhere.
- [ ] CS-WVR-004: waivers appear in sealing/replay artifacts when applied.
- [ ] CS-WVR-005: doc_impact enforcement introduces no waiver bypass.
- [ ] CS-TPL-001: PromptBundle policy_report fields/hashes required and schema-indexable.
- [ ] CS-TPL-002: PromptBundle integrity binds LockedSpec.prompt_bundle_ref deterministically.
- [ ] CS-TPL-003: DocsCompiler emits docs_compilation_log without schema changes.
- [ ] CS-TPL-004: Gate R obligations satisfied via EvidenceManifest indexing + `storage_ref` resolution, including bytes→hash verification and required report **payload schema validation** (no new schema fields).
- [ ] CS-TPL-005: Docs compilation is post-R and non-interfering.
- [ ] CS-VERIFY_BUNDLE-001: canonical deterministic verifier exists at chain/gate_r_verify.py.
- [ ] CS-GATE_R-MANDATES-VERIFY_BUNDLE-001: Gate R mandates chain/gate_r_verify.py and the MUST-level enforcement obligations.
- [ ] CS-VERIFY_BUNDLE-GATEVERDICT-BINDING-001: Gate R specifies GateVerdict.evidence_manifest_ref binding when GateVerdict is used.
- [ ] CS-SWEEP-001: sweep inputs reflect current schemas/tools.
- [ ] CS-GV-001: GateVerdict schema requires run_id.
- [ ] CS-LS-001: LockedSpec path prefix patterns are normalized + traversal-safe.
- [ ] CS-REF-001: ObjectRef storage_ref is constrained in all schemas.
- [ ] CS-R0-ENFORCEMENT-WIRED-001: Gate R R0 evidence sufficiency is wired.
- [ ] CS-RENDER-001: Render targets (JSON→MD) have no drift.

---

## D) Sweep Report

DEFAULT: **NO-GO** unless the sweep report is evidence-backed and contains zero unverified PASS claims.

Implementation note (deterministic + fail-closed): the reference sweep tool uses a hardened, repo-root-confined write with symlink checks on the parent chain.

### D1) Report Contract (normative)

#### D1.1 Evidence pointer format (mechanically checkable)

Evidence pointers MUST be stable, copy-pastable, and mechanically checkable.

Accepted formats:
- Markdown files: `path/to/file.md#github-rendered-anchor`
  - Use GitHub-style heading anchors (lowercase, spaces to `-`, punctuation stripped, consecutive dashes collapsed).
  - If a Markdown file defines an explicit HTML anchor (e.g., `<a id="canonical-chain"></a>`), prefer the explicit anchor: `CANONICALS.md#canonical-chain`.
- JSON schemas: `schemas/Foo.schema.json#/json/pointer/path`
  - Use RFC 6901 JSON Pointer (e.g., `schemas/GateVerdict.schema.json#/properties/remediation/properties/next_instruction/pattern`).
- Other repo-relative files (non-Markdown / non-schema): `path/to/file.ext`
  - MUST be repo-relative, copy-pastable, and point to a single concrete file (no globs, no directories).

If an anchor/pointer cannot be made stable, the invariant MUST be marked **FAIL** with remediation: “Fix heading/anchor and rerun sweep.”

#### D1.2 Sweep report artifact (MANDATORY, machine-readable)

The sweep execution MUST produce a single JSON artifact that is the authoritative, machine-readable Sweep Report.

**Artifact identity**
- Artifact id MUST be: `policy.consistency_sweep`.
- Artifact bytes MUST be JSON (UTF-8 encoded).

**Canonical bundle location**
- Within an evidence bundle, the artifact MUST be stored at: `policy/consistency_sweep.json`.
- The SHA-256 digest MUST be computed over the exact file bytes stored at that path.

**EvidenceManifest indexing (MANDATORY)**
The run’s EvidenceManifest MUST include exactly one `artifacts[]` entry with:
- `kind`: `"policy_report"`
- `id`: `"policy.consistency_sweep"`
- `media_type`: `"application/json"`
- `storage_ref`: `"policy/consistency_sweep.json"`
- `hash`: the SHA-256 hex digest of the file bytes at `storage_ref`
- `produced_by`: one of `C1`, `C2`, `R`, `C3`, `S` (RECOMMENDED `C1`)

If the `policy.consistency_sweep` artifact is missing or not indexed as above, the sweep outcome MUST be **NO-GO**, and no invariant result may be treated as a verified PASS.

#### D1.3 Required JSON fields (Sweep Report payload)

The JSON document at `policy/consistency_sweep.json` MUST be a single JSON object with these REQUIRED fields:

- `artifact_id`: string, MUST equal `"policy.consistency_sweep"`.
- `generated_at`: string, RFC3339 timestamp.
- `sweep_started_at`: string, RFC3339 timestamp.
- `sweep_finished_at`: string, RFC3339 timestamp.
- `tool`: object with:
  - `name`: string (operator tool identity; MAY be a repo-local script name)
  - `version`: string (tool version; MAY be a git describe string)
- `repo_revision`: string (git tree hash for the evaluated inputs). For determinism, the sweep outputs themselves are excluded from the evaluated tree (currently: `policy/consistency_sweep.json`, `policy/consistency_sweep.summary.md`). For CS-EV-006 stability, fixture EvidenceManifest entries for `policy.consistency_sweep` are normalized to a zero hash during the repo revision computation (self-referential pinning does not alter the revision). Implementation uses a temporary git index (read-tree/update-index/write-tree), not tree construction commands.
- `inputs`: array of objects, each with:
  - `path`: string, repository-relative, using `/` separators
  - `sha256`: string, 64 hex chars, SHA-256 over the file bytes
- `invariants`: array of per-invariant result objects.
- `failures`: array of failure summary objects (may be empty), each with:
  - `check_id`: string (invariant id)
  - `message`: string (one-line remediation)
- `summary`: object with:
  - `total`: integer ≥ 0
  - `passed`: integer ≥ 0
  - `failed`: integer ≥ 0

Per-invariant result objects in `invariants` MUST have these REQUIRED fields:
- `invariant_id`: string (e.g., `"CS-CAN-001"`).
- `status`: string, MUST be either `"PASS"` or `"FAIL"`.
- `evidence`: array of evidence pointer strings (per D1.1). For FAIL, this MAY be empty.
- `remediation`: string. For PASS, this MUST be the empty string `""`. For FAIL, this MUST be a one-sentence remediation.

Per-invariant result objects MAY include this OPTIONAL field:
- `details`: object (structured, machine-readable diagnostics; intended to be stable and deterministic).

**Determinism requirements**
- `invariants[]` MUST be sorted by `invariant_id` ascending.
- `summary.total` MUST equal the length of `invariants`.
- `summary.passed + summary.failed` MUST equal `summary.total`.

#### D1.4 Minimal examples (non-normative)

Minimal Sweep Report JSON example:

```json
{
  "artifact_id": "policy.consistency_sweep",
  "generated_at": "2000-01-01T00:00:00Z",
  "sweep_started_at": "2000-01-01T00:00:00Z",
  "sweep_finished_at": "2000-01-01T00:00:05Z",
  "tool": { "name": "consistency-sweep", "version": "1.0.0" },
  "repo_revision": "0123456789abcdef0123456789abcdef01234567",
  "inputs": [
    { "path": "CANONICALS.md", "sha256": "0000000000000000000000000000000000000000000000000000000000000000" }
  ],
  "invariants": [
    {
      "invariant_id": "CS-CAN-001",
      "status": "FAIL",
      "evidence": [],
      "remediation": "Produce and index policy.consistency_sweep, then rerun the sweep."
    }
  ],
  "failures": [
    { "check_id": "CS-CAN-001", "message": "Produce and index policy.consistency_sweep, then rerun the sweep." }
  ],
  "summary": { "total": 1, "passed": 0, "failed": 1 }
}
```

Minimal EvidenceManifest `artifacts[]` entry example:

```json
{
  "kind": "policy_report",
  "id": "policy.consistency_sweep",
  "hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "media_type": "application/json",
  "storage_ref": "policy/consistency_sweep.json",
  "produced_by": "C1"
}
```

### D2) Future hardening (NON-NORMATIVE)

- The reference report generator already emits deterministically serialized JSON bytes (e.g., stable key ordering + fixed whitespace/minified separators). A future implementation can additionally adopt a published canonical JSON scheme (e.g., RFC 8785 / JCS) to reduce cross-implementation byte differences.
- The report can be cryptographically signed and/or included as a referenced object in a seal, without changing any invariants defined in Section B.
