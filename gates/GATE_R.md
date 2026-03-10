# Gate R — Verify (Post-Proposal, Deterministic)

## 1. Purpose
Gate R is the deterministic verification gate in the canonical chain (P → C1 → Q → C2 → **R** → C3 → S). It evaluates the proposed repo state against the locked run contract and required evidence. Canonical responsibilities R1–R8 are defined in [CANONICALS.md#r-verifier-responsibilities](https://github.com/belgi-protocol/belgi/blob/main/CANONICALS.md#r-verifier-responsibilities).

## 2. Inputs (Required)

### 2.1 LockedSpec (locked)
- Input artifact: `LockedSpec.json`
- MUST validate against: [../schemas/LockedSpec.schema.json](../schemas/LockedSpec.schema.json)
- Key fields used:
  - `run_id`
  - `intent.*`
  - `tier.tier_id`
  - optional `doc_impact` (may be required by tier)
  - `environment_envelope.*`
  - `invariants[]`
  - `constraints.*`
  - `protocol_pack.*`
  - `upstream_state.commit_sha`
  - optional `waivers_applied[]`

### 2.2 EvidenceManifest
- Input artifact: `EvidenceManifest.json`
- MUST validate against: [../schemas/EvidenceManifest.schema.json](../schemas/EvidenceManifest.schema.json)

### 2.3 Gate Q verdict (upstream)
- Input artifact: `GateVerdict.Q.json`
- MUST validate against: [../schemas/GateVerdict.schema.json](../schemas/GateVerdict.schema.json)
- Gate R binds the exact Gate Q verdict bytes into the R-snapshot EvidenceManifest for downstream compilers.

### 2.4 Repository state (post-proposal)
- The repo state under evaluation MUST be a concrete revision (e.g., a commit) that can be deterministically diffed against `LockedSpec.upstream_state.commit_sha`.

### 2.5 Optional waiver documents
If `LockedSpec.waivers_applied` is present and non-empty, the corresponding waiver documents MUST be available to Gate R.
- Each waiver MUST validate against: [../schemas/Waiver.schema.json](../schemas/Waiver.schema.json)

### 2.6 Tier parameter defaults
Gate R reads tier policies from:
- Canonical SSOT: [../tiers/tier-packs.json](../tiers/tier-packs.json)
- Generated view (must match canonical): [../tiers/tier-packs.md](../tiers/tier-packs.md)

## 3. Outputs (Required)
Gate R produces a `GateVerdict.json` with `gate_id = "R"`.
- MUST validate against: [../schemas/GateVerdict.schema.json](../schemas/GateVerdict.schema.json)

### 3.0 How to run (v1 CLI runner)

Run Gate R deterministically using the canonical verifier entrypoint:

```bash
python chain/gate_r_verify.py \
  --repo . \
  --locked-spec LockedSpec.json \
  --gate-q-verdict GateVerdict.Q.json \
  --evidence-manifest EvidenceManifest.json \
  --evaluated-revision <EVALUATED_SHA40> \
  --gate-verdict-out policy/GateVerdict.json \
  --out policy/verify_report.json

# Optional: write the R-snapshot EvidenceManifest to a separate path (defaults to overwriting --evidence-manifest).
#   --r-snapshot-manifest-out policy/EvidenceManifest.r_snapshot.json
```

Exit codes (deterministic):
- `0`: GO (all checks PASS)
- `2`: NO-GO (any check FAIL)
- `3`: tool usage/internal errors (I/O, parse errors)

### 3.1 GO / NO-GO semantics (schema-enforced)
- GO => `failure_category = null`, `failures = []`, and `remediation` MUST be absent.
- NO-GO => `failure_category` MUST be a non-null token, `failures` MUST be non-empty, and `remediation.next_instruction` MUST match: `^Do .+ then re-run R\.$`

Deterministic selection rule for `GateVerdict.failure_category`:
- Set it to the category of the **first failing check** in the ordered check list:
  - `PROTOCOL-IDENTITY-001`
  - then `R-SNAPSHOT-INDEX-001` if protocol identity passed
  - then `R-OVERLAY-001` only when `--overlay` is supplied and earlier fatal stops did not trigger
  - then `R4` only when a required `policy_report`/`test_report` is present exactly once, is schema-valid, but its payload `run_id` belongs to a different run
  - then registry order: `R0.tier_parse` → `R0.evidence_sufficiency` → `R0.command_log_mode` → `R0.attestation_presence` →
    `R1` → `R2` → `R3` → `R-DOC-001` → `R4` → `R5` → `R6` → `R7` → `R8`.

**Primary-cause contract (hardening note):**
- Gate R default doctrine is **fail-fast / minimal mutation**.
- The **ordered check list** is the verifier execution order, serialized as an ordered array in the canonical verifier report: `verify_report.json.results[]`.
- `results[]` contains executed checks only.
- `PROTOCOL-IDENTITY-001` is always first. If it fails, Gate R MUST stop before mutation-producing snapshot work and MUST NOT execute later Gate R checks.
- If protocol identity passes, Gate R MUST run `R-SNAPSHOT-INDEX-001` next. If the snapshot index invariant fails or the R-snapshot manifest cannot be written, Gate R MUST stop before later checks.
- `R-OVERLAY-001` appears next only when `--overlay` is supplied and the earlier fatal-stop conditions did not trigger.
- Gate R applies required-report current-run binding structurally under `R4` before semantic checks (`R1`, `R5`, `R7`, `R8`) rely on those required report payloads.
- If that structural `R4` prevalidation fails, Gate R stops there and the registry checks do not execute.
- Canonical source of truth for later-check order is `chain/logic/r_checks/registry.py` (the verifier MUST emit results in that order).
- Consumers MUST treat the **first FAIL** entry in `results[]` as the primary cause and MUST NOT re-sort failures.
- If a verifier output does not include an ordered `results[]` list, any tool enforcing primary-cause selection MUST **FAIL closed** (no guessing from unordered sets).

### 3.2 Evidence manifest reference
`GateVerdict.evidence_manifest_ref` MUST point to the persisted EvidenceManifest used for evaluation.
- Snapshot manifest/index write failure is terminal because Gate R must not continue later evaluation without a persisted evidence anchor.

## 4. Evidence Sufficiency Rule (Deterministic)
Gate R MUST be **NO-GO** if required evidence is missing, regardless of how acceptable the patch appears.

Procedure:
1) Read `tier_id` from LockedSpec.
2) Parse tier parameters deterministically from [../tiers/tier-packs.json](../tiers/tier-packs.json).
  - If `tier_id` is missing/invalid OR tier parsing fails => fail with:
    - failure category: `FR-SCHEMA-ARTIFACT-INVALID`
    - failing rule_id: `R0.tier_parse`
3) Obtain `required_evidence_kinds` for that tier.
4) From EvidenceManifest, build the set of `artifacts[].kind` present.
5) If any required kind is missing => fail with:
   - failure category: `FR-EVIDENCE-MISSING`
   - failing rule_id: `R0.evidence_sufficiency`

If `envelope_policy.requires_attestation == yes`, additionally require:
- EvidenceManifest `envelope_attestation` is non-null
- At least one EvidenceManifest artifact exists with `kind == "env_attestation"`

Deterministic binding rule (double representation):
- When attestation is required, the attestation reference and artifact MUST bind by id: there MUST exist an EvidenceManifest artifact with `kind == "env_attestation"` and `id == EvidenceManifest.envelope_attestation.id`.
- Presence-only sufficiency is enforced at `R0.attestation_presence`; id-binding is enforced at `R6`.
- Any id-binding mismatch MUST fail closed under `FR-EVIDENCE-ATTESTATION-MISSING`.

Otherwise fail with:
- failure category: `FR-EVIDENCE-ATTESTATION-MISSING`
- failing rule_id: `R0.attestation_presence`

Additionally, Gate R MUST enforce the tier’s `command_log_mode` deterministically:
- If `command_log_mode == "structured"`, `EvidenceManifest.commands_executed` MUST be a list of structured command records (each item has `argv`, `exit_code`, `started_at`, `finished_at`). If any element is a string, fail with:
  - failure category: `FR-COMMAND-FAILED`
  - failing rule_id: `R0.command_log_mode`
  - remediation.next_instruction template: `Do ensure required command record belgi <subcommand> exists with exit_code 0 in EvidenceManifest.commands_executed then re-run R.`

## 5. Deterministic Checks (Executable Doc)
Checks below correspond exactly to canonical responsibilities R1–R8, plus deterministic preflight and contract compliance checks that do not expand trust or introduce heuristics:
- R0.* (tier parse + evidence sufficiency obligations)
- `R-DOC-001` (doc_impact contract compliance)

Each check specifies: `check_id`, required inputs, deterministic procedure, tier params used, failure category, required evidence kinds, and remediation template.

### PROTOCOL-IDENTITY-001 — Protocol pack identity matches LockedSpec.protocol_pack
- check_id: `PROTOCOL-IDENTITY-001`
- required inputs:
  - `LockedSpec.protocol_pack.pack_id` (LockedSpec schema)
  - `LockedSpec.protocol_pack.manifest_sha256` (LockedSpec schema)
  - `LockedSpec.protocol_pack.pack_name` (LockedSpec schema)
  - `LockedSpec.protocol_pack.source` (operational context; required by schema but not identity)
  - Active protocol context identity tuple (from the executing verifier): `pack_id`, `manifest_sha256`, `pack_name`
- deterministic procedure (v1, deterministic):
  1) FAIL if `LockedSpec` is missing or not an object.
  2) FAIL if `LockedSpec.protocol_pack` is missing or not an object.
  3) Compare the identity tuple fields for exact string equality; record any mismatches:
     - `LockedSpec.protocol_pack.pack_id` vs active `pack_id`
     - `LockedSpec.protocol_pack.manifest_sha256` vs active `manifest_sha256`
     - `LockedSpec.protocol_pack.pack_name` vs active `pack_name`
  4) FAIL if any mismatch exists.
  5) `source` is operational context and MUST NOT be used as an identity mismatch signal; policy checks may restrict allowed source values.
- failure category: `FR-PROTOCOL-IDENTITY-MISMATCH`
- required evidence kinds: `schema_validation`, `policy_report`
- remediation.next_instruction template: `Do ensure the same protocol pack is used for C1 compilation and gate verification then re-run R.`

### 5.1 Command matching rule (used by R1/R5/R6/R7/R8)
When a check requires a command, Gate R evaluates it deterministically against `EvidenceManifest.commands_executed`:

- In `structured` mode, a required command `belgi <subcommand>` is satisfied iff there exists a command record where:
  - `argv[0] == "belgi"`
  - `argv[1]` equals the required subcommand token (e.g., `"invariant-eval"`)
  - `exit_code == 0`

- In `strings` mode, a required command `belgi <subcommand>` is satisfied iff there exists a string entry exactly equal to `"belgi <subcommand>"`.

If a required command is missing or has `exit_code != 0`, Gate R fails with `FR-COMMAND-FAILED`.
- For `belgi adversarial-scan`, successful execution means `exit_code == 0` only; findings are policy report data (`policy.adversarial_scan.summary.failed`), not a command exit-code signal. Legacy alternative success codes are not accepted.

### 5.2 Policy report naming convention (used by R1/R7/R8)
Where a check requires a policy report, Gate R requires an EvidenceManifest artifact with:
- `kind == "policy_report"`
- `id` equal to the required report id (examples below)

### 5.2.1 Required report artifact integrity + payload schema validation (REQUIRED)
For any evidence artifact that is **required** by Gate R by specific `(kind,id)` (including required `policy_report` and tier-required `test_report`), Gate R MUST enforce all of the following deterministically:

**Uniqueness rule (MANDATORY):**
- The required `(kind,id)` obligation MUST match **exactly one** `EvidenceManifest.artifacts[]` entry.
- If it matches 0 entries => **NO-GO**.
- If it matches more than 1 entry => **NO-GO**.

**Integrity rule (MANDATORY):**
1) Resolve bytes via the artifact’s `storage_ref`.
  - Resolution MUST be local-only and repo/bundle-relative.
  - Resolution MUST reject traversal and remote schemes (enforced by schema constraints on `storage_ref`).
2) Compute `sha256(bytes)` and compare to the artifact’s declared `hash`.
3) Decode the bytes as UTF-8 JSON and validate the resulting object against the deterministic payload schema:
  - For `policy_report`: [../schemas/PolicyReportPayload.schema.json](../schemas/PolicyReportPayload.schema.json)
  - For `test_report`: [../schemas/TestReportPayload.schema.json](../schemas/TestReportPayload.schema.json)
4) Bind the required report payload to the current run:
  - Required `policy_report` payloads MUST have `payload.run_id == LockedSpec.run_id`.
  - Required `test_report` payloads MUST have `payload.run_id == LockedSpec.run_id`.
  - A schema-valid, hash-valid report from a different run is structurally invalid and MUST be rejected fail-closed.
5) Reject hollow payloads by enforcing minimum semantic sufficiency:
  - Required `policy_report` payload MUST include non-empty `checks[]`.
  - Required `policy_report` payload MUST include `summary.failed` as an integer (non-boolean).
  - Required `test_report` payload MUST include `summary.failed` as an integer (non-boolean) for structural validity.
  - **NOTE:** Required `test_report` pass/fail semantics (`summary.failed == 0`) are NOT enforced here; they are deferred to R5 to ensure deterministic failure categorization under `FR-TESTS-POLICY-FAILED`.

Deterministic interpretation of required `policy_report.summary.failed` (v1):
- For `R1` and `R7`, the accepted required report MUST have `summary.failed == 0`; otherwise those checks emit their specified failure category tokens.
- For `R8`, semantic verdicting is driven by `adversarial_policy.findings_mode` after `R4` structural acceptance:
  - `findings_mode == "fail"`: unwaived findings with `summary.failed != 0` emit `FR-ADVERSARIAL-DIFF-SUSPECT`.
  - `findings_mode == "warn"`: findings do not themselves cause `R8` to fail if command/report/waiver structure is otherwise valid.
  - If findings are present but all findings are covered by applicable active waivers allowed by the selected tier, `R8` PASSes.
- R4 validates required report integrity + payload schema (and does not gate on `summary.failed == 0`) to preserve deterministic failure selection for the dedicated checks.

### 5.2.2 Canonical deterministic verifier (MUST)
To prevent fragmented enforcement, Gate R MUST be executed using the canonical deterministic verifier entrypoint:

- `python chain/gate_r_verify.py --repo . --locked-spec LockedSpec.json --evidence-manifest EvidenceManifest.json --evaluated-revision <EVALUATED_SHA40> --gate-verdict-out policy/GateVerdict.json --out policy/verify_report.json`

This verifier MUST implement the MUST-level obligations in this gate spec, including:
- required `(kind,id)` uniqueness ("must match exactly one")
- bytes→hash verification (compute `sha256(bytes)` for required artifacts)
- payload schema validation for required `policy_report` and tier-required `test_report`

Optional binding check (when GateVerdict is provided to the verifier):
- If a `GateVerdict.json` is provided to verification, `GateVerdict.evidence_manifest_ref` MUST resolve under repo root, and `sha256(bytes)` MUST match the declared hash for the EvidenceManifest bytes used by Gate R.

### R1 — Intent invariants satisfied
- check_id: `R1`
- required inputs:
  - `LockedSpec.invariants[]` (LockedSpec schema)
  - Repo diff base: `LockedSpec.upstream_state.commit_sha`
  - EvidenceManifest command log and policy report index
- deterministic procedure:
  1) Require that `LockedSpec.invariants` is non-empty (schema-enforced by LockedSpec).
  2) Enforce invariant evaluation as an evidence obligation:
     - Require a successful command record for `belgi invariant-eval` (see command matching rule).
     - Require a `policy_report` artifact with `id == "policy.invariant_eval"`.
  3) If either obligation is missing => fail.
  4) After `R4` structurally accepts the required report for the current run (§5.2.1), interpret the accepted `policy.invariant_eval` payload semantically.
     - If the accepted report indicates failures (`summary.failed != 0`) => fail `FR-INVARIANT-FAILED`.
- tier params used: `command_log_mode`
- failure category:
  - `FR-COMMAND-FAILED` if the required command is missing/failed
  - `FR-INVARIANT-EVAL-MISSING` if the `policy.invariant_eval` policy report artifact is missing
  - `FR-SCHEMA-ARTIFACT-INVALID` if the required `policy.invariant_eval` report payload is invalid (schema/integrity/sufficiency)
  - `FR-INVARIANT-FAILED` if the required `policy.invariant_eval` report is valid but indicates failures (`summary.failed != 0`)
- required evidence kinds: `policy_report`, `command_log`
- remediation.next_instruction templates:
  - (for `FR-COMMAND-FAILED`) `Do ensure required command record belgi <subcommand> exists with exit_code 0 in EvidenceManifest.commands_executed then re-run R.`
  - (for `FR-INVARIANT-EVAL-MISSING`) `Do run belgi invariant-eval and record policy report policy.invariant_eval then re-run R.`
  - (for `FR-SCHEMA-ARTIFACT-INVALID`) `Do fix schema validation errors in required artifact then re-run R.`
  - (for `FR-INVARIANT-FAILED`) `Do modify the change so invariant <rule_id> is satisfied then re-run R.`

### R2 — Scope / Blast Radius within tier budgets
- check_id: `R2`
- required inputs:
  - `LockedSpec.constraints.allowed_paths`, optional `LockedSpec.constraints.max_touched_files`, optional `LockedSpec.constraints.max_loc_delta`
  - `LockedSpec.upstream_state.commit_sha`
  - Tier defaults (canonical SSOT): [../tiers/tier-packs.json](../tiers/tier-packs.json)
- deterministic procedure:
  1) Compute `touched_files` and `loc_delta` (insertions + deletions) from the diff between the locked base commit and evaluated revision.
  2) Determine effective limits:
     - `max_touched_files` = `LockedSpec.constraints.max_touched_files` if present else tier default.
     - `max_loc_delta` = `LockedSpec.constraints.max_loc_delta` if present else tier default.
  3) If effective limit is non-null and exceeded => fail.
- tier params used: `scope_budgets.max_touched_files`, `scope_budgets.max_loc_delta`
- failure category: `FR-SCOPE-BUDGET-EXCEEDED`
- required evidence kinds: `diff`, `command_log`
- remediation.next_instruction template: `Do reduce scope to within limits (tier scope budgets) or adjust tier/constraints with HOTL then re-run R.`

### R3 — Policy invariants satisfied (paths + constraints)
- check_id: `R3`
- required inputs:
  - `LockedSpec.constraints.allowed_paths`, `LockedSpec.constraints.forbidden_paths`
  - `LockedSpec.upstream_state.commit_sha`
  - Tier setting: `scope_budgets.forbidden_paths_enforcement`
  - Optional waivers (if referenced): [../schemas/Waiver.schema.json](../schemas/Waiver.schema.json)
- deterministic procedure (v1, deterministic):
  **Canonical path normalization algorithm (R3 path/prefix checks):**
  Define `normalize_repo_rel_path(s)` as:
  1) FAIL if `s` is empty.
  2) FAIL if `s` starts with `/`.
  3) FAIL if `s` contains `\\`.
  4) FAIL if `s` contains `*` or `?`.
  5) FAIL if `s` contains `:` or `://`.
  6) FAIL if `s` contains `//`.
  7) FAIL if `s` starts with `./`.
  8) Split `s` on `/` into segments. FAIL if any segment is `.` or `..`.
  9) Return `s` unchanged.

  Define `is_under_prefix(path, prefix)` as:
  - Let `p = normalize_repo_rel_path(path)`.
  - Let `x = normalize_repo_rel_path(prefix)`.
  - If `x` ends with `/`: return `p.startswith(x)`.
  - Else: return `p == x` OR `p.startswith(x + "/")`.

  Enforcement:
  1) Compute changed file paths from the locked base commit to evaluated revision.
  2) For each changed path:
    - FAIL if `normalize_repo_rel_path(changed_path)` fails.
    - Verify it is under at least one prefix in `constraints.allowed_paths` using `is_under_prefix`.
    - Verify it is not under any prefix in `constraints.forbidden_paths` using `is_under_prefix`.
  3) If a forbidden path is touched:
    - If tier enforcement is `strict`: fail.
    - If tier enforcement is `relaxed`: allow only if there exists an active waiver document where:
       - `gate_id == "R"`
       - `rule_id == "R3.forbidden_paths"`
       - `status == "active"`
       - `scope` is a normalized repo-relative prefix
       - offending path match uses canonical prefix semantics (`is_under_prefix`); literal substring matches do not apply
- tier params used: `scope_budgets.forbidden_paths_enforcement`, `waiver_policy.allowed`
- failure category: `FR-POLICY-FORBIDDEN-PATH`
- required evidence kinds: `diff`, `policy_report`, `command_log`
- remediation.next_instruction template: `Do revert changes to forbidden path <path> then re-run R.`

### R-DOC-001 — doc_impact required docs touched (contract compliance)
- check_id: `R-DOC-001`
- required inputs:
  - `LockedSpec.tier.tier_id` (LockedSpec schema)
  - Tier defaults (canonical SSOT): [../tiers/tier-packs.json](../tiers/tier-packs.json)
  - Optional `LockedSpec.doc_impact` (LockedSpec schema)
  - Repo diff base: `LockedSpec.upstream_state.commit_sha`
  - Evaluated repo revision (concrete revision)
- deterministic procedure (v1, deterministic):
  1) From [../tiers/tier-packs.json](../tiers/tier-packs.json), read `doc_impact_required` for the selected tier.
  2) If `doc_impact_required == true`:
    - FAIL if `doc_impact` is missing or null. (Defense-in-depth; this SHOULD already be caught by Gate Q.)
  3) If `doc_impact` is absent:
    - PASS this check (tier does not require it).
  4) If `doc_impact.required_paths` is `[]`:
    - PASS this check only if `doc_impact.note_on_empty` is present and non-empty.
  5) If `doc_impact.required_paths` has entries:
    - Compute `changed_files` as the exact set of repo-relative paths produced by:
      - `git diff --name-only <LockedSpec.upstream_state.commit_sha> <evaluated_revision>`
    - FAIL if none of the `required_path` entries are present as exact string matches in `changed_files`.
- tier params used: `doc_impact_required`
- failure category: `FR-INVARIANT-FAILED`
- required evidence kinds: `diff`, `command_log`
- remediation.next_instruction template: `Do modify the change so invariant <rule_id> is satisfied then re-run R.`

### R4 — Schema / contract checks
- check_id: `R4`
- required inputs:
  - EvidenceManifest: [../schemas/EvidenceManifest.schema.json](../schemas/EvidenceManifest.schema.json)
  - LockedSpec: [../schemas/LockedSpec.schema.json](../schemas/LockedSpec.schema.json)
- deterministic procedure (v1, deterministic):
  1) Validate LockedSpec and EvidenceManifest against their schemas.
  2) Verify `EvidenceManifest.run_id == LockedSpec.run_id`.
  2b) Enforce publication profile selection (fail-closed):
     - If `LockedSpec.publication_intent.publish == true`, then `LockedSpec.publication_intent.profile` MUST equal `"public"`.
  2c) Enforce Tier-3 Genesis Root-of-Trust (fail-closed):
    - If `LockedSpec.tier.tier_id == "tier-3"`, EvidenceManifest MUST include exactly one artifact with `kind == "genesis_seal"`.
    - The referenced payload MUST validate against [../schemas/GenesisSealPayload.schema.json](../schemas/GenesisSealPayload.schema.json).
    - Tier-3 canonical authority is rooted in [../belgi/anchor/v1/TrustAnchor.json](../belgi/anchor/v1/TrustAnchor.json), not in the historical repo-local genesis reference payload.
    - The verifier MUST compute `sha256(bytes)` over canonical `TrustAnchor.json` bytes and compare that digest against one pinned constant before consuming Tier-3 authority fields.
    - After digest verification, the verifier MUST use `TrustAnchor.anchor_payload` + `TrustAnchor.public_key_hex` to verify the `genesis_seal` payload and signature.
    - `belgi/genesis/GenesisSealPayload.json` remains a historical repo-local genesis reference surface only; it is not authoritative for canonical Tier-3 trust-anchor verification.
  3) Enforce per-kind producer constraints ("LLMs propose; gates dispose"):
     - `schema_validation`: allowed producers `{C1, R}`
     - `policy_report`: allowed producers `{C1, R}`
     - `test_report`: allowed producers `{C1, R}`
     - `env_attestation`: allowed producers `{C1}` (MUST NOT be C2)
     - `command_log`: allowed producers `{C1}`
     - `diff`: allowed producers `{C1, C2}` (the patch itself is the proposal)
     - `docs_compilation_log`: allowed producers `{C3}`
    - `genesis_seal`: allowed producers `{C1, R}`
  4) Verify each EvidenceManifest artifact has a valid ObjectRef (`id`, `hash`, `storage_ref`) and permitted enum values.
  5) For each Gate R **required** report artifact (required by `(kind,id)`), apply the Required report artifact integrity + payload schema validation procedure (see §5.2.1), including the uniqueness rule.
     - Required report payloads MUST also bind to the current run via `payload.run_id == LockedSpec.run_id`.
     - Gate R applies this required-report current-run binding structurally under `R4` before semantic checks (`R1`, `R5`, `R7`, `R8`) rely on those required report payloads.
  6) Verify `command_log` artifact exists and passes bytes→hash integrity check.
  7) Optional post-R evidence verification (defense-in-depth):
     - Gate R MUST NOT require `docs_compilation_log` (it is produced by C3 post-R).
     - If EvidenceManifest includes a `docs_compilation_log` artifact:
       - Verify bytes→hash integrity and validate payload against [../schemas/DocsCompilationLogPayload.schema.json](../schemas/DocsCompilationLogPayload.schema.json).
       - Verify payload `run_id` binds to `LockedSpec.run_id`.
       - If `LockedSpec.publication_intent.publish == true` and `LockedSpec.publication_intent.profile == "public"`, enforce public-safe redaction semantics: internal/secret prompt blocks MUST be represented as hashes only.
- tier params used: `command_log_mode` (shape enforced via Evidence Sufficiency Rule)
- failure category: `FR-SCHEMA-ARTIFACT-INVALID`
- required evidence kinds: `schema_validation`, `command_log`
- remediation.next_instruction template: `Do fix schema validation errors in required artifact then re-run R.`

### R5 — Tests policy satisfied
- check_id: `R5`
- required inputs:
  - Tier test policy (canonical SSOT): [../tiers/tier-packs.json](../tiers/tier-packs.json)
  - EvidenceManifest artifacts include `test_report` when required
  - test_summary extracted from `test_report.json` payload (not from EvidenceManifest directly)
- deterministic procedure (v1, deterministic):
  1) If `test_policy.required == no`:
    - If test_report exists and its `summary.failed > 0`, fail.
    - Otherwise pass.
  2) If `test_policy.required == yes`:
    - Require a `test_report` artifact with `(kind,id) == ("test_report", "tests.report")`.
    - Require `R4` structural acceptance of that required test report for the current run (see §5.2.1) before semantic evaluation.
    - For tiers where `command_log_mode == "structured"` (tiers >= 1), require `test_report.summary` is present.
    - Extract `test_summary` from `test_report.json` payload (SSOT source).
    - If `test_summary` is present, require `failed == 0`.
    - If `allowed_skips == no` and `test_summary` is present, require `skipped == 0`.
    - Require required command `belgi run-tests` is present and successful (per command matching rule).
- tier params used: `test_policy.required`, `test_policy.allowed_skips`, `command_log_mode`
- failure category:
  - `FR-COMMAND-FAILED` if `belgi run-tests` is missing/failed
  - `FR-TESTS-POLICY-FAILED` otherwise
- required evidence kinds: `test_report`, `command_log`
- remediation.next_instruction templates:
  - (for `FR-COMMAND-FAILED`) `Do ensure required command record belgi <subcommand> exists with exit_code 0 in EvidenceManifest.commands_executed then re-run R.`
  - (for `FR-TESTS-POLICY-FAILED`) `Do run required tests and resolve failures then re-run R.`

### R6 — Envelope attestation satisfied
- check_id: `R6`
- required inputs:
  - Tier envelope policy (canonical SSOT): [../tiers/tier-packs.json](../tiers/tier-packs.json)
  - `LockedSpec.run_id` (LockedSpec schema)
  - `LockedSpec.environment_envelope.attestation_pubkey_ref` (LockedSpec schema; required for tier-2/3)
  - EvidenceManifest `envelope_attestation` (ObjectRef or null)
  - EvidenceManifest contains `env_attestation` artifact when required
  - EvidenceManifest contains exactly one `command_log` artifact (for deterministic binding)
  - Schema: [../schemas/EnvAttestationPayload.schema.json](../schemas/EnvAttestationPayload.schema.json)
- deterministic procedure (v1, deterministic):
  1) If `envelope_policy.requires_attestation == no`: pass.
  2) If `envelope_policy.requires_attestation == yes`:
     - Require EvidenceManifest `envelope_attestation` is non-null.
     - Require exactly one artifact of kind `env_attestation` exists with `id == EvidenceManifest.envelope_attestation.id`.
     - Resolve the `env_attestation` artifact bytes via `storage_ref` and verify `sha256(bytes)` equals the declared `hash`.
     - Decode bytes as UTF-8 JSON and validate the resulting object against [../schemas/EnvAttestationPayload.schema.json](../schemas/EnvAttestationPayload.schema.json).
     - Enforce payload binding:
       - `EnvAttestationPayload.run_id == LockedSpec.run_id`
       - `EnvAttestationPayload.attestation_id == EvidenceManifest.envelope_attestation.id`
       - `EnvAttestationPayload.command_log_sha256 == <declared hash of the single command_log artifact>`
     - Enforce tier-driven signature verification:
       - Read `envelope_policy.attestation_signature_required` from tier packs (yes|no).
       - If `attestation_signature_required == yes`:
         - Require `EnvAttestationPayload.signature_alg == "ed25519"` and a non-empty base64 `EnvAttestationPayload.signature`.
         - Resolve `LockedSpec.environment_envelope.attestation_pubkey_ref` and verify its `sha256(bytes)` equals the declared `hash`.
         - Verify Ed25519 signature over `canonical_json(EnvAttestationPayload` with `signature` + `signature_alg` removed), using the pinned public key.
     - Require required command `belgi verify-attestation` is present and successful (per command matching rule).
- tier params used: `envelope_policy.requires_attestation`, `command_log_mode`
- failure category:
  - `FR-COMMAND-FAILED` if `belgi verify-attestation` is missing/failed
  - `FR-EVIDENCE-ATTESTATION-MISSING` otherwise
- required evidence kinds: `env_attestation`, `command_log`
- remediation.next_instruction templates:
  - (for `FR-COMMAND-FAILED`) `Do ensure required command record belgi <subcommand> exists with exit_code 0 in EvidenceManifest.commands_executed then re-run R.`
  - (for `FR-EVIDENCE-ATTESTATION-MISSING`) `Do produce envelope attestation evidence under the declared envelope then re-run R.`

### R7 — Supply chain changes detected and accounted for
- check_id: `R7`
- bounded meaning (v1):
  - repo-state / change-surface signal grounded in workspace/revision state and declared evidence
  - does not claim SBOM generation/verification, provenance or SLSA-style builder attestation, dependency vulnerability scanning, or a full dependency/toolchain inventory beyond declared evidence surfaces
- required inputs:
  - Repo diff base: `LockedSpec.upstream_state.commit_sha`
  - `LockedSpec.environment_envelope.pinned_toolchain_refs` (LockedSpec schema)
- deterministic procedure (v1, deterministic):
  1) Require required command `belgi supplychain-scan` is present and successful (per command matching rule).
  2) Require a `policy_report` artifact with `id == "policy.supplychain"`.
  3) Require `R4` structural acceptance of the required `policy.supplychain` report for the current run (§5.2.1) before semantic interpretation.
     - If the accepted report indicates failures (`summary.failed != 0`) => fail `FR-SUPPLYCHAIN-CHANGE-UNACCOUNTED`.
  4) Gate R does not publish path classification lists or signatures; it treats the scan command + policy report as the authoritative, deterministic evidence obligation.
  5) Tier ownership note: Q5 owns `envelope_policy.pinned_toolchain_refs_required`; R7 consumes declared `LockedSpec.environment_envelope.pinned_toolchain_refs` as evidence context but does not read that tier parameter.
- tier params used: `command_log_mode`
- failure category:
  - `FR-COMMAND-FAILED` if `belgi supplychain-scan` is missing/failed
  - `FR-SUPPLYCHAIN-SCAN-MISSING` if the `policy.supplychain` policy report artifact is missing
  - `FR-SCHEMA-ARTIFACT-INVALID` if the required `policy.supplychain` report payload is invalid (schema/integrity/sufficiency)
  - `FR-SUPPLYCHAIN-CHANGE-UNACCOUNTED` if the required `policy.supplychain` report is valid but indicates failures (`summary.failed != 0`)
- required evidence kinds: `policy_report`, `command_log`
- remediation.next_instruction templates:
  - (for `FR-COMMAND-FAILED`) `Do ensure required command record belgi <subcommand> exists with exit_code 0 in EvidenceManifest.commands_executed then re-run R.`
  - (for `FR-SUPPLYCHAIN-SCAN-MISSING`) `Do run belgi supplychain-scan and record policy report policy.supplychain then re-run R.`
  - (for `FR-SCHEMA-ARTIFACT-INVALID`) `Do fix schema validation errors in required artifact then re-run R.`

### R8 — Adversarial diff scan (category-level)
- check_id: `R8`
- required inputs:
  - Diff between locked base commit and evaluated revision
  - `LockedSpec.constraints.forbidden_primitives` (optional; category tokens only)
  - Optional waivers (if tier allows): [../schemas/Waiver.schema.json](../schemas/Waiver.schema.json)
- deterministic procedure (v1, deterministic):
  1) Require required command `belgi adversarial-scan` is present and successful (per command matching rule, `exit_code == 0` only).
  2) Require a `policy_report` artifact with `id == "policy.adversarial_scan"`.
  3) Require `R4` structural acceptance of the required `policy.adversarial_scan` report for the current run (§5.2.1) before semantic interpretation.
  4) Resolve semantic verdicting from `adversarial_policy.findings_mode`:
     - `findings_mode == "warn"`: findings do not themselves cause `R8` to fail if command/report/waiver structure is otherwise valid.
     - `findings_mode == "fail"`: if the accepted report indicates failures (`summary.failed != 0`) and one or more findings remain unwaived, fail `FR-ADVERSARIAL-DIFF-SUSPECT`.
  5) If findings are present but all findings are covered by applicable active waivers allowed by the selected tier, `R8` PASSes.
  6) Gate R does not publish signatures, patterns, regexes, or thresholds; it treats the scan command + policy report as the deterministic evidence obligation.
- tier params used: `waiver_policy.allowed`, `adversarial_policy.findings_mode`, `command_log_mode`
- failure category:
  - `FR-COMMAND-FAILED` if `belgi adversarial-scan` is missing/failed
  - `FR-ADVERSARIAL-SCAN-MISSING` if the `policy.adversarial_scan` policy report artifact is missing
  - `FR-SCHEMA-ARTIFACT-INVALID` if the required `policy.adversarial_scan` report payload is invalid (schema/integrity/sufficiency)
  - `FR-ADVERSARIAL-DIFF-SUSPECT` if the required `policy.adversarial_scan` report is valid, `adversarial_policy.findings_mode == "fail"`, and one or more findings remain unwaived (`summary.failed != 0`)
- required evidence kinds: `policy_report`, `command_log`
- remediation.next_instruction templates:
  - (for `FR-COMMAND-FAILED`) `Do ensure required command record belgi <subcommand> exists with exit_code 0 in EvidenceManifest.commands_executed then re-run R.`
  - (for `FR-ADVERSARIAL-SCAN-MISSING`) `Do run belgi adversarial-scan and record policy report policy.adversarial_scan then re-run R.`
