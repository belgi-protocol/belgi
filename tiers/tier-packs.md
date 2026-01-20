<!-- generated: tiers/tier-packs.json ; run: python -m tools.render tier-packs --repo . -->
# BELGI Tier Packs

## 0. Rule of Use (Canonical Pointer)
This file defines **tier parameter defaults** used by gate enforcement procedures. It MUST NOT redefine canonical terms.
Tier Packs are canonically defined in [CANONICALS.md#tier-packs](https://github.com/belgi-protocol/belgi/blob/main/CANONICALS.md#tier-packs).

## 1. Tier IDs
Tier packs are referenced by `LockedSpec.tier.tier_id`.

- Tier 0: `tier-0`
- Tier 1: `tier-1`
- Tier 2: `tier-2`
- Tier 3: `tier-3`

## 2. Parameter Definitions (Gate-Readable)

### 2.1 required_evidence_kinds
List of evidence artifact kinds required for Gate R evidence sufficiency.
Allowed values are exactly the enum in [../schemas/EvidenceManifest.schema.json](../schemas/EvidenceManifest.schema.json):
`diff`, `test_report`, `command_log`, `env_attestation`, `policy_report`, `schema_validation`, `docs_compilation_log`, `hotl_approval`, `seal_manifest`, `genesis_seal`.

Note: `docs_compilation_log` is produced by C3 (post-R). Gate R MUST NOT require it.

### 2.1a required_evidence_kinds_q
List of evidence artifact kinds required for Gate Q minimum evidence sufficiency.

Operational meaning:
- These are the minimum evidence kinds Gate Q requires to be present in `EvidenceManifest.artifacts[]`.
- This parameter MUST include at least: `command_log`, `policy_report`, `schema_validation`.

Allowed values are exactly the enum in [../schemas/EvidenceManifest.schema.json](../schemas/EvidenceManifest.schema.json).

### 2.2 test_policy
Category-level rules (no bypass-friendly details):
- `required`: whether Gate R requires test evidence.
- `allowed_skips`: whether skips may be present without NO-GO.
- `flaky_handling`: category-level rule for unstable evidence.

### 2.3 scope_budgets
Conservative defaults used by Gate R (R2) when `LockedSpec.constraints.max_*` are absent.
- `max_touched_files`: integer or null
- `max_loc_delta`: integer or null
- `forbidden_paths_enforcement`: `strict` or `relaxed` (still enforced)

Operational meaning (enforcement procedure only):
- `strict`: forbidden-path violations are NOT waivable.
- `relaxed`: forbidden-path violations may be waived only with an explicit active waiver scoped to the violating path.

### 2.4 waiver_policy
- `allowed`: yes/no
- `max_active_waivers`: integer
- `requires_HOTL`: yes/no

v1 enforcement note (deterministic, schema-only): Gate Q/R treat `Waiver` as the sole waiver authorization artifact. For tiers where `requires_HOTL == yes`, Gate Q/R still enforce only waiver validity and a v1 human-authorship heuristic (see Gate Q Q6); no additional HOTL artifact is required by schemas.

### 2.5 command_log_mode
Controls the required shape of `EvidenceManifest.commands_executed`.
- `strings`: `commands_executed` may be a list of strings.
- `structured`: `commands_executed` MUST be a list of structured command records (`argv`, `exit_code`, `started_at`, `finished_at`).

This parameter is enforced by Gate R as a deterministic evidence obligation.

### 2.6 envelope_policy
- `requires_attestation`: yes/no
- `pinned_toolchain_refs_required`: yes/no

Note: `LockedSpec.environment_envelope.pinned_toolchain_refs` is schema-required (array present) but may be empty at schema level; the **Q5 semantic check** enforces non-empty when `pinned_toolchain_refs_required: yes`. This parameter exists for completeness and for future schema evolution.

### 2.7 doc_impact_required
Boolean controlling whether the LockedSpec MUST include the `doc_impact` object.

Operational meaning:
- `true` means `LockedSpec.doc_impact` MUST be present (not that `required_paths` must be non-empty).
- `false` means `LockedSpec.doc_impact` MAY be omitted.

#### 2.7.1 doc_impact policy map (tiers 0–3)
This table is an operator-facing summary of how `doc_impact` is treated per tier.

Notes:
- `IntentSpec.doc_impact` is always present (schema-required by [../schemas/IntentSpec.schema.json](../schemas/IntentSpec.schema.json) and validated by Gate Q).
- `LockedSpec.doc_impact` presence is tier-controlled via `doc_impact_required` and validated by Gate Q `Q-DOC-002`.

| tier_id | doc_impact required? | required_paths may be empty []? | note_on_empty required when empty []? | enforcing gate(s) |
|---|---|---|---|---|
| tier-0 | no | yes | yes (schema-level, if doc_impact is present with empty []) | Gate Q: `Q-INTENT-002` (IntentSpec schema). Gate Q: `Q-INTENT-003` (mapping if LockedSpec.doc_impact present). |
| tier-1 | no | yes | yes (schema-level, if doc_impact is present with empty []) | Gate Q: `Q-INTENT-002` (IntentSpec schema). Gate Q: `Q-INTENT-003` (mapping if LockedSpec.doc_impact present). |
| tier-2 | yes | yes | yes (mandatory for tier when empty []) | Gate Q: `Q-DOC-002` (presence + note_on_empty). Gate R: `R-DOC-001` (if required_paths non-empty, diff must touch at least one declared required path; if empty, note_on_empty must be present). |
| tier-3 | yes | yes | yes (mandatory for tier when empty []) | Gate Q: `Q-DOC-002` (presence + note_on_empty). Gate R: `R-DOC-001` (if required_paths non-empty, diff must touch at least one declared required path; if empty, note_on_empty must be present). |

---

## 3. Tier Parameter Sets

### 3.1 Tier 0 (tier-0)

> ⚡ **Dev-friendly tier**: minimum friction, minimum required artifacts, fast GO/NO-GO.
> Goal is to onboard developers to the protocol from day one.
> Security/evidence burden increases at tier-1+.

- required_evidence_kinds: `["diff", "command_log", "schema_validation", "policy_report"]`
- required_evidence_kinds_q: `["command_log", "policy_report", "schema_validation"]`
- command_log_mode: `"strings"`
- doc_impact_required: `false`
- test_policy:
  - required: `no`
  - allowed_skips: `yes`
  - flaky_handling: `treat as insufficient evidence only if it changes outcomes across reruns within envelope`
- scope_budgets:
  - max_touched_files: `50`
  - max_loc_delta: `5000`
  - forbidden_paths_enforcement: `relaxed`
- waiver_policy:
  - allowed: `yes`
  - max_active_waivers: `3`
  - requires_HOTL: `no`
- envelope_policy:
  - requires_attestation: `no`
  - attestation_signature_required: `no`
  - pinned_toolchain_refs_required: `yes`

### 3.2 Tier 1 (tier-1)
- required_evidence_kinds: `["diff", "command_log", "schema_validation", "policy_report", "test_report", "env_attestation"]`
- required_evidence_kinds_q: `["command_log", "policy_report", "schema_validation"]`
- command_log_mode: `"structured"`
- doc_impact_required: `false`
- test_policy:
  - required: `yes`
  - allowed_skips: `yes` (skips permitted only when they do not hide failing coverage; category-level)
  - flaky_handling: `unstable tests are insufficient evidence unless HOTL explicitly approves proceeding`
- scope_budgets:
  - max_touched_files: `25`
  - max_loc_delta: `2500`
  - forbidden_paths_enforcement: `strict`
- waiver_policy:
  - allowed: `yes`
  - max_active_waivers: `2`
  - requires_HOTL: `yes`
- envelope_policy:
  - requires_attestation: `yes`
  - attestation_signature_required: `no`
  - pinned_toolchain_refs_required: `yes`

### 3.3 Tier 2 (tier-2)
- required_evidence_kinds: `["diff", "command_log", "schema_validation", "policy_report", "test_report", "env_attestation"]`
- required_evidence_kinds_q: `["command_log", "policy_report", "schema_validation"]`
- command_log_mode: `"structured"`
- doc_impact_required: `true`
- test_policy:
  - required: `yes`
  - allowed_skips: `no` (skips are forbidden (not waivable in v1))
  - flaky_handling: `flaky/unstable evidence is NO-GO (not waivable in v1)`
- scope_budgets:
  - max_touched_files: `15`
  - max_loc_delta: `1500`
  - forbidden_paths_enforcement: `strict`
- waiver_policy:
  - allowed: `yes`
  - max_active_waivers: `1`
  - requires_HOTL: `yes`
- envelope_policy:
  - requires_attestation: `yes`
  - attestation_signature_required: `yes`
  - pinned_toolchain_refs_required: `yes`

### 3.4 Tier 3 (tier-3)
- required_evidence_kinds: `["diff", "command_log", "schema_validation", "policy_report", "test_report", "env_attestation", "genesis_seal"]`
- required_evidence_kinds_q: `["command_log", "policy_report", "schema_validation"]`
- command_log_mode: `"structured"`
- doc_impact_required: `true`
- test_policy:
  - required: `yes`
  - allowed_skips: `no`
  - flaky_handling: `any unstable evidence is NO-GO`
- scope_budgets:
  - max_touched_files: `10`
  - max_loc_delta: `800`
  - forbidden_paths_enforcement: `strict`
- waiver_policy:
  - allowed: `no`
  - max_active_waivers: `0`
  - requires_HOTL: `yes`
- envelope_policy:
  - requires_attestation: `yes`
  - attestation_signature_required: `yes`
  - pinned_toolchain_refs_required: `yes`

---

## 4. Tier → Gate Parameter Map
This table lists which tier parameters each check reads.

| gate_check_id | tier params read |
|---|---|
| Q1 | (none) |
| Q2 | (none) |
| Q3 | (none) |
| Q4 | (none) |
| Q5 | envelope_policy.pinned_toolchain_refs_required |
| Q6 | waiver_policy.allowed, waiver_policy.max_active_waivers, waiver_policy.requires_HOTL |
| Q7 | (none) |
| Q-EVIDENCE-002 | required_evidence_kinds_q |
| Q-DOC-001 | (none) |
| Q-DOC-002 | doc_impact_required |
| R1 | command_log_mode |
| R2 | scope_budgets.max_touched_files, scope_budgets.max_loc_delta |
| R3 | scope_budgets.forbidden_paths_enforcement |
| R4 | command_log_mode |
| R5 | test_policy.required, test_policy.allowed_skips, test_policy.flaky_handling, command_log_mode |
| R6 | envelope_policy.requires_attestation, envelope_policy.attestation_signature_required, command_log_mode |
| R7 | envelope_policy.pinned_toolchain_refs_required, command_log_mode |
| R8 | waiver_policy.allowed (whether a waiver can be considered at all), command_log_mode |
| R-DOC-001 | doc_impact_required |
