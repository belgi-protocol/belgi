<!-- generated: tiers/tier-packs.json ; run: python -m tools.render tier-packs --repo . -->
# BELGI Tier Packs

## 0. Rule of Use (Canonical Pointer)
This file defines **tier parameter defaults** used by gate enforcement procedures. It MUST NOT redefine canonical terms.
Tier Packs are canonically defined in [CANONICALS.md#tier-packs](https://github.com/belgi-protocol/belgi/blob/main/CANONICALS.md#tier-packs).

## 1. Tier IDs
Tier packs are referenced by `LockedSpec.tier.tier_id`.

{{TP_TIER_IDS_LIST}}

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
- `IntentSpec.doc_impact` is always present (schema-required by [../schemas/IntentSpec.schema.json](../schemas/IntentSpec.schema.json) and verified by Gate Q).
- `LockedSpec.doc_impact` presence is tier-controlled via `doc_impact_required` and enforced by Gate Q `Q-DOC-002`.

{{TP_DOC_IMPACT_POLICY_MAP_TABLE}}

---

## 3. Tier Parameter Sets

### 3.1 Tier 0 (tier-0)

> ⚡ **Dev-friendly tier**: minimum friction, minimum required artifacts, fast GO/NO-GO.
> Goal is to onboard developers to the protocol from day one.
> Security/evidence burden increases at tier-1+.

{{TP_TIER_0_PARAMS}}

### 3.2 Tier 1 (tier-1)
{{TP_TIER_1_PARAMS}}

### 3.3 Tier 2 (tier-2)
{{TP_TIER_2_PARAMS}}

### 3.4 Tier 3 (tier-3)
{{TP_TIER_3_PARAMS}}

---

## 4. Tier → Gate Parameter Map
This table lists which tier parameters each check reads.

{{TP_GATE_PARAMETER_MAP_TABLE_PREFIX}}
| R8 | waiver_policy.allowed (whether a waiver can be considered at all), command_log_mode |
{{TP_GATE_PARAMETER_MAP_TABLE_SUFFIX}}
