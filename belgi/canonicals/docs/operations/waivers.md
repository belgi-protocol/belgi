# Waivers (LLM-closed waiver lifecycle)

Waivers are **explicit, human-authored artifacts** that permit a scoped, time-bounded exception to a specific rule/check for a specific run.

This document is grounded in:
- Canonical waiver rules: `../../CANONICALS.md#waivers`
- Waiver schema: `../../schemas/Waiver.schema.json`
- Gate Q waiver enforcement: Q6 in `../../gates/GATE_Q.md`
- Gate R waiver usage: R3 in `../../gates/GATE_R.md`
- Tier waiver policy limits (canonical SSOT): `../../tiers/tier-packs.json`
  - Generated view (must match canonical): `../../tiers/tier-packs.md`

## 1) Policy principles (non-negotiable)

1) Waivers are schema artifacts
- A waiver MUST be a standalone JSON document that validates against `Waiver.schema.json`.

2) Waivers are human-controlled
- Waivers MUST NOT be created, edited, approved, extended, revoked, or applied by an LLM/proposer.
- The proposer (C2) is explicitly **forbidden** from waiver actions.

3) Waivers are time-bounded and scoped
- `expires_at` is required by schema.
- `scope` must be specific and bounded (schema text).

4) Waivers are auditable
- `audit_trail_ref` (id + storage_ref) is required by schema.

5) Waivers must be visible in sealing
- SealManifest includes `waivers[]` as ObjectRef references (see `SealManifest.schema.json`).

## 2) Roles

### 2.1 Requester (human)
- Drafts the waiver request content and gathers supporting rationale.

### 2.2 Approver (human / HOTL)
- Approves and signs off on the waiver.
- Must be represented in `Waiver.approver`.
- Schema requirement: approver identity class MUST be human and MUST NOT be an LLM/agent.

### 2.3 Operator (human / CI)
- Ensures the waiver document is present, schema-valid, unexpired, and correctly referenced by the run artifacts.

### 2.4 Proposer (LLM) — forbidden
The proposer MUST NOT:
- create a waiver document,
- edit waiver content,
- select `gate_id` / `rule_id` for a waiver,
- set or change `expires_at`,
- change `status` (active/expired/revoked),
- add/remove `LockedSpec.waivers_applied[]`,
- add/remove `SealManifest.waivers[]`.

## 3) Lifecycle (human-controlled)

### 3.1 Create request (human)
- Create a waiver JSON document with required fields:
  - `schema_version`, `waiver_id`, `gate_id` ("Q" or "R"), `rule_id`, `scope`, `justification`, `approver`, `created_at`, `expires_at`, `audit_trail_ref`, `status`.
- Set `status: "active"` for an active waiver.

Artifact produced:
- Waiver document (schema: `Waiver.schema.json`).

Evidence kinds to record:
- `schema_validation` (waiver validates)
- `policy_report` (category-level summary that a waiver was requested; no bypass details)

Gate checks satisfied:
- Gate Q: Q6 (Waivers validity) when applied pre-proposal

### 3.2 Approve + sign (human)
- The approver reviews scope and justification and ensures the waiver is time-bounded.
- The approver identity is recorded in `Waiver.approver`.

Artifact produced:
- Updated waiver document remains schema-valid.

### 3.3 Store (storage_ref)
- Store the waiver document in a retrievable location.
- Ensure it can be referenced by ObjectRef (`id`, `hash`, `storage_ref`) from downstream artifacts.

Artifact produced:
- ObjectRef addressing the waiver content (used by `SealManifest.waivers[]` and potentially by evidence refs).

### 3.4 Apply to a run (LockedSpec.waivers_applied)
- A human updates the candidate LockedSpec to include the waiver document **storage reference** in `LockedSpec.waivers_applied[]`.
  - Each entry MUST be a repo/bundle-relative `storage_ref` string that resolves to the waiver JSON bytes.

Artifacts produced:
- Candidate `LockedSpec.json` (schema: `LockedSpec.schema.json`) referencing waiver IDs.

Evidence kinds to record:
- `schema_validation` (LockedSpec validates)
- `policy_report` (category-level record of waiver application)

Gate checks satisfied:
- Gate Q: Q6 validates:
  - tier allows waivers,
  - waiver count ≤ `max_active_waivers`,
  - waiver schema-valid,
  - `status == "active"`,
  - `expires_at` is present, RFC3339-parseable, and compares after Gate Q’s deterministic evaluation baseline (Gate Q does not rely on ambient wall-clock time for determinism),
  - and a v1 human-authorship check (approver must not contain substrings `llm` or `agent`, case-insensitive).
  - For tier-1..3, the approver MUST use `human:<identity>` format.

### 3.5 Revoke or expire (human)
- To revoke, a human updates `Waiver.status` to `"revoked"`.
- To expire, time passes beyond `expires_at`, or a human updates status to `"expired"`.

Artifacts produced:
- Updated waiver document (schema: `Waiver.schema.json`).

Gate impact:
- Gate Q (Q6) rejects expired/inactive waivers applied to a run.
- Gate R will only consider waivers when they are present, active, and consistent with the rule being waived.

## 4) Enforcement points (where LLM actions are blocked)

### 4.1 Process enforcement (must be implemented by operators/CI)
- Waiver documents are only accepted from human-controlled sources (e.g., protected branches / restricted storage).
- Proposer outputs must be treated as untrusted; any waiver-related changes proposed by C2 are rejected out-of-band.

### 4.2 Gate Q enforcement (pre-LLM)
Gate Q Q6 (`../../gates/GATE_Q.md`) enforces:
- waiver tier policy (`waiver_policy.allowed`, `max_active_waivers`),
- schema validity (`Waiver.schema.json`),
- `status == "active"`,
- `expires_at` after Gate Q evaluation time,
- human-authorship heuristic (approver string must not contain `llm` or `agent`).

### 4.3 Gate R enforcement (post-proposal)
Gate R uses waiver documents as inputs when referenced by `LockedSpec.waivers_applied[]`.

Specific deterministic waiver usage in v1:
- R3 (forbidden paths) in `../../gates/GATE_R.md`:
  - If `forbidden_paths_enforcement == "strict"`, forbidden-path violations are NOT waivable.
  - If `forbidden_paths_enforcement == "relaxed"`, a forbidden-path violation is only allowed if there exists an active waiver where:
    - `gate_id == "R"`
    - `rule_id == "R3.forbidden_paths"`
    - `scope` contains the offending path as a literal substring.

Note: Gate R does not consume SealManifest (Seal occurs after R). Seal inclusion is enforced at sealing/replay time.

## 5) Abuse prevention (tier limits and waivability)

### 5.1 Limits per tier
From `../../tiers/tier-packs.json` (canonical SSOT; see `../../tiers/tier-packs.md` for the generated view):
- Tier 0: waivers allowed, max 3 active
- Tier 1: waivers allowed, max 2 active, HOTL required (policy-level)
- Tier 2: waivers allowed, max 1 active, HOTL required (policy-level)
- Tier 3: waivers not allowed

### 5.2 Strict vs relaxed forbidden-path waivability
From R3 and tier defaults:
- Tier 1–3 use `forbidden_paths_enforcement: strict` (not waivable)
- Tier 0 uses `forbidden_paths_enforcement: relaxed` (waivable only with an explicit, active waiver scoped to the violating path)

## 6) Waiver checklist (manual verification)

| Field (Waiver.schema.json) | Required | Manual check |
|---|---:|---|
| `schema_version` | yes | Matches semver-like pattern; correct schema revision used |
| `waiver_id` | yes | Unique and stable for this waiver |
| `gate_id` | yes | Exactly "Q" or "R"; matches intended gate |
| `rule_id` | yes | Exact rule identifier being waived |
| `scope` | yes | Bounded, specific; does not exceed declared blast radius |
| `justification` | yes | Category-level; no bypass instructions |
| `approver` | yes | Human identity class; not an LLM/agent |
| `created_at` | yes | RFC3339 date-time |
| `expires_at` | yes | RFC3339 date-time; not expired for the run |
| `audit_trail_ref.id` + `audit_trail_ref.storage_ref` | yes | Points to a human-auditable record |
| `status` | yes | "active" for applied waivers; revoked/expired not applied |
