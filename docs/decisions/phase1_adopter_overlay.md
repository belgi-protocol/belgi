# Phase 1 Adopter Overlay Model

Status: accepted  
Scope: BELGI kernel + adopter integration surface (no canonical contamination)

## Decision

BELGI remains the canonical chain runner and canonical contract owner.

- Canonical protocol surface remains in BELGI canonicals/schemas/gates/tiers.
- Adopter-specific obligations are expressed as overlay data and policy report checks.
- Overlay checks are optional inputs to verification and are fail-closed when supplied.

## Mental Model

### One-time initialization

`belgi init` writes repository defaults only:

- `.belgi/adopter.toml` (stable defaults, not per-run mutable state)
- `.belgi/README.md` (layout + invariants)
- `.belgi/templates/IntentSpec.core.template.md` (repo-local template copied from BELGI package)
- `belgi_pack/DomainPackManifest.json` (adopter overlay stub)

`belgi init` MUST NOT copy BELGI canonical files (`schemas/`, `gates/`, `tiers/`) into adopter repositories.

### Per-run authority

Per-run authority is run-local workspace + LockedSpec:

- `.belgi/runs/<run_id>/` contains run artifacts for that run only.
- `LockedSpec.json` and referenced evidence hashes are authoritative for verification.
- `.belgi/adopter.toml` is never rewritten by run execution.

### Dev cadence

Dev cadence for adopter repositories:

1. start run workspace (`.belgi/runs/<run_id>/`)
2. fill IntentSpec
3. C1 compile + run Gate Q repeatedly until stable
4. do implementation work (C2 untrusted proposer or human changes)
5. run Gate R at meaningful checkpoints
6. optional C3 in dev
7. optional seal + Gate S in dev; mandatory for release/audit workflows

## Overlay contract (Phase 1)

Overlay file: `DomainPackManifest.json` (adopter-owned)

Required fields:

- `format_version` (int)
- `pack_name` (string)
- `pack_semver` (string)
- `belgi_protocol_pack_pin`:
  - `pack_name`
  - `pack_id`
  - `manifest_sha256`
- `required_policy_check_ids` (array of check IDs)

Verification behavior when overlay is provided:

1. load overlay manifest (strict JSON parsing, fail-closed)
2. verify overlay pin equals active protocol pack identity
3. verify required policy check IDs are present with `passed == true` in schema-valid `policy_report` payloads
4. fail NO-GO on any mismatch

## Governance constraints

- No adopter/service terms in canonicals/schemas/gates/tiers.
- No new `EvidenceManifest.artifacts[].kind` values for adopter data.
- No hardcoded builtin pack file paths; pack identity comes from BELGI protocol loader.
- No second chain runner in adopter repos.
- Overlay is additive verification only; canonical gate semantics remain unchanged.
