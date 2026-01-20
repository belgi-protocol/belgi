# BELGI Schemas

This folder contains Draft 2020-12 JSON Schemas for the BELGI protocol contracts. These schemas are **schema-only** artifacts and are intended to be strict for core gate artifacts, while supporting deterministic verification and replay.

Note: Some payload-style schemas intentionally allow extension fields (`additionalProperties: true`) for forward compatibility (for example `PolicyReportPayload` and `TestReportPayload`, and some nested objects inside `IntentSpec`). When a token vocabulary is required, the deterministic verifiers enforce it at runtime.

## Index

- DocsCompilationLogPayload: DocsCompilationLogPayload.schema.json
- EnvAttestationPayload: EnvAttestationPayload.schema.json
- EvidenceManifest: EvidenceManifest.schema.json
- GateVerdict: GateVerdict.schema.json
- GenesisSealPayload: GenesisSealPayload.schema.json
- HOTLApproval: HOTLApproval.schema.json
- IntentSpec: IntentSpec.schema.json
- LockedSpec: LockedSpec.schema.json
- PolicyReportPayload: PolicyReportPayload.schema.json
- ReplayInstructionsPayload: ReplayInstructionsPayload.schema.json
- SealManifest: SealManifest.schema.json
- TestReportPayload: TestReportPayload.schema.json
- Waiver: Waiver.schema.json

## Shared conventions

- schema_version is required and semver-like.
- All datetime fields are constrained by an RFC3339 regex `pattern` (and may also include `format: date-time`). Enforcement relies on the deterministic verifier, not validator-dependent "format assertions".
- ObjectRef shape (where used): { "id", "hash" (sha256), "storage_ref" }.
- Hashes are SHA-256 hex (pattern: ^[A-Fa-f0-9]{64}$).
- storage_ref values are local-only, repo/bundle-relative POSIX paths and MUST NOT include wildcards (`*`, `?`), traversal, backslashes, or URL schemes.
- Schemas intentionally avoid bypass-oriented heuristics; only category-level tokens are permitted where applicable.
- Failure ids are stable and machine-actionable: `<gate_id>-<rule_id>-NNN` (example: `R-R4-001`).

## IntentSpec and doc_impact (input vs compiled output)

### IntentSpec (input)
`IntentSpec.schema.json` validates the machine-parsed YAML object embedded in the input artifact `IntentSpec.core.md`.

Authoring guidance:
- Core template (canonical filename): `belgi/templates/IntentSpec.core.template.md`
- Gate Q validates presence/parseability/schema-validity before any LLM/C2 step: `gates/GATE_Q.md`

### LockedSpec.intent (compiled output)
`LockedSpec.intent` is the compiled, locked representation of the human intent used by deterministic gates. It is derived deterministically from IntentSpec by C1 and verified/locked by Gate Q (see Gate Q `Q-INTENT-003`).

### LockedSpec.environment_envelope pinned keys (audit-grade)
For Tier 2–3 (audit-grade) runs, `LockedSpec.environment_envelope` includes pinned public key references:
- `attestation_pubkey_ref`: Ed25519 public key used by Gate R (`R6`) when `envelope_policy.attestation_signature_required` is enabled.
- `seal_pubkey_ref`: Ed25519 public key reserved for Seal verification at stage S (signature enforcement is performed at sealing/replay, not at Gate R).

These are ObjectRef values and are intended to prevent attacker-controlled key substitution.
### doc_impact
`doc_impact` is a first-class declaration of documentation update requirements:
- In IntentSpec: `doc_impact` is required by schema.
- In LockedSpec: `doc_impact` is required for Tier 2–3 by schema (`LockedSpec.schema.json#/allOf`), and is enforced by Gate Q (`Q-DOC-002`) and Gate R (`R-DOC-001`).

Deterministic rule (schema-enforced): if `doc_impact.required_paths` is empty `[]`, then `doc_impact.note_on_empty` MUST be present and non-empty.

## Examples

### LockedSpec example

```json
{
  "schema_version": "1.0.0",
  "belgi_version": "0.2.0",
  "run_id": "run-example-001",
  "intent": {
    "intent_id": "intent-001",
    "title": "Add initial schema set",
    "narrative": "Produce strict JSON Schemas for run contracts.",
    "scope": "schemas/ only",
    "success_criteria": "Schemas validate and introduce no magic fields."
  },
  "tier": {
    "tier_id": "tier-0",
    "tier_name": "Tier 0",
    "tolerances_ref": {
      "id": "tol-001",
      "hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "storage_ref": "bundle/tolerances/tol-001.json"
    }
  },
  "environment_envelope": {
    "id": "env-001",
    "description": "Windows + pinned tooling",
    "expected_runner": "ci:windows-latest",
    "pinned_toolchain_refs": [
      {
        "id": "toolchain-001",
        "hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "storage_ref": "bundle/toolchains/toolchain-001.json"
      }
    ]
  },
  "invariants": [
    {
      "id": "inv-001",
      "description": "Only files under schemas/ are modified.",
      "severity": "policy"
    }
  ],
  "constraints": {
    "allowed_paths": ["schemas/"],
    "forbidden_paths": ["CANONICALS.md"],
    "max_touched_files": 6,
    "max_loc_delta": 2000,
    "forbidden_primitives": ["bypass-oriented-heuristics"]
  },
  "compilation": {
    "compiler_id": "C1",
    "compiler_version": "1.0",
    "compiled_at": "2000-01-01T00:00:00Z",
    "source_hashes": [
      "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    ]
  },
  "prompt_bundle_ref": {
    "id": "prompt-001",
    "hash": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    "storage_ref": "bundle/prompts/prompt-001.json"
  },
  "upstream_state": {
    "repo_ref": "github:example/belgi",
    "commit_sha": "0123456789abcdef0123456789abcdef01234567",
    "dirty_flag": false
  },
  "waivers_applied": ["waiver-001"]
}
```

### GateVerdict example (NO-GO)

```json
{
  "schema_version": "1.0.0",
  "run_id": "run-example-001",
  "gate_id": "R",
  "verdict": "NO-GO",
  "failure_category": "FR-SCHEMA-ARTIFACT-INVALID",
  "failures": [
    {
      "id": "R-R4-001",
      "category": "FR-SCHEMA-ARTIFACT-INVALID",
      "rule_id": "R4",
      "message": "Evidence manifest does not match schema.",
      "evidence_refs": [
        {
          "id": "ev-001",
          "hash": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
          "storage_ref": "bundle/evidence/ev-001.json"
        }
      ]
    }
  ],
  "remediation": {
    "next_instruction": "Do fix the evidence manifest schema mismatch then re-run R.",
    "constraints": ["Do not change canonicals."]
  },
  "evidence_manifest_ref": {
    "id": "evidence-manifest-001",
    "hash": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "storage_ref": "bundle/evidence/manifests/evidence-manifest-001.json"
  },
  "evaluated_at": "2000-01-01T00:10:00Z",
  "evaluator": "system:gate-r"
}
```

### GateVerdict example (GO)

```json
{
  "schema_version": "1.0.0",
  "run_id": "run-example-001",
  "gate_id": "Q",
  "verdict": "GO",
  "failure_category": null,
  "failures": [],
  "evidence_manifest_ref": {
    "id": "evidence-manifest-001",
    "hash": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "storage_ref": "bundle/evidence/manifests/evidence-manifest-001.json"
  },
  "evaluated_at": "2000-01-01T00:02:00Z",
  "evaluator": "system:gate-q"
}
```

### EvidenceManifest example

```json
{
  "schema_version": "1.0.0",
  "run_id": "run-example-001",
  "artifacts": [
    {
      "kind": "diff",
      "id": "diff-001",
      "hash": "1111111111111111111111111111111111111111111111111111111111111111",
      "media_type": "text/x-diff",
      "storage_ref": "bundle/artifacts/diff-001.patch",
      "produced_by": "C2"
    }
  ],
  "commands_executed": [
    {
      "argv": ["pwsh", "-Command", "git status"],
      "exit_code": 0,
      "started_at": "2000-01-01T00:01:00Z",
      "finished_at": "2000-01-01T00:01:01Z"
    }
  ],
  "test_summary": {
    "total": 0,
    "passed": 0,
    "failed": 0,
    "skipped": 0,
    "duration_seconds": 0
  },
  "envelope_attestation": {
    "id": "env-attest-001",
    "hash": "2222222222222222222222222222222222222222222222222222222222222222",
    "storage_ref": "bundle/attestations/env-attest-001.json"
  },
  "notes": "Tier-dependent evidence may require additional artifacts."
}
```

### SealManifest example

```json
{
  "schema_version": "1.0.0",
  "belgi_version": "0.2.0",
  "run_id": "run-example-001",
  "locked_spec_ref": {
    "id": "lockedspec-001",
    "hash": "3333333333333333333333333333333333333333333333333333333333333333",
    "storage_ref": "bundle/locked/lockedspec-001.json"
  },
  "gate_q_verdict_ref": {
    "id": "q-001",
    "hash": "4444444444444444444444444444444444444444444444444444444444444444",
    "storage_ref": "bundle/verdicts/q-001.json"
  },
  "gate_r_verdict_ref": {
    "id": "r-001",
    "hash": "5555555555555555555555555555555555555555555555555555555555555555",
    "storage_ref": "bundle/verdicts/r-001.json"
  },
  "evidence_manifest_ref": {
    "id": "evidence-manifest-001",
    "hash": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "storage_ref": "bundle/evidence/manifests/evidence-manifest-001.json"
  },
  "waivers": [],
  "final_commit_sha": "0123456789abcdef0123456789abcdef01234567",
  "signature_alg": "ed25519",
  "signature": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A=",
  "sealed_at": "2000-01-01T00:30:00Z",
  "seal_hash": "6666666666666666666666666666666666666666666666666666666666666666",
  "signer": "human:release-manager",
  "replay_instructions_ref": {
    "id": "replay-001",
    "hash": "7777777777777777777777777777777777777777777777777777777777777777",
    "storage_ref": "bundle/replay/replay-001.json"
  }
}
```

### Waiver example

```json
{
  "schema_version": "1.0.0",
  "waiver_id": "waiver-001",
  "gate_id": "R",
  "rule_id": "R5",
  "scope": "tests: allow skip of integration suite for this run only",
  "justification": "CI environment missing required dependency; will be restored next run.",
  "approver": "human:tech-lead",
  "created_at": "2000-01-01T00:05:00Z",
  "expires_at": "2000-01-08T00:00:00Z",
  "audit_trail_ref": {
    "id": "audit-001",
    "storage_ref": "bundle/audit/audit-001.json"
  },
  "status": "active"
}
```

### HOTLApproval example

```json
{
  "schema_version": "1.0.0",
  "approver": "human:alice@example.com",
  "approval_type": "post-proposal",
  "decision": "approved",
  "reviewed_artifacts": [
    {
      "id": "policy_report.invariant_eval",
      "hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "storage_ref": "evidence/policy_report.invariant_eval.json"
    }
  ],
  "conditions": [],
  "approved_at": "2000-01-01T00:06:00Z"
}
```

#### HOTLApproval Purpose

HOTLApproval artifacts enforce **human-on-the-loop (HOTL) approvals** for audit-grade runs, preventing role confusion where LLM/agent decisions might be attributed to humans.

**Scope:** Tier-2+ (audit-grade) runs MUST include a valid HOTLApproval artifact in EvidenceManifest. Tier-1 runs trigger a warning if missing.

**Key fields:**
- `approver`: **MUST** use format `human:<identity>` (regex: `^human:[A-Za-z0-9_.@+-]+$`) to prevent LLM/agent spoofing.
- `approval_type`: One of `pre-proposal`, `post-proposal`, `post-gate-r`, `seal-authorization`. Indicates when approval was given relative to the proposal.
- `decision`: One of `approved`, `approved-with-conditions`, `rejected`.
- `reviewed_artifacts`: ObjectRef array listing which evidence artifacts the human actually reviewed (required for audit trail).
- `conditions`: Array of strings describing approval conditions (required when decision="approved-with-conditions").

**Enforcement (Gate Q-HOTL-001):**
- Tier-2/3: FAIL if no `hotl_approval` artifact found.
- Tier-1: WARNING if missing (backward compatibility).
- Tier-0: No requirement.

## Schema ↔ Canonicals Mapping

| Schema | Canonical anchors (single source of truth) | Notes |
|---|---|---|
| LockedSpec | CANONICALS.md#lockedspec, CANONICALS.md#p-intent, CANONICALS.md#tier-packs, CANONICALS.md#environment-envelope, CANONICALS.md#waivers, CANONICALS.md#blast-radius | Represents the locked run contract used by gates. |
| GateVerdict | CANONICALS.md#q-gate-1-lock-verify, CANONICALS.md#r-gate-2-verify, CANONICALS.md#failure-taxonomy-interface, CANONICALS.md#go, CANONICALS.md#no-go, CANONICALS.md#evidence-sufficiency | Includes rule_id per Failure Taxonomy Interface. |
| EvidenceManifest | CANONICALS.md#evidence-bundle, CANONICALS.md#evidence-sufficiency, CANONICALS.md#environment-envelope, CANONICALS.md#bounded-trust | Evidence index supports determinism and replay checks. |
| SealManifest | CANONICALS.md#s-seal, CANONICALS.md#lockedspec, CANONICALS.md#waivers, CANONICALS.md#evidence-bundle | Seals references/hashes without embedding bypass heuristics. |
| GenesisSealPayload | CANONICALS.md#evidence-bundle, CANONICALS.md#bounded-trust | Signed genesis root-of-trust payload required for Tier-3 runs (enforced by Gate R R4). |
| Waiver | CANONICALS.md#waivers, CANONICALS.md#hotl, CANONICALS.md#no-go | Waivers are explicitly human-authored and time-bounded. |
| HOTLApproval | CANONICALS.md#hotl, CANONICALS.md#role-confusion | Human-on-the-loop approvals prevent role confusion (LLM/agent ↔ human) in audit-grade runs. Enforced by Gate Q (Q-HOTL-001). |
| EnvAttestationPayload | CANONICALS.md#environment-envelope, CANONICALS.md#bounded-trust | Payload for env_attestation evidence; validated and bound at Gate R (R6) to prevent hollow or unbound attestations. |
| DocsCompilationLogPayload | CANONICALS.md#c3-docs-compiler, CANONICALS.md#publication-posture, CANONICALS.md#evidence-bundle | Payload for docs_compilation_log evidence (C3). Public-safe disclosure surface for prompt block hashes; Gate R validates when present. |

## Known gaps (canonicalization pending)

- Failure category vocabulary: the canonical token set is defined in `gates/failure-taxonomy.md` (as `category_id` values). Schemas keep category fields as strings; deterministic gate tooling validates membership against the taxonomy.
- Invariant severity vocabulary: CANONICALS defines invariants conceptually but not severity levels; keep as token string until canonized.
- Forbidden primitive category vocabulary: CANONICALS and trust-model emphasize category-level checks, but do not define token lists for forbidden_primitives.
- Commit hash algorithm: schemas currently assume git SHA-1 (commit_sha/final_commit_sha are 40-hex). If protocol shifts to SHA-256, canonize and update patterns.

## Verification

Schema validation is necessary but not sufficient.

Authoritative verification for schema adherence and deterministic rules is performed by the deterministic verifier tooling:

- Gate Q entrypoint: `chain/gate_q_verify.py` (IntentSpec parsing + schema checks + lock/verify steps)
- Gate R entrypoint: `chain/gate_r_verify.py` (LockedSpec + EvidenceManifest verification, report emission, and GateVerdict output)

See the gate policies and operations manual for the MUST-level verification obligations:

- `gates/GATE_Q.md`
- `gates/GATE_R.md`
- `docs/operations/running-belgi.md`
