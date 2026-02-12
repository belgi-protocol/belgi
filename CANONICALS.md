# Belgi Protocol (BELGI) Canonicals (Sprint 1)

<a id="purpose"></a>
## 0. Purpose (Canonical)
BELGI is a protocol for development under probabilistic cognition.

<a id="bounded-claim"></a>
## 1. Bounded Claim (Canonical)
“Deterministic validation of probabilistic execution within a declared environment envelope.”

This claim is scoped: deterministic validation holds ONLY within the declared Environment Envelope and LockedSpec inputs, and MUST NOT be interpreted as a claim of universal determinism across environments, toolchains, or unstated conditions.

## Anchor Registry (Stable IDs)
This section is a mechanical registry of stable anchor IDs for downstream references.

- purpose
- bounded-claim
- canonical-chain
- canonical-stages
- p-intent
- c1-prompt-compiler
- q-gate-1-lock-verify
- c2-propose
- r-gate-2-verify
- r-verifier-responsibilities
- c3-docs-compiler
- s-seal
- trust-model-overview
- principle
- evidence-bundle
- tier-packs
- waivers
- publication-posture
- propagation-consistency-sweep
- propagation-sweep
- failure-taxonomy-interface
- additional-terms
- environment-envelope
- bounded-trust-execution-envelope
- bounded-trust
- deterministic-belgi
- evidence-sufficiency
- evidence-sufficiency-conceptual
- lockedspec
- blast-radius
- hotl
- protocol-pack
- protocol-pack-identity
- protocol-pack-symlink-policy
- evaluated-revision
- r-snapshot
- replay-integrity
- wheel-vs-repo-local
- pack-mirror-drift
- no-go
- go

<a id="canonical-chain"></a>
## 2. Canonical Chain (Canonical)
P → C1 → Q → C2 → R → C3 → S

<a id="canonical-stages"></a>
## 3. Canonical Stages (Chain Definitions)

<a id="p-intent"></a>
### P — Intent (Canonical)
P Intent is the human-authored, unambiguous statement of the outcome, constraints, and acceptance criteria for a run, written to be compiled into invariants without relying on unstated assumptions; if P is missing required details, P MUST be amended by the human author rather than inferred by the LLM.

<a id="c1-prompt-compiler"></a>
### C1 — Prompt Compiler (Canonical)
C1 Prompt Compiler is a deterministic transformation that maps P into a structured prompt + constraints package for the proposer, ensuring scope, constraints, and required evidence are explicit and stable across retries; C1 MUST also carry forward any pre-declared Tier Pack selection and any declared envelope inputs so Q can lock/verify them into the LockedSpec.

<a id="q-gate-1-lock-verify"></a>
### Q — Gate 1 Lock & Verify (Canonical)
Q Gate 1 Lock & Verify is the first deterministic gate that locks the declared environment envelope and verifies that P is sufficiently specific to compile invariants and acceptance checks; “If P is too vague to compile invariants, the run is NO-GO at Q, not later.”

<a id="c2-propose"></a>
### C2 — Propose (probabilistic) (Canonical)
C2 Propose is an untrusted, probabilistic step (typically an LLM) that produces candidate artifacts (patches, plans, explanations) that attempt to satisfy the locked intent and constraints, but whose outputs MUST be treated as unverified until passing deterministic verification.

<a id="r-gate-2-verify"></a>
### R — Gate 2 Verify (deterministic) (Canonical)
R Gate 2 Verify is the deterministic verification step that evaluates the proposed artifacts against the locked intent, environment envelope, and required evidence rules, and MUST return GO only if checks pass and evidence is sufficient.

<a id="r-verifier-responsibilities"></a>
#### Verifier Responsibilities (Gate R) (Canonical Summary)
Gate R MUST implement the following responsibility categories at a policy/interface level (category descriptions only; bypass-oriented rule details MUST remain private):
- R1 Intent invariants: verify compiled acceptance criteria and invariants from P are met.
- R2 Scope / Blast Radius: verify changes remain within declared Blast Radius and scope constraints.
- R3 Policy invariants: verify required policy constraints (e.g., safety/compliance constraints as declared) are satisfied.
- R4 Schema / contract: verify outputs conform to declared schemas/contracts and interface requirements.
- R5 Tests: verify required test evidence exists and meets Tier Pack requirements.
- R6 Envelope attestation: verify evidence is produced within the declared Environment Envelope.
- R7 Supply chain changes: detect and account for dependency/toolchain changes that affect evidence validity.
- R8 Adversarial diff scan category: scan diffs for adversarial or policy-violating patterns at a category level.

<a id="c3-docs-compiler"></a>
### C3 — Docs Compiler (deterministic) (Canonical)
C3 Docs Compiler is a deterministic transformation that produces or updates documentation artifacts from the verified state (including canonical pointers, evidence references, and change summaries) such that the documented contract matches what was verified.

<a id="s-seal"></a>
### S — Seal (Canonical)
S Seal is the deterministic act of sealing the run outputs (artifacts + evidence + declared envelope + waivers, if any) into an auditable record that can be reproduced or challenged within the same declared environment envelope.

<a id="trust-model-overview"></a>
## 4. Trust Model Overview (Canonical)
- Untrusted by default: any LLM output, any free-form text in the repo that is not locked/verified, and any proposed diffs prior to verification.
- Bounded-trust: execution via CLI/CI tools ONLY within the declared Environment Envelope and ONLY for the purposes of producing verifiable evidence (e.g., builds, tests, linters); anything outside the envelope MUST be treated as untrusted.
- Deterministic components: the gates (Q, R) and compilers (C1, C3) MUST be deterministic with respect to their inputs (locked P, locked envelope, and declared rules) and MUST produce stable pass/fail decisions.

<a id="principle"></a>
## 5. Principle (Canonical)
LLMs propose; gates dispose.

<a id="tier-packs"></a>
## 6. Tier Packs (Tier 0–3) (Canonical, No Numbers Yet)
Tier Packs are named policy bundles that configure what varies across runs without changing the canonical chain: tolerances (e.g., what deviations are acceptable), evidence strictness (e.g., which verifications are required and how broad they must be), and HOTL requirements (e.g., when explicit human approval is mandatory); Tier Packs MUST NOT change the meaning of GO/NO-GO and MUST be declared before proposing begins.

<a id="waivers"></a>
## 7. Waivers (Canonical)
A Waiver is an explicit, human-authored artifact that temporarily permits a scoped exception to a specific rule/check for a specific run.

Waivers MUST:
- NOT disable gates globally; they may only grant a scoped exception to a specific rule/check.
- Reference the exact rule they waive and the gate at which it applies.
- Be time-bounded (expiry is required).
- Be visible in the final Seal manifest as an explicit dependency.

Waivers MUST include, at minimum:
- rule_id
- gate_id
- scope
- justification
- approver identity class
- created_at
- expiry
- audit trail reference

Waivers MUST NOT be created by an LLM.

<a id="publication-posture"></a>
## 8. Publication Posture (Canonical)
BELGI SHOULD publish the protocol and interfaces needed for independent verification (e.g., stage contracts, evidence categories, and deterministic gate behaviors) but MUST keep bypass-oriented rule details private (MUST NOT publish exploit signatures, evasion thresholds, or other bypass-friendly specifics; only categories of checks may be described).

Adopter overlays (e.g., `DomainPackManifest.json`) are non-canonical, adopter-owned inputs. They MAY add fail-closed verification requirements only when explicitly supplied to verification entrypoints; they MUST NOT modify canonical schema/gate/tier semantics.

<a id="propagation-consistency-sweep"></a>
<a id="propagation-sweep"></a>
## 9. Propagation / Consistency Sweep (Canonical)
Whenever canonicals, templates, or manuals change, a propagation/consistency sweep MUST be performed across all of them to eliminate contradictions and ensure every term and contract still points back to CANONICALS; note: in later sprints this expands to schemas/gates/manuals.

<a id="failure-taxonomy-interface"></a>
## 10. Failure Taxonomy Interface (Canonical)
Any NO-GO decision produced by a gate MUST include:
- A machine-parseable failure category.
- An explicit gate identifier.
- An explicit rule identifier (or rule reference) for the failing check.
- An exact next remediation instruction in a fixed, machine-parseable format.

Required remediation instruction format (interface only; the taxonomy itself is defined elsewhere):

failure.category: <token>
failure.gate_id: <token>
failure.rule_id: <token>
failure.next_instruction: "Do <ACTION> then re-run <GATE_ID>."

<a id="additional-terms"></a>
## 11. Additional Canonical Terms (Definitions)

<a id="environment-envelope"></a>
### Environment Envelope (Canonical)
The Environment Envelope is the declared, lockable description of the execution context (toolchain, dependencies, platform, and configuration surface) within which deterministic verification is claimed to hold, and outside of which results MUST NOT be considered validated.

<a id="bounded-trust-execution-envelope"></a>
<a id="bounded-trust"></a>
### Bounded-Trust Execution Envelope (Canonical)
A Bounded-Trust Execution Envelope is the operational rule that CLI/CI execution is trusted only to the extent it stays inside the declared Environment Envelope and produces reproducible evidence, with all external effects and out-of-envelope behaviors treated as untrusted.

<a id="deterministic-belgi"></a>
### Deterministic (BELGI Sense) (Canonical)
Deterministic (in BELGI) means that given the same locked inputs (P, rules, and Environment Envelope) and the same verified source state, the gate or compiler yields the same decision and materially equivalent outputs, with any allowable variance explicitly declared by the selected Tier Pack.

<a id="evidence-bundle"></a>
### Evidence Bundle (Canonical)
An Evidence Bundle is the minimal, declared set of artifacts and outputs required to justify a GO decision (e.g., test results, build logs, static analysis outputs, diffs, and envelope declaration) as determined by the selected Tier Pack and the gate rules.

<a id="evidence-sufficiency"></a>
### Evidence Sufficiency (Canonical)
Evidence Sufficiency is the gate-level determination that the Evidence Bundle covers all required checks for the selected Tier Pack, addresses the acceptance criteria compiled from P, and is consistent with the locked Environment Envelope; if sufficiency cannot be established, the decision MUST be NO-GO.

<a id="evidence-sufficiency-conceptual"></a>
#### Evidence Sufficiency (conceptual) (Canonical)
For a GO verdict, evidence MUST exist (as applicable under the selected Tier Pack) to support deterministic verification within the declared Environment Envelope, including at minimum:
- Diff stats summary (what changed, where, and how much; category-level, not bypass-focused).
- Test reports (results and scope).
- Command log (what was executed to produce evidence).
- Environment Envelope attestation (what envelope was used).
- Policy checks summary (what policy categories were checked and pass/fail outcomes).
- Cryptographic hashes for key artifacts (inputs, outputs, evidence files) sufficient to detect tampering.

This evidence supports deterministic validation inside the declared envelope and MUST NOT be interpreted as proving universal determinism or program semantic correctness outside the protocol scope.

<a id="lockedspec"></a>
### LockedSpec (Canonical)
LockedSpec is the locked, immutable snapshot of the run's controlling inputs (P, selected Tier Pack, Environment Envelope, applicable waivers, and protocol pack identity) used by gates to ensure proposals are judged against a stable contract. The `protocol_pack` binding (pack_id, manifest_sha256, pack_name, source) MUST be required and gates MUST verify it matches the active protocol pack or fail closed.

<a id="blast-radius"></a>
### Blast Radius (Canonical)
Blast Radius is the declared scope of impact a change is permitted to have (files, modules, behaviors, and operational surfaces), used to constrain proposals and to determine which verification evidence is required.

<a id="hotl"></a>
### HOTL (Human-On-The-Loop) (Canonical)
HOTL is a required human control point in which a human reviews and explicitly approves specified decisions or artifacts (e.g., P wording, waivers, or GO authorization), with the required moments determined by the selected Tier Pack.

<a id="no-go"></a>
### NO-GO (Canonical)
NO-GO is a deterministic gate outcome indicating verification failed or evidence is insufficient under the LockedSpec, and it MUST stop progression to later stages until the cause is corrected or a valid Waiver is issued (where permitted).

<a id="go"></a>
### GO (Canonical)
GO is a deterministic gate outcome indicating verification passed and evidence is sufficient under the LockedSpec for the selected Tier Pack, permitting progression to the next canonical stage.

<a id="protocol-pack"></a>
### Protocol Pack (Canonical)
A Protocol Pack is a versioned, immutable bundle of protocol support files (schemas, gate definitions, tier configurations) that governs a BELGI run. The pack is resolved at runtime (builtin, vendored, or override) and its identity is bound into the LockedSpec and SealManifest.

<a id="protocol-pack-identity"></a>
### Protocol Pack Identity (Canonical)
Protocol pack identity is the deterministic binding that allows verification of which protocol rules governed a run.

**Identity fields (required for binding):**
- `pack_id`: SHA-256 of protocol content (deterministic, computed from file tree)
- `manifest_sha256`: SHA-256 of the `ProtocolPackManifest.json` bytes
- `pack_name`: human-readable pack identifier from the manifest

**Metadata field (not part of identity):**
- `source`: enum `builtin|override|dev-override` indicating how the pack was loaded; this is operational context, not cryptographic identity

**pack_id derivation rule (deterministic):**
1. Enumerate all files under the pack root matching protocol content prefixes (`schemas/`, `gates/`, `tiers/`).
2. Exclude scaffolding: `__init__.py`, `__pycache__`, `.DS_Store`, `.gitkeep`, `Thumbs.db`, `desktop.ini`, and extensions `.py`, `.pyc`, `.pyo`.
3. Exclude the manifest file (`ProtocolPackManifest.json`) itself.
4. Normalize all relative paths to POSIX (`/`), sort lexicographically.
5. For each file in sorted order, concatenate: `relpath + "\n" + sha256(bytes) + "\n" + size_bytes_decimal + "\n"`.
6. `pack_id = sha256(concatenation).hexdigest()`.

**manifest_sha256 role:**
The `manifest_sha256` is the SHA-256 of the raw `ProtocolPackManifest.json` bytes. It provides an additional integrity anchor: even if `pack_id` matches, a tampered manifest (e.g., wrong `pack_name`) would yield a different `manifest_sha256`. Gates verify both.

<a id="protocol-pack-symlink-policy"></a>
### Protocol Pack Symlink Policy (Canonical)
No symlinks are permitted anywhere under the pack root (even inside excluded directories like `__pycache__`). This is enforced fail-closed during pack scanning, building, and validation. Symlinks are rejected because they can escape the pack boundary, break deterministic traversal, and create replay/audit inconsistencies.

<a id="evaluated-revision"></a>
### evaluated_revision (Canonical)
`evaluated_revision` is the immutable repository revision being evaluated by deterministic verification (e.g., Gate R’s diff- and scope-based checks). It MUST resolve to a stable commit SHA (not a moving ref) and MUST be recorded in the evidence record so that independent verifiers can reproduce the same checks.

Non-normative example identifier:
```text
bk_ycanary_7f3a9c2d
```

<a id="r-snapshot"></a>
### R-Snapshot (Canonical)
The R-Snapshot is the EvidenceManifest snapshot referenced by the Gate R verdict. It is immutable and serves as the baseline evidence index for replay; any post-R evidence (e.g., docs compilation logs from C3) MUST be recorded only via an append-only extension, never by rewriting the R-Snapshot.

<a id="replay-integrity"></a>
### Replay Integrity (Canonical)
Replay Integrity means an independent verifier can re-run deterministic verification for a run and obtain the same gate decisions given the same LockedSpec, the same `evaluated_revision`, the same protocol pack identity, and the same Environment Envelope inputs.

<a id="wheel-vs-repo-local"></a>
### Wheel vs Repo-Local (Canonical)
Wheel-distributed BELGI includes publish-safe protocol assets (builtin protocol pack, schemas, and templates) and publish-safe CLI tooling, but MAY exclude repo-local deterministic gate implementations and internal operator tooling. A verifier MUST fail closed if required repo-local capabilities are absent.

<a id="pack-mirror-drift"></a>
### Pack Mirror Drift (Canonical)
Pack Mirror Drift is any divergence between the canonical protocol sources (root `schemas/`, `gates/`, `tiers/`) and the builtin protocol pack mirror shipped in the wheel (`belgi/_protocol_packs/v1/`). Drift is forbidden: it MUST be detected deterministically and corrected by rebuilding the mirror and updating protocol pack identity pins.
