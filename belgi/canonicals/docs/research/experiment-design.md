# Experiment Design: Measuring BELGI Under Probabilistic Cognition (Draft Specification)

## Status: Draft / Future Work
- This document defines experiment framing and procedures only. It MUST NOT claim or imply experimental results.
- Canonical terms and bounded claims MUST follow [CANONICALS.md](../../CANONICALS.md).
- Trust model scope and threat categories MUST follow [trust-model.md](../../trust-model.md).
- Failure category IDs MUST follow [gates/failure-taxonomy.md](../../gates/failure-taxonomy.md).
- Artifacts used for reproducibility MUST be schema-valid against the published schemas in [schemas](../../schemas).

## 1. Goals and hypotheses (bounded)
### 1.1 Primary goal (what BELGI is expected to improve)
Measure whether BELGI increases deterministic traceability and replayability of LLM-assisted development by:
- enforcing evidence sufficiency deterministically at Gate R,
- producing schema-valid, hashed, sealed run artifacts,
- reducing unscoped drift by requiring a locked contract (LockedSpec) and blast-radius constraints.

### 1.2 What these experiments do NOT test
These experiments do not test:
- program correctness proofs,
- semantic equivalence guarantees,
- security proofs.

Any correctness or security-relevant signals are treated only as evidence obligations defined by the protocol and tier policies.

## 2. C1) Baselines
Each baseline is evaluated on the same set of experimental units as the treatment.
### 2.0 Common: Evaluation Check Suite (objective completion criteria)
To avoid subjective "done" judgments and make baselines comparable, experiments MUST define a fixed
**Evaluation Check Suite** before any trials are run.

Definition:
- A deterministic check set used ONLY to judge trial completion and compute outcome metrics.
- The Evaluation Check Suite MUST be the same across Baseline 0, Baseline 1, and Treatment for a given
  configuration group (repo + harness + tooling version).

Minimum contents (recommended):
- The fixed CI-only check set used in Baseline 1 (tests/lint/etc), plus
- Any unit-specific acceptance checks explicitly declared in the unit spec (human-authored; no LLM inference).

Rules:
- Baselines MAY run arbitrary ad hoc commands during iteration, but completion is determined ONLY by the
  Evaluation Check Suite passing.
- The harness MUST record pass/fail + logs for the Evaluation Check Suite per attempt (or at minimum, at
  final attempt if per-attempt is infeasible).
### 2.1 Baseline 0: “LLM dev + ad hoc CI”
Definition:
- No LockedSpec locking step.
- No deterministic gates Q/R.
- No schema-enforced evidence manifest.
- No seal manifest binding artifacts to a commit.

Operational procedure:
- Use the same LLM and temperature regime as the treatment.
- Allow the developer/agent to iterate using ad hoc CI/test commands.
- Trial completion is achieved ONLY when the Evaluation Check Suite passes (Section 2.0), or when stopping rules apply.

Artifacts to retain (baseline instrumentation, not BELGI artifacts):
- starting commit SHA and final commit SHA
- diff patch bytes
- raw command log (stdout/stderr) for each attempt
- test reports if available

### 2.2 Baseline 1: “CI-only policy checks”
Definition:
- Some deterministic checks may exist (tests, lint), but:
  - no LockedSpec intent/envelope locking,
  - no GateVerdict schema with failure taxonomy categories,
  - no EvidenceManifest as a required index,
  - no sealing.

Operational procedure:
- Same as Baseline 0 except:
  - CI job definitions are fixed before experiments begin,
  - After each attempt, run the Evaluation Check Suite (Section 2.0), which includes the fixed CI-only check set as the standard component.
- Trial completion is achieved ONLY when the Evaluation Check Suite passes (Section 2.0), or when stopping rules apply.

Artifacts to retain (baseline instrumentation):
- same as Baseline 0, plus:
  - CI job metadata (job ids, statuses)

### 2.3 Treatment: BELGI full chain with tiers
Definition:
- Follow the canonical chain P → C1 → Q → C2 → R → C3 → S.
- Gate Q rejects vague intent at Q (pre-proposal).
- Gate R enforces evidence sufficiency deterministically.
- Evidence is indexed in EvidenceManifest and sealed via SealManifest.

Tier usage:
- Treatment MUST declare a tier (tier-0..tier-3) in LockedSpec.
- Experiments SHOULD include multiple tiers to quantify trade-offs.

## 3. C2) Experimental units and controls

### 3.1 Experimental unit
- **Unit:** a single change request defined by:
  - human intent text (P) and
  - starting repository commit SHA.

The experiment harness MUST assign a stable `unit_id` per unit.

### 3.2 Controls
To isolate protocol effects from model and environment effects, each unit MUST be evaluated under:
- the same task set (same units)
- the same model identifier and version
- the same temperature / sampling regime
- the same wall-clock budget and stopping rules
- the same actual execution environment when feasible

Envelope control rule:
- For the BELGI treatment, the Environment Envelope is declared and locked in LockedSpec.
- For baselines (which lack an envelope artifact), the experiment harness MUST still attempt to run in the same environment as the treatment to reduce confounding, and must record environment metadata externally.

Mandatory per-trial records (all procedures):
- Model regime record (model identifier + version + sampling parameters + max tokens + any harness seed).
- Environment attestation record (OS + toolchain + dependency lock fingerprint + harness version/commit SHA).

### 3.3 Randomization strategy
Randomization is optional but recommended.

If used:
- Randomize the order in which procedures are run per unit: {Baseline 0, Baseline 1, Treatment}.
- Randomize the seed used for any stochastic components in the harness (not the protocol) and record the seed.

Constraints:
- Randomization MUST NOT change the declared tier or envelope for the BELGI treatment within a configuration group.

## 4. C3) Protocol

### 4.1 Definitions (trial vs run)
- **Trial:** one execution of a baseline or treatment procedure for a unit under a fixed configuration (model + temperature regime + tier + envelope where applicable).
- **Run:** the schema artifact set sharing a common `run_id` (BELGI treatment only).
- **Attempt:** a single propose→verify cycle within a trial.

### 4.2 Per-unit procedure
For each unit, perform the following in each procedure group.

#### Baseline 0 trial steps
1) Start from the unit’s starting commit.
2) Allow LLM-driven iteration with ad hoc CI/test runs.
3) Stop when either:
   - the Evaluation Check Suite passes, or
   - stopping rules trigger.
4) Record baseline artifacts (diff, command logs, test results) for each attempt.

#### Baseline 1 trial steps
1) Start from the unit’s starting commit.
2) Allow LLM-driven iteration.
3) After each attempt, run the Evaluation Check Suite (Section 2.0).
4) Stop when:
   - the Evaluation Check Suite passes, or
   - stopping rules trigger.
5) Record baseline artifacts.

#### BELGI treatment trial steps (P → C1 → Q → C2 → R → C3 → S)
1) P: create or provide intent (human-authored).
2) C1: compile candidate LockedSpec.
3) Q: run Gate Q to lock/verify the run inputs.
   - If NO-GO: remediate as instructed and re-run Q (this is a Q loop).
4) C2: propose changes under the locked constraints.
5) R: run Gate R with required evidence.
   - If NO-GO: remediate and re-run R or, if the locked contract must change, return to Q.
6) C3: compile docs (deterministic, post-R).
7) S: seal the run.

### 4.3 Stopping rules (required)
Stopping rules MUST be set before running the experiments.

Minimum required stopping rules:
- `max_attempts_per_trial`: maximum number of attempts in a trial
- `max_wall_time_minutes`: maximum time per trial
- `max_Q_loops`: maximum number of Gate Q NO-GO cycles (treatment only)
- `max_R_loops`: maximum number of Gate R NO-GO cycles (treatment only)

Tier budget breach handling:
- For the BELGI treatment, tier-defined scope budgets are enforced by Gate R (R2).
- If a trial repeatedly breaches scope budgets, the trial MUST stop when the stopping criterion is reached; do not change tier or constraints without explicit HOTL in the experiment protocol.

Censoring rule:
- If a trial stops without reaching a Gate R GO (treatment) or without reaching baseline completion criteria, the trial outcome is recorded as censored with the stop reason.
  - Baseline completion criteria is: Evaluation Check Suite passes (Section 2.0).

## 5. Artifact requirements (reproducibility; mandatory)
For the BELGI treatment, each trial MUST produce and retain a complete, schema-valid artifact set enabling third-party replay within the declared envelope.

### 5.1 Mandatory BELGI artifacts per run
The following artifacts are REQUIRED and MUST validate against their schemas:

- LockedSpec.json
  - Schema: [schemas/LockedSpec.schema.json](../../schemas/LockedSpec.schema.json)

- GateVerdict for Gate Q and Gate R
  - Schema: [schemas/GateVerdict.schema.json](../../schemas/GateVerdict.schema.json)
  - Failure categories must be drawn from: [gates/failure-taxonomy.md](../../gates/failure-taxonomy.md)

- EvidenceManifest(s)
  - Schema: [schemas/EvidenceManifest.schema.json](../../schemas/EvidenceManifest.schema.json)
  - Must include tier-required evidence kinds per [tiers/tier-packs.json](../../tiers/tier-packs.json) (generated view: [tiers/tier-packs.md](../../tiers/tier-packs.md))

- SealManifest
  - Schema: [schemas/SealManifest.schema.json](../../schemas/SealManifest.schema.json)

- Waiver artifacts (if referenced)
  - Schema: [schemas/Waiver.schema.json](../../schemas/Waiver.schema.json)

### 5.2 Evidence bytes requirement
For every ObjectRef `storage_ref` referenced by:
- SealManifest (locked spec, gate verdicts, evidence manifest, waivers, optional replay instructions)
- each EvidenceManifest `artifacts[]`

…the corresponding bytes MUST be retained and resolvable for replay.

### 5.3 Replay categorization to record
Each BELGI run MUST be classified as one of:
- `audit_grade_replay`
- `execution_only_replay`
- `no_go_replay`

using the public replay rules in [operations/evidence-bundles.md](../operations/evidence-bundles.md).

### 5.4 Baseline artifact expectations
Baselines do not produce BELGI artifacts. However, to enable fair measurement, each baseline trial MUST retain:
- starting and final commit SHAs
- diff bytes
- command logs
- test reports where applicable
- Evaluation Check Suite logs (pass/fail + stdout/stderr)
- Model regime record (model/version/sampling/seed)
- Environment attestation record (OS/toolchain/deps fingerprint/harness version)

Baseline data MUST NOT be mislabeled as schema-valid BELGI artifacts.

## 6. C4) Reporting template

### 6.1 Per-unit table spec
Produce a table where each row is a trial and columns include:

- `unit_id`
- `procedure ∈ {baseline0, baseline1, belgi}`
- `trial_id`
- `model_id`
- `model_version`
- `sampling_regime` (temperature/top_p/etc)
- `harness_seed` (if any)
- `env_attestation_fingerprint` (hash/token)
- `run_id` (treatment only; null for baselines)
- `tier_id` (treatment only)
- `starting_commit_sha`
- `final_commit_sha`
- `outcome_label` (analysis label; see metrics clustering labels)
- `failure_category_token` (treatment: GateVerdict.failure_category; baseline: synthetic mapping or null)
- `Q_loops` (treatment only)
- `R_loops` (treatment only)
- `time_to_goal_seconds` (goal defined per procedure)
  - goal: Treatment = first R:GO; Baselines = first Evaluation Check Suite pass
- `touched_files_count`
- `loc_delta`
- `evidence_completeness` (treatment only)
- `replay_outcome` (treatment only)
- `waiver_count` (treatment only)
- `stop_reason` (null if completed)

Synthetic mapping rule for baseline failure category tokens:
- If a baseline ends due to missing/failed command execution evidence, map to `FR-COMMAND-FAILED`.
- If it ends due to failing tests, map to `FR-TESTS-POLICY-FAILED`.
- Otherwise leave null.

This mapping is for analysis comparability and MUST NOT be confused with an actual GateVerdict output.

### 6.2 Plots to produce (names only)
- Outcome distribution by procedure
- Failure category histogram (treatment only; taxonomy tokens)
- Time-to-goal CDF by procedure
- Patch churn distribution (touched files, LOC delta)
- Evidence completeness distribution by tier (treatment only)
- Replay outcome rates by tier (treatment only)
- Clustering visualization (2D embedding) colored by outcome_label

### 6.3 Future planned experiments (non-blocker)
The following are planned experimental extensions. They are NOT required for protocol publication.

- Shannon/entropy-style measures (E1/E2/E3) by configuration

## 7. C5) Validity and limitations

### 7.1 External validity
- Results may not generalize beyond the chosen task portfolio/testbed.
- Different repos, languages, and CI cultures may yield different evidence and drift characteristics.

### 7.2 Construct validity
- (Future planned) Entropy measures outcome variability and failure-mode diversity, not correctness.
- Evidence completeness measures presence of required evidence kinds, not truth of claims beyond the bounded envelope.

### 7.3 Threats to validity
- Dataset leakage: units may overlap with model training data.
- Model drift: model versions may change during the study.
- Toolchain drift: baselines and treatment may inadvertently run under different environments.
- Nondeterministic tests: flakiness can inflate variability or cause unstable outcomes.
- Human intervention: HOTL decisions can change trajectories and must be recorded.

## 8. Mandatory final step — Consistency sweep checklist
This checklist MUST be executed after drafting and before publishing experimental docs.

- [ ] No overclaim statements remain (no correctness, semantic equivalence, or security proof claims).
- [ ] Outcome classes map to failure taxonomy categories via category IDs (links to failure taxonomy).
- [ ] No metric depends on private exploit signatures or bypass heuristics (public-safe bins only).
- [ ] Artifact requirements are consistent with schemas (LockedSpec, GateVerdict, EvidenceManifest, SealManifest, Waiver).

Future planned (non-blocker):
- [ ] If entropy metrics are included, each entropy metric states exactly what it measures (RV, alphabet, probability estimation, sample size).
