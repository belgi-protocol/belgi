# Metrics Spec: BELGI Process, Determinism, Entropy, and Clustering (RFC - Draft Specification)

## 0. Rule of use (canonical + schema alignment)
- Canonical protocol terms and meanings MUST be taken from [CANONICALS.md](../../CANONICALS.md).
- This document defines *measurement metrics* (new terms) and MUST NOT redefine canonical terms.
- All metrics MUST be computable from schema-valid run artifacts and the repo diff between the locked base commit and the evaluated revision.

**Authoritative artifacts (required for most metrics):**
- Locked run contract: [schemas/LockedSpec.schema.json](../../schemas/LockedSpec.schema.json)
- Gate outputs: [schemas/GateVerdict.schema.json](../../schemas/GateVerdict.schema.json)
- Evidence index: [schemas/EvidenceManifest.schema.json](../../schemas/EvidenceManifest.schema.json)
- Seal binding: [schemas/SealManifest.schema.json](../../schemas/SealManifest.schema.json)
- Waiver artifact: [schemas/Waiver.schema.json](../../schemas/Waiver.schema.json)

**Tier requirements (evidence kinds):** [tiers/tier-packs.json](../../tiers/tier-packs.json) (generated view: [tiers/tier-packs.md](../../tiers/tier-packs.md))

**Failure category IDs (do not redefine):** [gates/failure-taxonomy.md](../../gates/failure-taxonomy.md)

## 1. Shared definitions used by multiple metrics
### 1.1 Experimental unit, trial, run, attempt
These metrics are designed to be used in experiments where a “change request” is evaluated under baselines and BELGI.

- **Unit**: a single change request defined by (intent text + starting commit). The unit must have a stable `unit_id` assigned by the experiment harness.
- **Trial**: one end-to-end execution of a baseline or treatment procedure for a unit under a specified configuration (model, temperature regime, tier, envelope).
- **Attempt**: a single propose→verify cycle within a trial, producing at minimum a Gate R verdict (and associated evidence) for the evaluated revision.
- **Run (artifact sense)**: a set of schema artifacts sharing a common `run_id` across LockedSpec, EvidenceManifest(s), GateVerdict(s), and SealManifest.

Because the schema includes `run_id` but not `unit_id`, the experiment harness MUST maintain a mapping table:
- `unit_id -> {run_id_1, run_id_2, ...}`

### 1.2 Required minimal artifact set for metric computation
A metric is only **valid** for a run if the following are present and schema-valid:
- LockedSpec.json (LockedSpec schema)
- GateVerdict for Q and/or R as required by metric (GateVerdict schema)
- EvidenceManifest referenced by the relevant GateVerdict (EvidenceManifest schema)
- SealManifest.json (SealManifest schema) for metrics that depend on sealing or replay category

If an artifact is missing or schema-invalid, metrics MUST be marked `undefined` for that run with a structured reason (see metric failure modes).

### 1.3 Diff-derived primitives (public-safe)
Some metrics require a diff between:
- base: `LockedSpec.upstream_state.commit_sha`
- evaluated: the revision being verified/sealed (typically `SealManifest.final_commit_sha`)

Diff primitives used by metrics:
- `touched_files_count`: number of distinct paths changed
- `loc_delta`: insertions + deletions (sum across file hunks)
- `touched_path_bins`: classification of touched file paths into **bins** (see B3.2). Bins are used instead of exact paths for public-safe reporting.

### 1.4 Verdict selection (handling loops)
Since a single run may involve multiple Gate Q or Gate R iterations (loops) under the same `run_id`:
- **Outcome metrics** (e.g., success rates, failure entropy) MUST use the **Final** GateVerdict per `(run_id, gate_id)`.
  - Final is defined by `max(evaluated_at)`.
- **Process metrics** (e.g., attempt counts, loops) MUST use **All** GateVerdicts per `(run_id, gate_id)` to capture every iteration.

**Entropy-specific clarification:**
- **E3 (Gate-failure entropy)** uses the **Final** verdict per trial (i.e., one failure category token per trial, when the trial ends in NO-GO).
- **E4 (Process-failure entropy)** uses the **Multiset of All** attempt-level verdicts per trial (i.e., failure categories from every intermediate NO-GO loop and any final NO-GO), not just the final outcome.

## 2. B1) Process metrics (iteration + drift)

### B1.1 Attempts per stage (Q loops, R loops)
- **Inputs:**
  - Sequence of GateVerdict artifacts for the unit’s trial(s), each schema-valid.
- **Computation:**
  - `Q_loops = count(GateVerdict.gate_id == "Q" and verdict == "NO-GO")` within the trial.
  - `R_loops = count(GateVerdict.gate_id == "R" and verdict == "NO-GO")` within the trial.
  - `total_attempts = R_loops + count(GateVerdict.gate_id == "R" and verdict == "GO")`.
- **Output range:** integers ≥ 0.
- **Interpretation:** higher values indicate more iteration needed to reach a GO (or inability to reach GO before stopping rule).
- **Failure modes:**
  - If verdict sequence is incomplete (missing R verdicts for an attempt) → `undefined: missing_gate_verdicts`.
  - If unit↔run mapping is missing → `undefined: missing_unit_mapping`.

### B1.2 Mean time-to-GO (per trial)
- **Inputs:**
  - Timestamps:
    - Gate Q `evaluated_at` (earliest) and Gate R `evaluated_at` for GO, or
    - SealManifest `sealed_at` if sealing is required by the experiment protocol.
- **Computation:**
  - Define `t0 = min(evaluated_at over GateVerdict where gate_id == "Q")`.
  - Define `t_go = evaluated_at of the first GateVerdict where gate_id == "R" and verdict == "GO"`.
  - Optionally (if required), define `t_seal = sealed_at`.
  - Report:
    - `time_to_R_GO_seconds = (t_go - t0)`
    - `time_to_seal_seconds = (t_seal - t0)` when SealManifest is required.
- **Output range:** real numbers ≥ 0.
- **Interpretation:** lower values indicate faster convergence to a verified GO.
- **Failure modes:**
  - If no R GO occurs before stopping → `censored: no_go_before_stop`.
  - If timestamps missing/invalid → `undefined: missing_timestamps`.

### B1.3 Patch churn: LOC delta and touched files
- **Inputs:**
  - A diff artifact referenced in EvidenceManifest (`artifacts[].kind == "diff"`), plus base/evaluated revision IDs.
- **Computation:**
  - Parse diff to compute:
    - `touched_files_count`
    - `loc_delta = insertions + deletions`
- **Output range:** integers ≥ 0.
- **Interpretation:** larger churn indicates broader code changes (often correlated with higher verification risk).
- **Failure modes:**
  - Diff artifact missing → `undefined: missing_diff_evidence`.
  - Diff not parseable → `undefined: diff_parse_error`.

## 3. B2) Determinism / traceability metrics (what BELGI actually improves)

### B2.1 Evidence completeness rate (per tier)
- **Inputs:**
  - LockedSpec `tier.tier_id`
  - EvidenceManifest `artifacts[].kind`
  - Tier pack required evidence kinds from [tiers/tier-packs.json](../../tiers/tier-packs.json) (generated view: [tiers/tier-packs.md](../../tiers/tier-packs.md))
- **Computation:**
  - Let `required_kinds(tier_id)` be the tier’s `required_evidence_kinds`.
  - Let `present_kinds = set(EvidenceManifest.artifacts[].kind)`.
  - `evidence_completeness = |required_kinds ∩ present_kinds| / |required_kinds|`.
- **Output range:** [0, 1].
- **Interpretation:** 1.0 indicates the EvidenceManifest contains all tier-required evidence kinds (necessary but not sufficient for GO).
- **Failure modes:**
  - EvidenceManifest missing or schema-invalid → `undefined: missing_or_invalid_evidence_manifest`.
  - Tier id unknown → `undefined: unknown_tier_id`.

### B2.2 Replay outcome rate (execution-only vs audit-grade)
This metric classifies each run’s replay capability using the public replay rules in [operations/evidence-bundles.md](../operations/evidence-bundles.md).

- **Inputs:**
  - SealManifest (required)
  - GateVerdict (R) and referenced EvidenceManifest (R-snapshot)
  - Final EvidenceManifest referenced by SealManifest
  - Availability of all bytes addressed by each `ObjectRef.storage_ref`
- **Computation (categorical outcome):**
  - `replay_outcome ∈ {no_go_replay, execution_only_replay, audit_grade_replay}`
  - `no_go_replay` if any of the following holds:
    - any required schema validation fails,
    - any `ObjectRef.hash` does not match the referenced bytes,
    - Replay Integrity Rule fails (R-snapshot not preserved in final evidence set),
    - required envelope reconstruction is not possible from declared/pinned refs.
  - `audit_grade_replay` if all `no_go_replay` checks pass and the seal verification algorithm passes.
  - `execution_only_replay` if schema + hashes pass and replay is possible, but seal verification is not performed or cannot be performed.
- **Output range:** categorical.
- **Interpretation:** audit-grade replay is a stronger integrity claim than execution-only replay; neither implies program correctness.
- **Failure modes:**
  - If SealManifest missing → `undefined: missing_seal_manifest`.

### B2.3 Replay success rate (per group)
- **Inputs:**
  - `replay_outcome` from B2.2 computed for each run.
- **Computation:**
  - `audit_grade_rate = count(replay_outcome == audit_grade_replay) / total_runs`
  - `execution_only_rate = count(replay_outcome == execution_only_replay) / total_runs`
  - `no_go_replay_rate = count(replay_outcome == no_go_replay) / total_runs`
- **Output range:** each in [0, 1] and sums to 1 (over defined runs).
- **Interpretation:** higher audit-grade rate indicates stronger traceability outcomes.
- **Failure modes:**
  - If too few defined runs → report with confidence caveat (see B3.4 minimum N).

### B2.4 Waiver rate and waiver density
- **Inputs:**
  - LockedSpec `waivers_applied[]` (optional)
  - SealManifest `waivers[]` (always present as an array; may be empty)
  - Optionally Waiver documents (schema-valid) referenced by SealManifest
  - Diff-derived `loc_delta` (from B1.3)
- **Computation:**
  - `waiver_count = len(LockedSpec.waivers_applied)` (treat missing as 0)
  - `waiver_rate = count(waiver_count > 0) / total_runs`
  - `waiver_density_per_1k_loc = waiver_count / max(1, loc_delta) * 1000`
- **Output range:**
  - `waiver_count`: integer ≥ 0
  - `waiver_rate`: [0, 1]
  - `waiver_density_per_1k_loc`: real number ≥ 0
- **Interpretation:** waivers represent scoped, human-authored exceptions; higher density suggests more deviations from default policy.
- **Failure modes:**
  - If loc_delta undefined → waiver density is `undefined` but waiver count remains defined.

### B2.5 Outcome distribution divergence (between procedures or configurations)
This metric quantifies how outcome distributions shift between two groups (e.g., baseline vs treatment) without claiming any group is “more correct.”

- **Inputs:**
  - A set of trials in group A and group B, each with an outcome token as defined in E1 (GO or failure category token).
- **Computation:**
  1) Compute empirical distributions over the shared alphabet:
     - `P(x)` from group A and `Q(x)` from group B.
  2) Compute Jensen–Shannon divergence (base-2):
     - `M = (P + Q) / 2`
     - `JSD(P||Q) = 0.5 * KL(P||M) + 0.5 * KL(Q||M)`
  3) Handling zero probabilities:
     - Use the empirical support union of A and B.
     - If a smoothing rule is applied, it MUST be documented (ε value and where applied).
- **Output range:** [0, 1] bits (for base-2 JSD).
- **Interpretation:**
  - Higher values indicate the two groups fail (or succeed) in systematically different ways.
  - Lower values indicates more similar outcome distributions.
- **Failure modes:**
  - If either group has fewer than N=20 trials → report JSD with a low-sample warning.
  - If outcome tokens are missing for many trials → compute on remaining defined trials and report censoring rate.

## 4. B3) Entropy metrics (explicit random variables)
Entropy metrics are used to quantify variability of outcomes, diff structure, and failure categories across repeated runs under controlled conditions. They do **not** measure correctness.

### 4.1 General entropy computation
- Use Shannon entropy: $H(X) = -\sum_x p(x) \log_2 p(x)$.
- When estimating $p(x)$ empirically from N samples, use:
  - `p_hat(x) = count(x) / N`.
  - If zero-probability bins must be represented (e.g., for divergence), apply a documented smoothing rule (e.g., add-ε) and report ε.

### 4.2 Entropy variable E1: Prompt-output outcome entropy proxy
This measures variability of final outcomes across repeated trials under the same LockedSpec and environment envelope.

- **Random variable (RV):**
  - `X_outcome = final outcome class per trial`.
- **Alphabet:**
  - `A = {GO} ∪ {failure_category tokens from gates/failure-taxonomy.md}`.
  - For GO, represent as the literal token `GO`.
- **Probability estimation:**
  - Run N trials under identical controls; compute empirical frequency of each token.
- **Metric output:**
  - `H_outcome_bits = H(X_outcome)`.
- **Output range:**
  - [0, log2(|A_observed|)] bits for observed alphabet.
- **Interpretation:**
  - Higher entropy indicates more variability in whether and how a trial fails.
  - Lower entropy indicates more stable outcomes under the same LockedSpec.
- **Failure modes:**
  - If outcome token is missing (no final verdict) → exclude sample and record `censored`.

### 4.3 Entropy variable E2: Diff-structure (path-bin) entropy
This measures how the *structure* of changes varies, using public-safe bins rather than exact file paths.

- **Random variable (RV):**
  - `X_bins = dominant touched path-bin for a run` (single label per run), or
  - optionally `X_bins_multiset` as a distribution over bins within a run (must specify which is used).

This spec uses the single-label version for simplicity.

- **Alphabet (public-safe bins):**
  - `A_bins = {code, tests, docs, config, schemas, gates, operations, other}`

**Bin assignment rule (deterministic):**
- `schemas` if path starts with `schemas/`
- `gates` if path starts with `gates/`
- `operations` if path starts with `docs/operations/`
- `docs` if file extension is `.md` and not already in a stricter bin above
- `tests` if path contains `/test/` or `/tests/` segment (case-insensitive) and not already in a stricter bin above
- `config` if file name matches configuration conventions used by the repo (experiment harness may define this internally; public reports MUST NOT publish pattern/signature lists)
- `code` for remaining source-like files
- `other` otherwise

- **Probability estimation:**
  - For each run, compute the bin touched most frequently (ties broken lexicographically by bin token), yielding one label.
  - Across N runs, estimate empirical frequencies.
- **Metric output:**
  - `H_pathbin_bits = H(X_bins)`.
- **Output range:** [0, log2(8)] = [0, 3] bits.
- **Interpretation:**
  - Higher entropy indicates a run set that varies more in which parts of the repo it tends to touch.
- **Failure modes:**
  - If diff is missing or unparseable → entropy sample is undefined for that run.

### 4.4 Entropy variable E3: Gate-failure entropy
This measures variability of failure categories across runs.

- **Random variable (RV):**
  - `X_fail = failure_category of the final NO-GO verdict for a trial`.
- **Alphabet:**
  - `A_fail = {category_id tokens from gates/failure-taxonomy.md}`.
- **Probability estimation:**
  - Consider only trials that end in NO-GO (or compute conditional entropy).
  - Empirical frequency over N_fail samples.
- **Metric output:**
  - `H_failure_bits = H(X_fail)`.
- **Output range:** [0, log2(|A_fail_observed|)] bits.
- **Interpretation:**
  - Higher entropy indicates failures are spread across many categories; lower entropy indicates a dominant failure mode.
- **Failure modes:**
  - If NO-GO verdict has null failure_category (schema should prevent, but treat as invalid) → `undefined: invalid_gate_verdict`.

### 4.5 Entropy variable E4: Process-failure entropy
This measures variability of failure categories across **all attempts** within a trial, including intermediate NO-GO loops.

- **Definition:** Measures variability of failure categories across **ALL attempts** (including intermediate NO-GO loops) within a trial.
- **Random variable (RV):**
  - `X_process_fail = failure_category of any attempt`.
- **Samples used (per trial):**
  - Let `C_trial` be the multiset of `failure_category` tokens from **all** NO-GO GateVerdicts observed within the trial (Gate Q and/or Gate R), in time order.
  - Define `N_trial = |C_trial|`. If `N_trial == 0` (trial has no NO-GO attempts), then this metric is `undefined` for that trial.
- **Probability estimation (within trial):**
  - `p_hat_trial(c) = count(c in C_trial) / N_trial`.
- **Metric output (per trial):**
  - `H_process_failure_bits(trial) = H(X_process_fail)` computed using `p_hat_trial`.
- **Output range:** [0, log2(|A_fail_observed_trial|)] bits.
- **Interpretation:**
  - Lower entropy indicates **Systematic Error** (repeating the same failure category across attempts).
  - Higher entropy indicates **Stochastic Flailing** (varying failure modes across attempts).
- **Failure modes:**
  - If any NO-GO GateVerdict has null/invalid `failure_category` → `undefined: invalid_gate_verdict`.
  - If the GateVerdict sequence is incomplete for the trial → `undefined: missing_gate_verdicts`.

### 4.6 Minimum sample sizes (required)
Entropy estimates are unstable at small N.

- **Minimum N for E1 (outcome entropy):** N ≥ 20 trials per configuration.
- **Minimum N for E2 (path-bin entropy):** N ≥ 20 runs per configuration.
- **Minimum N for E3 (failure entropy):** N_fail ≥ 20 NO-GO outcomes per configuration.
- **Minimum N for E4 (process-failure entropy):** ≥ 20 trials with `N_trial > 0` per configuration (and report the distribution of `N_trial`).

If these minimum sample size requirements are not met, entropy values MUST be reported as preliminary and accompanied by N.

### 4.7 Known confounders (must be recorded)
Each trial MUST record (in experiment metadata, not in canonical artifacts):
- model identifier and version
- temperature / sampling regime
- any prompt bundle changes (even if referenced as ObjectRef)
- environment envelope drift (changes in pinned toolchain refs or runner)
- nondeterministic tests and flaky evidence policies
- human intervention (e.g., HOTL decisions), if applicable

## 5. B4) Clustering definition (mandatory)
Clustering is used to group similar run behaviors (diff structure + evidence + failure traces) without inventing new failure taxonomy IDs.

### 5.1 Objects clustered
- Primary: **runs** (attempt-level) represented by a schema-valid artifact set.
- Optional secondary analysis: **trials** aggregated over attempts.

This spec clusters **runs**.

### 5.2 Feature vector definition
For each run, construct feature vector `f(run)`:

1) **Outcome features**
- `verdict_R`: one-hot over {GO, NO-GO}
- `failure_category_R`: one-hot over failure category IDs when verdict is NO-GO; all zeros when GO

2) **Evidence features**
- `tier_id`: one-hot over {tier-0, tier-1, tier-2, tier-3}
- `evidence_completeness`: scalar in [0, 1] (B2.1)
- `command_log_shape`: {strings, structured} derived from tier policy (or directly from EvidenceManifest shape)
- `has_env_attestation_ref`: boolean (EvidenceManifest.envelope_attestation != null)

3) **Diff / blast-radius features**
- `touched_files_count`: scalar (B1.3)
- `loc_delta`: scalar (B1.3)
- `pathbin_histogram`: 8-dimensional normalized histogram over A_bins (computed from touched files within the run)

4) **Governance features**
- `waiver_count`: integer ≥ 0 (B2.4)

5) **Replay features** (if SealManifest available)
- `replay_outcome`: one-hot over {no_go_replay, execution_only_replay, audit_grade_replay}

All numeric features MUST be normalized (e.g., z-score within the analysis dataset) before distance computation.

### 5.3 Distance metric
Use **Gower distance** to support mixed numeric, categorical, boolean, and histogram features.

- Numeric: scaled absolute difference
- Categorical/boolean: 0 if equal else 1
- Histogram: use L1 distance scaled to [0, 1]

### 5.4 Outcome classes (labels) and mapping to failure taxonomy
Outcome classes are **analysis labels** derived from the gate verdicts. They MUST map to existing failure category IDs.

- `clean-go`:
  - Condition: Gate R verdict == GO

- `evidence-missing`:
  - Maps to: `FR-EVIDENCE-MISSING`, `FR-EVIDENCE-ATTESTATION-MISSING`

- `test-failure`:
  - Maps to: `FR-TESTS-POLICY-FAILED`

- `scope-violation`:
  - Maps to: `FR-SCOPE-BUDGET-EXCEEDED`, `FR-POLICY-FORBIDDEN-PATH`

- `schema-invalid`:
  - Maps to: `FQ-SCHEMA-LOCKEDSPEC-INVALID`, `FR-SCHEMA-ARTIFACT-INVALID`

- `intent-insufficient`:
  - Maps to: `FQ-INTENT-INSUFFICIENT`, `FQ-INVARIANTS-EMPTY`, `FQ-CONSTRAINTS-MISSING`, `FQ-ENVELOPE-MISSING`, `FQ-TIER-UNKNOWN`, `FQ-WAIVER-INVALID`

- `supplychain-flag`:
  - Maps to: `FR-SUPPLYCHAIN-SCAN-MISSING`, `FR-SUPPLYCHAIN-CHANGE-UNACCOUNTED`

- `adversarial-flag`:
  - Maps to: `FR-ADVERSARIAL-SCAN-MISSING`, `FR-ADVERSARIAL-DIFF-SUSPECT`

**Rule:** these labels MUST NOT be used as replacements for GateVerdict.failure_category. They are derived for analysis and must always retain the original category token.
