# BELGI CLI Operator Guide

This is the operator SSOT for CLI usage. Keep this file focused on:
- init
- run workspace creation
- run + verify
- NO-GO evidence pointers

For chain module reference commands, use:
- `docs/operations/running-belgi.md`

For Operator Anchor classes, handling, and workspace/file-boundary guidance, use:
- `docs/operations/operator-anchors.md`

## CLI Tiers

| Tier | Commands | Status |
|---|---|---|
| A (operator-critical) | `about`, `init`, `run`, `waiver`, `verify` | v1.4.0 operator UX closure target |
| B (operator-support) | `policy`, `bundle`, `pack` | stable, not polished for operator UX |
| C (expert-only) | `manifest`, `stage`, `supplychain-scan`, `adversarial-scan` | stable, expert surface |

Guarantee scope:
- v1.4.0 guarantees Tier A operator UX closure.
- Tier B and Tier C remain stable, but are not polished operator surfaces.

## Quickstart

```bash
# 1) Initialize BELGI surfaces in the repo
belgi init --repo .

# 2) Create a run workspace
belgi run new --repo . --run-id run-001

# 3) Edit intent input
# .belgi/runs/run-001/inputs/intent/IntentSpec.core.md

# Optional Tier-2/Tier-3 shared Operator Anchors live under:
# .belgi/runs/run-001/inputs/anchors/{approvals,keys,signing}/
# Optional Tier-3 evidence input lives under:
# .belgi/runs/run-001/inputs/evidence/genesis_seal.json
# Optional shared run accounting refs can point at actual dependency/toolchain declaration surfaces:
# requirements.txt, pyproject.toml, uv.lock, toolchains/python.lock.json

# 4) Resolve a stable base SHA
BASE_SHA40=$(git rev-parse HEAD)

# 5) Run canonical CLI flow
belgi run \
  --repo . \
  --tier tier-1 \
  --intent-spec .belgi/runs/run-001/inputs/intent/IntentSpec.core.md \
  --base-revision "${BASE_SHA40}"

# Optional when the run binds an explicit ToolchainSet object:
#   --toolchain-set-ref env.toolchains=.belgi/runs/run-001/inputs/environment/toolchain-set.json
# Optional shorthand when the run needs explicit R7 accounting context:
#   --toolchain-ref deps.requirements=requirements.txt
# Optional when the run should lock an explicit Tolerances object:
#   --tolerances-ref tier.tolerances=.belgi/runs/run-001/inputs/environment/tolerances.json

# 6) Verify run outputs
belgi verify --repo .
```

Optional shared run object inputs on any tier:
- `--toolchain-set-ref <object_id>=<repo-relative-path>` (singular)
- binds an authoritative ToolchainSet object into `LockedSpec.environment_envelope.toolchain_set_ref` on the same shipped `belgi run` spine
- ToolchainSet is the first-class declaration object for operator-supplied dependency/toolchain accounting refs
- the referenced ToolchainSet file is a pre-lock operator input; accepted only as the current run's canonical run-local object path: `.belgi/runs/<run_id>/inputs/environment/toolchain-set.json`
- BELGI stages that ToolchainSet into locked/store authority before C1; later stages consume the locked/store copy, not ambient workspace bytes
- ToolchainSet member declaration paths must still point at actual repo-relative dependency/toolchain declaration surfaces in the evaluated revision truth envelope
- this is not an Operator Anchor
- `--toolchain-ref <object_id>=<repo-relative-path>` (repeatable)
- shorthand only: `belgi run` normalizes these refs into authoritative ToolchainSet object authority before lock
- use actual repo-relative dependency/toolchain declaration surfaces that matter for the run (for example `requirements.txt`, `pyproject.toml`, `uv.lock`, `toolchains/python.lock.json`)
- the referenced declaration file must already exist in the evaluated revision truth envelope; local-only extras are rejected fail-closed
- do not mix `--toolchain-set-ref` with shorthand `--toolchain-ref` values
- `toolchain.main` is reserved for the built-in generated run toolchain input
- this is not an Operator Anchor
- `--tolerances-ref <object_id>=<repo-relative-path>` (singular)
- binds a real locked tolerances object into `LockedSpec.tier.tolerances_ref` on the same shipped `belgi run` spine
- recommended object id: `tier.tolerances`
- the referenced Tolerances file is a pre-lock operator input; accepted only as the current run's canonical run-local object path: `.belgi/runs/<run_id>/inputs/environment/tolerances.json`
- BELGI stages that Tolerances object into locked/store authority before C1; later stages consume the locked/store copy, not ambient workspace bytes
- `Tolerances.tier_id` must match the selected tier
- for the selected tier, `scope_budgets.max_touched_files` and `scope_budgets.max_loc_delta` may equal or tighten the selected tier ceilings, but BELGI rejects wider values
- if omitted, `belgi run` materializes the canonical tolerances object from the selected tier pack and locks that generated object automatically
- numeric scope budgets no longer live in `IntentSpec`; move any legacy `IntentSpec.scope.max_*` values into the Tolerances object
- this is not an Operator Anchor

## Tier-2 / Tier-3 Shared Path

Tier-2 and Tier-3 use the same shipped `belgi run` backbone as Tier-0/1.

Canonical noun:
- `Operator Anchors` = operator-supplied control artifacts/refs on the shared run spine
- canonical definition: `CANONICALS.md#operator-anchors`
- operator prep guide: `docs/operations/operator-anchors.md`

Required shared Operator Anchors on `belgi run` for Tier-2/Tier-3:
- `--attestation-pubkey-ref <object_id>=<repo-relative-path>`
- `--seal-pubkey-ref <object_id>=<repo-relative-path>`
- `--hotl-approval-ref <repo-relative-path>`
- `--attestation-signing-key-ref <repo-relative-path>`
- exactly one of:
  - `--seal-private-key-ref <repo-relative-path>`
  - `--seal-signature-ref <repo-relative-path>`

Additional Tier-3 evidence input on `belgi run`:
- `--genesis-seal-ref <repo-relative-path>`

Rules:
- all shared Operator Anchors and Tier-3 evidence inputs are local-only repo-relative refs
- no remote fetches or ambient key discovery are used
- raw attestation/seal secret material is consumed locally for signing only and is not copied into `.belgi/store/.../repo/out/`, manifests, bundle outputs, or replay surfaces
- `genesis_seal` is Tier-3 evidence, not an Operator Anchor
- `belgi/anchor/v1/TrustAnchor.json` remains the canonical Tier-3 authority artifact and is not an Operator Anchor
- `belgi run` fails closed if the selected tier's shared-control or evidence input set is incomplete or malformed
- recommended workspace family is `.belgi/runs/<run_id>/inputs/anchors/`
  - `approvals/` for HOTL approval artifacts
  - `keys/` for pinned public-key materials
  - `signing/` for local signing refs or precomputed signatures
- Tier-3 evidence is taught separately under `.belgi/runs/<run_id>/inputs/evidence/`
  - `genesis_seal.json` for Tier-3 evidence input only

Tier-2 example:

```bash
belgi run \
  --repo . \
  --tier tier-2 \
  --intent-spec .belgi/runs/run-001/inputs/intent/IntentSpec.core.md \
  --base-revision "${BASE_SHA40}" \
  --attestation-pubkey-ref env.attestation_pubkey=.belgi/runs/run-001/inputs/anchors/keys/attestation_pubkey.hex \
  --seal-pubkey-ref env.seal_pubkey=.belgi/runs/run-001/inputs/anchors/keys/seal_pubkey.hex \
  --hotl-approval-ref .belgi/runs/run-001/inputs/anchors/approvals/hotl_approval.json \
  --attestation-signing-key-ref .belgi/runs/run-001/inputs/anchors/signing/attestation_signing_key.hex \
  --seal-private-key-ref .belgi/runs/run-001/inputs/anchors/signing/seal_private_key.hex
```

Tier-2 precomputed signature branch:

```bash
belgi run \
  --repo . \
  --tier tier-2 \
  --intent-spec .belgi/runs/run-001/inputs/intent/IntentSpec.core.md \
  --base-revision "${BASE_SHA40}" \
  --attestation-pubkey-ref env.attestation_pubkey=.belgi/runs/run-001/inputs/anchors/keys/attestation_pubkey.hex \
  --seal-pubkey-ref env.seal_pubkey=.belgi/runs/run-001/inputs/anchors/keys/seal_pubkey.hex \
  --hotl-approval-ref .belgi/runs/run-001/inputs/anchors/approvals/hotl_approval.json \
  --attestation-signing-key-ref .belgi/runs/run-001/inputs/anchors/signing/attestation_signing_key.hex \
  --seal-signature-ref .belgi/runs/run-001/inputs/anchors/signing/seal_signature.b64
```

Shared-path outcome for Tier-2:
- C1 receives the required pubkey refs in `LockedSpec.environment_envelope`
- the operator-supplied `hotl_approval` artifact is indexed before Gate Q
- `test_report` and signed `env_attestation` are produced on the same run spine before Gate R
- the Tier-2 seal signature is produced or verified on the same run spine before Gate S

Tier-3 example:

```bash
belgi run \
  --repo . \
  --tier tier-3 \
  --intent-spec .belgi/runs/run-001/inputs/intent/IntentSpec.core.md \
  --base-revision "${BASE_SHA40}" \
  --attestation-pubkey-ref env.attestation_pubkey=.belgi/runs/run-001/inputs/anchors/keys/attestation_pubkey.hex \
  --seal-pubkey-ref env.seal_pubkey=.belgi/runs/run-001/inputs/anchors/keys/seal_pubkey.hex \
  --hotl-approval-ref .belgi/runs/run-001/inputs/anchors/approvals/hotl_approval.json \
  --attestation-signing-key-ref .belgi/runs/run-001/inputs/anchors/signing/attestation_signing_key.hex \
  --seal-private-key-ref .belgi/runs/run-001/inputs/anchors/signing/seal_private_key.hex \
  --genesis-seal-ref .belgi/runs/run-001/inputs/evidence/genesis_seal.json
```

Shared-path outcome for Tier-3:
- C1 receives the required pubkey refs in `LockedSpec.environment_envelope`
- the operator-supplied `hotl_approval` artifact is indexed before Gate Q
- `test_report`, signed `env_attestation`, and `genesis_seal` are present on the same run spine before Gate R
- `genesis_seal` is verified under canonical `belgi/anchor/v1/TrustAnchor.json` authority at Gate R
- the Tier-3 seal signature is produced or verified on the same run spine before Gate S

## Verify Selection Priority

`belgi verify` selection is deterministic and sorted:
1. explicit: `--run-key` (and optional `--attempt-id`) verifies exactly that target
2. pointer: latest run workspace id with `last_attempt.txt` uses `run_key.txt` + `last_attempt.txt`
  - invalid pointer targets are skipped deterministically
3. store: lexicographically max run_key under `.belgi/store/runs/`, then max attempt id
  - used only when no valid pointer target remains

## Layout Map

- `.belgi/runs/<run_id>/`
  - human workspace and pointers (inputs, `RUN.md`, `open_verdict.txt`, `open_evidence.txt`)
- `.belgi/store/runs/<run_key>/<attempt_id>/`
  - authoritative artifacts (`GateVerdict.*.json`, `EvidenceManifest*.json`, summaries, reports)

Boundary:
- `.belgi/runs/...` is operator workspace.
- `.belgi/store/...` is authoritative run output.

## NO-GO Pointers

When `belgi run` returns public `NO-GO (10)`, inspect in this order:
1. `next`
   - prefers `GateVerdict.<Q|R|S>.json remediation.next_instruction` from a produced `NO-GO` gate verdict
   - otherwise uses current `C1IntentParseError.json next_instruction` when present
   - otherwise falls back to generic CLI guidance
2. `evidence.gate` + `evidence.gate_status` summary
3. `open.verdict_<gate>` target

Separate public `USER_ERROR (20)` path:
- input, argument, or repo-state failures may print direct CLI guidance instead of the `NO-GO (10)` precedence above

Human output mode:
- default: compact segmented block (summary, cause/next, evidence, open)
- `--verbose`: includes full authoritative store paths and expanded open helpers

Open helper behavior:
- default prints one copy/paste command for the current OS only
- set `BELGI_SHOW_ALL_OPEN=1` (or use `--verbose`) to print all OS command variants

Default open targets (exact order):
1. `verdict_<gate>`
2. `intent`
3. `waivers`

Verdict pointer behavior:
- `.belgi/runs/<run_id>/open_verdict.txt`
- label may show this pointer path for readability
- open command always opens the authoritative `GateVerdict.<Q|R|S>.json` file

Evidence manifest behavior:
- default shows `manifest: present|missing`
- manifest open target is omitted in default and only shown in verbose mode when present

Authoritative store paths remain available under `--verbose` (`verdict_Q_path`, `verdict_R_path`, `verdict_S_path`, `manifest_path`).

## Verify vs Bundle Check

- `belgi verify` rechecks the selected attempt’s stored summary/artifact hash bindings, `EvidenceManifest` contract, and waiver-expiry anchor against the produced run outputs.
- `belgi verify` does not create missing Tier-2/Tier-3 inputs, HOTL approvals, attestations, `genesis_seal`, or seals, and it does not substitute for missing run-path wiring.
- `belgi bundle check --demo` is a bounded demo-grade bundle checker.
- `belgi bundle check --demo` is not a full replay verifier and does not replace `belgi verify`.

## GO Output

Default GO output is compact and sectioned:
- `summary`
- `evidence` (`verdict_R`, `manifest`, `seal`)
- `open` (`verdict_R`, `manifest`, `intent`, `waivers`)

Verbose GO output includes authoritative absolute paths (`verdict_R_path`, `manifest_path`, `seal_path`) and expanded open helper variants.

Hyperlinks:
- OSC-8 links are opt-in only (`BELGI_HYPERLINKS=1`).
- Copy/paste open commands are always printed for terminal compatibility.

## Wheel vs Source Checkout

- Wheel install (`pip install belgi`):
  - publish boundary SSOT is `{belgi/, chain/, wrapper/, tools/}`
  - use packaged CLI surfaces (`belgi about`, `belgi run`, `belgi verify`, `belgi pack verify --builtin`)
- Source checkout:
  - includes the same shipped module prefixes plus repo-only operator surfaces (for example `policy/`, `.github/`, `housekeeping/`)

Deterministic boundary checker:
- `python -m tools.wheel_boundary --wheel <path-to-wheel>`
