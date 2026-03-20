# BELGI CLI Operator Guide

This is the operator SSOT for CLI usage. Keep this file focused on:
- init
- run workspace creation
- run + verify
- NO-GO evidence pointers

For chain module reference commands, use:
- `docs/operations/running-belgi.md`

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

# 4) Resolve a stable base SHA
BASE_SHA40=$(git rev-parse HEAD)

# 5) Run canonical CLI flow
belgi run \
  --repo . \
  --tier tier-1 \
  --intent-spec .belgi/runs/run-001/inputs/intent/IntentSpec.core.md \
  --base-revision "${BASE_SHA40}"

# 6) Verify run outputs
belgi verify --repo .
```

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

When `belgi run` returns `NO-GO`, inspect in this order:
1. `next` (authoritative next step)
2. `evidence.gate` + `evidence.gate_status` summary
3. `open.verdict_<gate>` target

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
