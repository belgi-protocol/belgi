# Dev Tier Runbook (Q/R Loop)

This runbook is for adopter-repo day-to-day development.

Canonical chain still applies: `P → C1 → Q → C2 → R → C3 → S`.

## 0) One-time repo initialization

```bash
belgi init --repo .
```

If the builtin protocol pack pin changes later, `belgi init` fails closed until you opt in:

```bash
belgi init --repo . --refresh-pin
```

Expected created files (if missing):

- `.belgi/adopter.toml`
- `.belgi/README.md`
- `.belgi/templates/IntentSpec.core.template.md`
- `belgi_pack/DomainPackManifest.json`

## 1) Start a run workspace

Pick a run ID and create a deterministic run folder:

```bash
export RUN_ID=run-dev-001
belgi run new --repo . --run-id ${RUN_ID}
```

Outputs:

- `.belgi/runs/${RUN_ID}/IntentSpec.core.md`

## 2) Compile + lock early (C1 + Q)

Compile candidate lock:

```bash
python -m chain.compiler_c1_intent \
  --repo . \
  --intent-spec .belgi/runs/${RUN_ID}/IntentSpec.core.md \
  --out .belgi/runs/${RUN_ID}/LockedSpec.json \
  --run-id ${RUN_ID} \
  --repo-ref owner/repo \
  --prompt-bundle-out .belgi/runs/${RUN_ID}/prompt_bundle.bin \
  --tolerances tol-001=.belgi/runs/${RUN_ID}/tolerances.json \
  --envelope-id env-dev \
  --envelope-description "dev envelope" \
  --expected-runner local \
  --toolchain-ref tc-001=.belgi/runs/${RUN_ID}/toolchain.json
```

Seed/update evidence manifest (example using existing helper flow):

```bash
python -m tools.belgi manifest-init \
  --repo . \
  --out .belgi/runs/${RUN_ID}/EvidenceManifest.json \
  --locked-spec .belgi/runs/${RUN_ID}/LockedSpec.json
```

Add/update evidence artifacts deterministically with installed CLI:

```bash
belgi manifest add \
  --repo . \
  --manifest .belgi/runs/${RUN_ID}/EvidenceManifest.json \
  --artifact .belgi/runs/${RUN_ID}/artifacts/policy.overlay.json \
  --kind policy_report \
  --id policy.overlay \
  --media-type application/json \
  --produced-by R
```

Run Gate Q:

```bash
python -m chain.gate_q_verify \
  --repo . \
  --intent-spec .belgi/runs/${RUN_ID}/IntentSpec.core.md \
  --locked-spec .belgi/runs/${RUN_ID}/LockedSpec.json \
  --evidence-manifest .belgi/runs/${RUN_ID}/EvidenceManifest.json \
  --out .belgi/runs/${RUN_ID}/GateVerdict.Q.json
```

Outputs:

- `.belgi/runs/${RUN_ID}/LockedSpec.json`
- `.belgi/runs/${RUN_ID}/EvidenceManifest.json`
- `.belgi/runs/${RUN_ID}/GateVerdict.Q.json`

Cadence: run Q frequently ("tak tak") while tightening intent/lock quality.

## 3) Dev checkpoint verify (R)

At meaningful checkpoints, run Gate R:

```bash
python -m chain.gate_r_verify \
  --repo . \
  --locked-spec .belgi/runs/${RUN_ID}/LockedSpec.json \
  --gate-q-verdict .belgi/runs/${RUN_ID}/GateVerdict.Q.json \
  --evidence-manifest .belgi/runs/${RUN_ID}/EvidenceManifest.json \
  --evaluated-revision HEAD \
  --gate-verdict-out .belgi/runs/${RUN_ID}/GateVerdict.R.json \
  --out .belgi/runs/${RUN_ID}/verify_report.json \
  --overlay belgi_pack
```

Outputs:

- `.belgi/runs/${RUN_ID}/verify_report.json`
- `.belgi/runs/${RUN_ID}/GateVerdict.R.json`

Cadence: run R at checkpoints, not on every tiny edit.

Overlay-only preflight helper (installed CLI, no `chain/` dependency):

```bash
belgi policy check-overlay \
  --repo . \
  --evidence-manifest .belgi/runs/${RUN_ID}/EvidenceManifest.json \
  --overlay belgi_pack
```

Generate deterministic adopter overlay policy report:

```bash
belgi policy stub \
  --out .belgi/runs/${RUN_ID}/artifacts/policy.overlay.json \
  --run-id ${RUN_ID} \
  --check-id PFY-OVERLAY-001
```

## 4) Optional dev extras

Optional C3:

```bash
python -m chain.compiler_c3_docs \
  --repo . \
  --locked-spec .belgi/runs/${RUN_ID}/LockedSpec.json \
  --gate-q-verdict .belgi/runs/${RUN_ID}/GateVerdict.Q.json \
  --gate-r-verdict .belgi/runs/${RUN_ID}/GateVerdict.R.json \
  --r-snapshot-manifest .belgi/runs/${RUN_ID}/EvidenceManifest.json \
  --out-final-manifest .belgi/runs/${RUN_ID}/EvidenceManifest.final.json \
  --out-log .belgi/runs/${RUN_ID}/docs_compilation_log.json \
  --out-docs .belgi/runs/${RUN_ID}/run_docs.md \
  --out-bundle-dir .belgi/runs/${RUN_ID}/bundle \
  --out-bundle-root-sha .belgi/runs/${RUN_ID}/bundle_root.sha256 \
  --profile internal \
  --prompt-block-hashes .belgi/runs/${RUN_ID}/prompt_block_hashes.json
```

Optional seal + S:

```bash
python -m chain.seal_bundle --repo . ... --out .belgi/runs/${RUN_ID}/SealManifest.json
python -m chain.gate_s_verify --repo . ... --out .belgi/runs/${RUN_ID}/GateVerdict.S.json
```

Use seal/S in dev when you need replay-grade artifacts; always use for release-grade workflows.
