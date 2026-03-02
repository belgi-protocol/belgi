# BELGI CLI Operator Guide

Default verdict is `NO-GO` unless evidence proves otherwise.

This is the operator SSOT for CLI usage. Keep this file focused on:
- init
- run workspace creation
- run + verify
- NO-GO evidence pointers

For chain module reference commands, use:
- `docs/operations/running-belgi.md`

## Quickstart

```bash
# 1) Initialize BELGI surfaces in the repo
belgi init --repo .

# 2) Create a run workspace
belgi run new --repo . --run-id run-001

# 3) Edit intent input
# .belgi/runs/run-001/inputs/intent/IntentSpec.core.md

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
2. `evidence.gate` + `evidence.gate_verdicts` summary
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

## Wheel vs Source Checkout

- Wheel install (`pip install belgi`):
  - use packaged CLI surfaces (`belgi about`, `belgi run`, `belgi verify`, `belgi pack verify --builtin`)
- Source checkout:
  - includes repo-local chain modules and stage forwarders (`belgi stage ...`)

If `belgi stage` reports missing repo-local modules, run from a BELGI source checkout.
