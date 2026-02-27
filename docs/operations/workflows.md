# Workflows (Operations)

This page defines the operational purpose and trigger model for BELGI GitHub
Actions workflows.

## Workflow Set

- `ci.yml`
  - always-on baseline checks for repository health and wheel smoke.
- `proof-tier1.yml`
  - opt-in proof workflow for release-grade PR evidence collection.

## Triggering `proof-tier1.yml`

`proof-tier1.yml` is pull-request driven but job execution is label-gated.

Trigger steps:

1. Open/update the PR.
2. Add label `proof:full` to the PR.
3. Wait for proof jobs to complete.

Without `proof:full`, proof jobs are skipped.

## Evidence Collection (Audit)

Download artifacts from GitHub Actions UI:

1. Actions -> run -> Artifacts.
2. Collect:
   - `proof-preflight-<pr_sha>`
   - `proof-smoke-<os>-<pr_sha>`
   - `proof-wheel-<pr_sha>`
   - `proof-wheel-logs-<pr_sha>`

These artifacts are the PR-branch proof evidence surface (logs, smoke outputs,
and built wheel) for audit.
