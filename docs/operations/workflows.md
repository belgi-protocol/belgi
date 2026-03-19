# Workflows (Operations)

This page defines the hosted workflow surfaces for BELGI GitHub Actions.

These workflows prove different things under different input and trust models.
Overlap in Tier-0/Tier-1 execution does not make them duplicates.

## Workflow Set

- `repository-verification.yml`
  - visible name: `Repository Verification`
  - repo/package verification surface.
- `pull-request-proof.yml`
  - visible name: `Pull Request Proof`
  - exact PR-head review proof surface.
- `pinned-install-proof.yml`
  - visible name: `Pinned Install Proof`
  - reusable/manual pinned-install proof surface.

## Repository Verification

`Repository Verification` is the repo/package verification surface.

It owns:
- repo health / drift / guards / tests / sweeps
- canonical wheel build
- wheel boundary verification
- installed-wheel runtime compatibility proof

It does not own:
- exact PR-head review proof
- reusable/manual pinned-install proof
- Tier-2/Tier-3 hosted operator path

## Pull Request Proof

`Pull Request Proof` is the exact PR-head review proof surface.

It owns:
- exact `github.event.pull_request.head.sha` preflight
- immutable SHA pin verification
- Tier-0 cross-platform smoke for the exact PR head
- Tier-1 Ubuntu smoke for the exact PR head
- PR-scoped audit artifacts
- exact PR-head package proof for the reviewed candidate revision

It does not own:
- canonical repo/package verification ownership
- reusable/manual pinned-install proof
- Tier-2/Tier-3 hosted operator path

It is pull-request driven and job execution is label-gated by `proof:full`.
Without `proof:full`, proof jobs are skipped.

## Pinned Install Proof

`Pinned Install Proof` is the reusable/manual pinned-install proof surface.

It owns:
- caller/manual BELGI ref and repo URL input
- fail-closed immutable BELGI ref verification
- pinned source install via `git+repo@sha`
- Tier-0 cross-platform smoke from installed BELGI
- Tier-1 Ubuntu smoke from installed BELGI
- pinned-install run artifacts

It does not own:
- PR review proof
- canonical repo/package verification ownership
- Tier-2/Tier-3 hosted operator path

It is a bounded pinned-install path, not a PR-artifact collector.
Artifact names include the resolved BELGI ref short prefix so the verified install target remains visible across OS/tier matrix entries.

## Required GitHub Settings

- Protect `main` and `dev` with required status checks before merge.
- Enable required pull-request reviews and require review from Code Owners.

## Triggering Pull Request Proof

Trigger steps for `pull-request-proof.yml`:

1. Open/update the PR.
2. Add label `proof:full` to the PR.
3. Wait for proof jobs to complete.

## Triggering Pinned Install Proof

Use either:

1. `workflow_dispatch` with explicit `belgi_ref` / optional `belgi_repo_url`, or
2. `workflow_call` with the same inputs (or repository vars fallback).

## Evidence Collection

Download artifacts from GitHub Actions UI when the hosted run is part of the audit set.

`Pull Request Proof` artifacts:
- `proof-preflight-<pr_sha>`
- `proof-smoke-<os>-<pr_sha>`
- `proof-wheel-<pr_sha>`
- `proof-wheel-logs-<pr_sha>`

`Pinned Install Proof` artifacts:
- `pinned-install-<belgi_ref_short>-<os>-<tier>`

`Repository Verification` proves repo/package truth, `Pull Request Proof` proves the exact candidate revision inside repo review flow, and `Pinned Install Proof` proves the reusable/manual pinned install path from a caller-supplied immutable ref.

## Release Boundary

- BELGI signs/verifies protocol evidence.
- The release/publish boundary is currently manual/operator-owned.
- Stronger release artifact provenance is future work, not a present claim.
- Tier-2/Tier-3 remains outside the hosted proof-backed workflow surface in this patch.
