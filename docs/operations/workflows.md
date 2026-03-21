# Workflows (Operations)

This page defines the hosted workflow surfaces and hosted required gate contexts for BELGI GitHub Actions.

Proof surfaces and required gate contexts are not the same thing.
GitHub may show additional job-level checks in the UI.
Hosted governance should bind only to the stable required gate contexts listed here.

These workflows prove different things under different input and trust models.
Overlap in Tier-0/Tier-1 execution does not make them duplicates.

## Proof Surfaces

- `repository-verification.yml`
  - visible name: `Repository Verification`
  - repo/package verification surface.
- `pull-request-proof.yml`
  - visible name: `Pull Request Proof`
  - exact PR-head review proof surface.
- `pinned-install-proof.yml`
  - visible name: `Pinned Install Proof`
  - reusable/manual pinned-install proof surface.

## Required Gate Contexts

Hosted rulesets or branch protection should require these stable gate contexts:

- `repository-verification-gate`
- `pull-request-proof-gate`

Do not bind hosted governance to volatile matrix/job surfaces.
Do not bind hosted governance to workflow display names alone.

`Pinned Install Proof` is not a PR-required context in `v1.4.17`.
If present, `pinned-install-proof-gate` is a human-readable summary inside that workflow, not a hosted merge requirement in this release.

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

Hosted job topology:
- `health`
- `wheel-build`
- `wheel-smoke`
- `repository-verification-gate`

Package proof topology:
- one canonical wheel build job builds the wheel once
- one boundary verification step verifies that canonical built artifact
- the built wheel artifact is uploaded once
- compatibility jobs install and test that same exact wheel artifact across the supported Python versions

`repository-verification-gate` is the stable hosted required context for this surface.
It depends on the proof-carrying jobs and fails closed if any required upstream job fails or is cancelled.
Tracked `ruff` configuration is active on this surface for the chosen `F`, `I`, and `B` rule families. It is repo-maintenance enforcement only, not a separate protocol-proof surface. Pyright remains non-gating.

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

Hosted job topology:
- `preflight`
- `smoke`
- `wheel-smoke`
- `pull-request-proof-gate`

`Pull Request Proof` is pull-request driven.
The proof-carrying jobs are label-gated by `proof:full`.
`pull-request-proof-gate` is the stable hosted required context for this surface.
Without `proof:full`, that gate remains NO-GO and the exact PR-head proof is not satisfied.
This avoids permanently pending required contexts while keeping the governance story explicit.

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

Hosted job topology:
- `belgi`
- `pinned-install-proof-gate`

It is a bounded pinned-install path, not a PR-artifact collector.
It is manual/reusable and not PR-required in `v1.4.17`.
Artifact names include the resolved BELGI ref short prefix so the verified install target remains visible across OS/tier matrix entries.

Pinned install uses the declared build path for `pip install git+repo@sha`.
It does not rely on `--no-build-isolation` as an ambient runner shortcut.

## Hosted Governance Settings

- Protect `main` and `dev` with required status checks before merge.
- Enable required pull-request reviews and require review from Code Owners.
- After this patch, select only these hosted required contexts:
  - `repository-verification-gate`
  - `pull-request-proof-gate`

GitHub may still display additional check runs for matrix jobs or proof-carrying jobs.
That is expected.
Hosted governance should still bind only to the two stable gate contexts above.

## Triggering Pull Request Proof

Trigger steps for `pull-request-proof.yml`:

1. Open or update the PR.
2. Add label `proof:full` to the PR.
3. Wait for `pull-request-proof-gate` to pass.

Without `proof:full`, the workflow still emits the stable gate context, but the exact PR-head proof remains unsatisfied.

## Triggering Pinned Install Proof

Use either:

1. `workflow_dispatch` with explicit `belgi_ref` / optional `belgi_repo_url`, or
2. `workflow_call` with the same inputs (or repository vars fallback).

## Evidence Collection

Download artifacts from the GitHub Actions UI when the hosted run is part of the audit set.

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
