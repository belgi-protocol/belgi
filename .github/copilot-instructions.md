# Copilot Instructions — BELGI Repo (DEV-SAFE, non-blocking)

You are working in the BELGI repository during active development.
Goal: **ship fast** without breaking the repo’s integrity/determinism posture.

## 1) Prime rule
- **Don’t stall development.**
- **Don’t ship silent holes.**
- Block only on **critical** risks (below). Otherwise proceed and report.

## 2) CRITICAL risks (only these are blockers)
You MUST stop (ask 1 targeted question) or fail-closed if your change would create any of:

1) **Fail-open**: errors/missing inputs still lead to PASS / exit 0.
2) **Scope escape**: any authoritative input/output path can resolve outside repo root (incl. symlinks).
3) **Schema/evidence drift**: changing required fields, artifact formats, or acceptance rules without updating the canonical schema/docs that define them.
4) **Non-determinism**: timestamps, randomness, locale/timezone, unstable ordering, network calls in gates/sweeps/verifiers.
5) **Public CI regression**: any change that could make `.github/workflows/ci.yml` go red after pushing.

If none of these apply, **do not block**.

## 3) Hard rules (non-negotiable)
1) **Never weaken guarantees silently**
   - No MUST→SHOULD, FAIL→WARN, required→optional unless user explicitly requests it.
2) **Fail-closed by default (gates/sweeps/verifiers)**
   - Any enumerate/read/parse/resolve error => non-zero exit.
   - Empty scan (`checked==0`) => FAIL unless an explicit `--allow-empty` exists (default false).
3) **Repo-root confinement (READ + WRITE)**
   - Reject absolute paths, `..`, NUL bytes for any authoritative path.
   - Resolve paths and ensure they stay under repo root.
   - Reject symlinks for security-relevant scopes (or skip+FAIL; never silently).
4) **No hidden bypass logic**
   - No undocumented skip rules/exemptions.
   - Any exception must be explicit, discoverable, and default-closed.
5) **Determinism posture**
   - Stable ordering (sorted lists), stable serialization, no locale/timezone dependence.
   - Prefer `sys.executable` over `"python"` in subprocess.
   - No network calls in gates unless explicitly gated + evidenced.

## 4) Scope policy (repo must not get wrecked)
### GREEN (ok to modify)
- Tracked code and tracked docs needed to satisfy the current request.

### YELLOW (read ok, write only if explicitly asked)
- **gitignored paths**: may read for context/verification; do not modify unless explicitly asked.
  - If a workflow expects updating a gitignored artifact, generate a **tracked alternative** under repo (e.g., `temp/` or `reports/`) and mention it.

### RED (never touch unless explicitly asked)
- `temp/usefılcmds.txt` (read or write -- user notes; never touch)
- any explicitly private/pro vault paths (if present)

## 5) Ambiguity rule (the correct version)
If something is ambiguous:
- **Do not invent semantics.**
- Proceed only with changes that are **mechanical + reversible** and cannot create CRITICAL risks.
- If ambiguity touches CRITICAL risks (Section 2): ask **one** targeted question and stop.

## 6) Comment policy (tight)
- No obvious comments.
- Add only **invariant comments** above security/determinism checks (1 line max):
  - “what is authenticated/bound?”
  - “what is canonicalized/normalized?”

Example:
```python
# Bind attestation payload to (run_id, command_log_sha256) to prevent replay/substitution.
```


## 7) Tooling hygiene (keep repo neat)

Hard rule: **do not introduce new top-level tools** (new Python scripts/entrypoints) unless the user explicitly asks.

Canonical tool entrypoints:
- `tools/sweep.py` — all sweeps live here as subcommands
- `tools/rehash.py` — all rehash utilities live here as subcommands

If you need new functionality:
- Add a new subcommand under the appropriate canonical file (usually `tools/sweep.py` or `tools/rehash.py`).
- Do NOT create helper modules like `tools/_new_thing.py` to hold logic; keep it in the canonical file unless the user explicitly requests a split.

Naming conventions (non-negotiable):
- Gates are gates: Q/R/S
- Seal is seal
- Fixture sweep commands:
   - `fixtures-q`, `fixtures-r`, `fixtures-qr` for Gate Q/R
   - `fixtures-s` for **Gate S** (verifier)
   - `fixtures-seal` for **Seal** (producer)

## 8) File Creation (ask first)

Hard rule: **Do not create new tracked files** (including extra `README.md` files) unless the user explicitly asks.

Preference:
- Keep explanations centralized in existing canonical docs (e.g. `policy/fixtures/README.md`) instead of adding per-folder READMEs.

## 9) Mandatory per-dev workflow (public-green)

This repo is public-facing. **Do not push, merge, tag, or fast-forward `main` unless the full workflow is green locally**.

### A) Before running CI (local convergence)
- If your changes touch any of: `policy/**`, `schemas/**`, `belgi/_protocol_packs/**`, `chain/**`, `tools/**` or anything that can affect fixtures/sweeps, you MUST run the local convergence flow described in `docs/operations/*` (dev-sync).
- If convergence generates tracked diffs (e.g. fixtures pins, sweep reports), commit them on your feature branch before CI.

### A0) Best practice: single converge commit

Goal: avoid “calibration commit spam” while staying deterministic.

- Phase 1 (human edits): do all code/doc/version/changelog changes first.
- Phase 2 (converge once, at the end): run the required convergence steps (dev-sync / `--fix-fixtures`) exactly once, then commit *all* resulting governed diffs together.
- Do NOT run `act` (or any CI gate) between Phase 1 edits and Phase 2 convergence.

Notes:
- Consistency sweep fixture pins (e.g., CS-EV-006) can legitimately change when you touch apparently unrelated tracked content (docs, `VERSION`, `CHANGELOG.md`, policy files). Treat that as normal: converge once at the end.
- If you have not pushed your branch yet, prefer folding the convergence diff into your last “human edits” commit via `git commit --amend` to keep history clean. If the branch is already pushed, do NOT rewrite history; add one final convergence commit.

### B) Local preflight checks (must be clean)
Run these from repo root and ensure they pass with **no tracked changes** afterwards:
- `python -m tools.normalize --repo . --check --tracked-only`
- `python -m tools.check_drift`

### C) Full CI workflow locally (must be green)
Run the actual GitHub Actions workflow locally via `act` (includes `health` + `wheel-smoke`):
- `act -W .github/workflows/ci.yml -P ubuntu-latest=ghcr.io/catthehacker/ubuntu:full-latest --container-architecture linux/amd64 --rm --artifact-server-path /tmp/act-artifacts-belgi`

Notes:
- The `--artifact-server-path` flag is mandatory so `actions/upload-artifact` doesn’t fail locally (no `ACTIONS_RUNTIME_TOKEN`).
- If any job fails locally, treat it as a blocker (Section 2.5). Fix before pushing.

### D) Push/merge discipline (never invert order)
- Do NOT fast-forward or merge into `main` until (B) and (C) are green on the feature branch.
- Do NOT tag a release until the exact commit to be tagged has a green (C) run.
