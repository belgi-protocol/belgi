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
- `usefulcmds.txt/` (read or write -- this is users notes not important for you)
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
