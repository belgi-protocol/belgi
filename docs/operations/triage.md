# BELGI Triage Quick Path

Helpers in `scripts/` are convenience only. BELGI verifiers and gate verdict artifacts are the authority.

## 30-second pointers

### If you installed via wheel

- Expected to work: packaged BELGI CLI surfaces (for example `belgi about`, `belgi pack verify --builtin`).
- Repo-local only surface: `belgi stage` forwarders (`chain/*` modules must be available in the execution context).
- Detection signal:
  - `belgi stage ...` returns `USER_ERROR (20)` with:
    - `repo-local stage module missing; run inside BELGI source checkout or use canonical python -m chain.<...> invocation`

### If you are in a source checkout

- Use `belgi stage` for targeted per-stage operations; it is a strict forwarder to `python -m chain.*`.
- Prefer `belgi run` for the canonical end-to-end orchestration spine and consolidated run artifacts.

## Where artifacts live

BELGI run artifacts are repo-local under the workspace runs root, typically:

- `.belgi/store/runs/<run_key>/<attempt_id>/`

## Inspection order

1. `run.summary.json`
2. machine-readable result JSON (if your runtime emitted one)
3. gate outputs (`GateVerdict.Q.json`, `GateVerdict.R.json`, `GateVerdict.S.json`, `verify_report.R.json`)

## Minimal support/proof paste checklist

1. Exact command(s) executed and exit code(s).
2. Run root path (`<run_key>/<attempt_id>`).
3. `run.summary.json` path.
4. Gate output paths and first failure reason if verdict is `NO-GO`.
