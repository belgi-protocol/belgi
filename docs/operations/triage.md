# BELGI Triage Quick Path

Helpers in `scripts/` are convenience only. BELGI verifiers and gate verdict artifacts are the authority.

## Where artifacts live

BELGI run artifacts are repo-local under the workspace runs root, typically:

- `.belgi/runs/<run_key>/<attempt_id>/`

## Inspection order

1. `run.summary.json`
2. machine-readable result JSON (if your runtime emitted one)
3. gate outputs (`GateVerdict.Q.json`, `GateVerdict.R.json`, `GateVerdict.S.json`, `verify_report.R.json`)

## Minimal support/proof paste checklist

1. Exact command(s) executed and exit code(s).
2. Run root path (`<run_key>/<attempt_id>`).
3. `run.summary.json` path.
4. Gate output paths and first failure reason if verdict is `NO-GO`.
