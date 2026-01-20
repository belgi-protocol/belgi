# scripts/

Small developer convenience scripts for working in this repo.

- `dev_sync.cmd` / `dev_sync.ps1`
  - Deterministic “sync my dev environment” helpers.
  - Intended to standardize local setup steps (no protocol semantics, no gate logic).

Notes:
- These scripts are developer tooling only; they are not part of the published `belgi` wheel interface.
- Keep changes deterministic: avoid network calls, timestamps, and machine-specific paths unless explicitly required.
