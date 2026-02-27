#!/usr/bin/env bash
#
# Usage:
#   bash scripts/belgi_latest_run.sh [--root <repo_root>]
#
# Purpose:
#   Print the latest BELGI run attempt path and key triage files.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENTRYPOINT="$SCRIPT_DIR/belgi_latest_run.py"

if [[ ! -f "$ENTRYPOINT" ]]; then
  echo "[belgi latest-run] ERROR: missing helper script: $ENTRYPOINT" >&2
  exit 2
fi

if command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
else
  echo "[belgi latest-run] ERROR: python is required but was not found in PATH." >&2
  exit 2
fi

exec "$PYTHON_BIN" "$ENTRYPOINT" "$@"
