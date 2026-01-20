#!/usr/bin/env python3
"""Compatibility wrapper for repo-local BELGI tooling.

Why:
- A script named "tools/belgi.py" can shadow the real "belgi" package when
  invoked by path (Python places the script directory first on sys.path).

Preferred entrypoint:
- Use tools/belgi_tools.py.

This wrapper remains for backwards compatibility and simply dispatches to
tools/belgi_tools.py.
"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path


def main() -> int:

    # Ensure ENGINE repo root precedes tools/ on sys.path.
    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    target = Path(__file__).with_name("belgi_tools.py")
    if not target.exists():
        print("[belgi tools] ERROR: tools/belgi_tools.py missing", file=sys.stderr)
        return 3

    try:
        runpy.run_path(str(target), run_name="__main__")
    except SystemExit as e:
        code = e.code
        if code is None:
            return 0
        if isinstance(code, int):
            return code
        return 3

    return 0


if __name__ == "__main__":
    sys.exit(main())

