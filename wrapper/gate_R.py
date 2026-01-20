#!/usr/bin/env python3
"""Strict forwarder to chain/gate_r_verify.py."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    target = repo_root / "chain" / "gate_r_verify.py"
    os.execv(sys.executable, [sys.executable, str(target), *sys.argv[1:]])
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
