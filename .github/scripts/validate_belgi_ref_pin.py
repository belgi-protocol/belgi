#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys


PIN_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
FLOATING_REFS = {"main", "master", "latest", "head"}
PIN_EXAMPLE = "0123456789abcdef0123456789abcdef01234567"


def _failure_message(detail: str) -> str:
    return (
        "FAIL-CLOSED: BELGI_REF must be an immutable 40-hex commit SHA "
        "(accepted format: ^[0-9a-f]{40}$). "
        f"Example: {PIN_EXAMPLE}. "
        f"{detail} "
        "Floating refs are rejected for reproducibility and integrity."
    )


def validate_belgi_ref_pin(ref: str) -> tuple[bool, str]:
    candidate = str(ref or "").strip()
    if not candidate:
        return False, _failure_message("BELGI_REF is empty.")

    low = candidate.lower()
    if low in FLOATING_REFS:
        return False, _failure_message(
            f"Rejected floating ref: {candidate!r} (examples: main/latest/HEAD)."
        )

    if PIN_SHA_PATTERN.fullmatch(candidate):
        return True, f"OK: BELGI_REF is immutable SHA pin: {candidate}"

    if re.fullmatch(r"[0-9a-f]{7,39}", low):
        detail = f"Rejected short SHA: {candidate!r}; use full 40-hex commit SHA."
    else:
        detail = (
            f"Rejected non-SHA ref: {candidate!r}; branches/tags/aliases are mutable and not allowed."
        )
    return False, _failure_message(detail)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="validate_belgi_ref_pin",
        description="Fail-closed BELGI_REF pin validator (requires full 40-hex SHA).",
    )
    ap.add_argument("--ref", required=True, help="BELGI_REF value to validate")
    ns = ap.parse_args(argv)

    ok, message = validate_belgi_ref_pin(ns.ref)
    if ok:
        print(message)
        return 0
    print(message, file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
