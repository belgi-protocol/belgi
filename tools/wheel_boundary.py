#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from typing import Iterable
import zipfile


REQUIRED_MODULE_PREFIXES: tuple[str, ...] = (
    "belgi/",
    "chain/",
    "wrapper/",
    "tools/",
)

FORBIDDEN_MODULE_PREFIXES: tuple[str, ...] = (
    "tests/",
    "policy/",
    "gates/",
    "schemas/",
    "tiers/",
    "docs/",
    "housekeeping/",
    "scripts/",
    "templates/",
    "assets/",
    "compilers/",
    "belgi_pack/",
)


def list_wheel_entries(wheel_path: Path) -> list[str]:
    with zipfile.ZipFile(wheel_path) as zf:
        return sorted(zf.namelist())


def wheel_listing_sha256(entries: list[str]) -> str:
    payload = "".join(f"{entry}\n" for entry in entries).encode("utf-8", errors="strict")
    return hashlib.sha256(payload).hexdigest()


def module_prefixes(entries: list[str]) -> list[str]:
    prefixes: set[str] = set()
    for entry in entries:
        norm = entry.rstrip("/")
        if "/" not in norm:
            continue
        head = norm.split("/", 1)[0]
        if head.endswith(".dist-info") or head.endswith(".data"):
            continue
        prefixes.add(f"{head}/")
    return sorted(prefixes)


def validate_wheel_boundary(entries: list[str]) -> list[str]:
    prefixes = set(module_prefixes(entries))
    violations: list[str] = []
    missing_required = sorted([prefix for prefix in REQUIRED_MODULE_PREFIXES if prefix not in prefixes])
    present_forbidden = sorted([prefix for prefix in FORBIDDEN_MODULE_PREFIXES if prefix in prefixes])
    unexpected = sorted(prefixes - set(REQUIRED_MODULE_PREFIXES))
    if missing_required:
        violations.append(f"missing required module prefixes: {', '.join(missing_required)}")
    if present_forbidden:
        violations.append(f"forbidden module prefixes present: {', '.join(present_forbidden)}")
    if unexpected:
        violations.append(f"unexpected module prefixes present: {', '.join(unexpected)}")
    return violations


def run_check(*, wheel_path: Path) -> int:
    if not wheel_path.exists() or not wheel_path.is_file() or wheel_path.is_symlink():
        print(f"NO-GO: invalid wheel path: {wheel_path}")
        return 2
    if wheel_path.suffix != ".whl":
        print(f"NO-GO: expected .whl input, got: {wheel_path}")
        return 2

    entries = list_wheel_entries(wheel_path)
    prefixes = module_prefixes(entries)
    violations = validate_wheel_boundary(entries)

    print(f"wheel={wheel_path.as_posix()}")
    print(f"entries_total={len(entries)}")
    print(f"entries_sha256={wheel_listing_sha256(entries)}")
    print(f"module_prefixes={','.join(prefixes)}")

    if violations:
        print("NO-GO: wheel boundary validation failed:")
        for violation in violations:
            print(f" - {violation}")
        return 1

    print("PASS: wheel boundary matches SSOT prefixes")
    return 0


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="wheel_boundary",
        description="Deterministic wheel boundary checker (module prefix SSOT).",
    )
    ap.add_argument("--wheel", required=True, help="Path to built wheel (.whl)")
    ns = ap.parse_args(list(argv) if argv is not None else None)
    return run_check(wheel_path=Path(str(ns.wheel)).resolve())


if __name__ == "__main__":
    raise SystemExit(main())
