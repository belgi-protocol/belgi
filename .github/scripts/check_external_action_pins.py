#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*(?P<value>\S+)\s*$")
DEFAULT_PATHS: tuple[str, ...] = (
    ".github/workflows",
    ".github/actions",
)


def _iter_target_files(repo_root: Path) -> list[Path]:
    files: list[Path] = []
    for rel in DEFAULT_PATHS:
        root = repo_root / rel
        if not root.exists():
            continue
        if root.is_file():
            files.append(root)
            continue
        files.extend(sorted(root.rglob("*.yml")))
        files.extend(sorted(root.rglob("*.yaml")))
    return sorted(set(files))


def _is_local_or_non_github_uses(value: str) -> bool:
    return value.startswith("./") or value.startswith("docker://")


def _is_external_action_uses(value: str) -> bool:
    if "@" not in value:
        return False
    source, _sep, _ref = value.partition("@")
    if not source or "/" not in source:
        return False
    return not _is_local_or_non_github_uses(value)


def find_floating_external_action_refs(repo_root: Path) -> list[tuple[str, int, str]]:
    violations: list[tuple[str, int, str]] = []
    for path in _iter_target_files(repo_root):
        rel = path.relative_to(repo_root).as_posix()
        text = path.read_text(encoding="utf-8", errors="strict")
        for lineno, line in enumerate(text.splitlines(), start=1):
            m = USES_RE.match(line)
            if not m:
                continue
            value = m.group("value")
            if not _is_external_action_uses(value):
                continue
            _source, _sep, ref = value.rpartition("@")
            if SHA40_RE.fullmatch(ref):
                continue
            violations.append((rel, lineno, value))
    return violations


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="check_external_action_pins",
        description="Fail closed if tracked workflow/action surfaces use floating external action refs.",
    )
    ap.add_argument("--repo", default=".", help="Repo root (default: .)")
    ns = ap.parse_args(argv)

    repo_root = Path(ns.repo).resolve()
    violations = find_floating_external_action_refs(repo_root)
    if not violations:
        print("PASS: all tracked external action refs are pinned by full commit SHA")
        return 0

    print(
        "FAIL-CLOSED: tracked workflow/action surfaces contain floating external action refs.",
        file=sys.stderr,
    )
    for rel, lineno, value in violations:
        print(f"- {rel}:{lineno}: {value}", file=sys.stderr)
    print(
        "Remediation: pin every external GitHub Action `uses:` entry to a full 40-hex commit SHA.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
