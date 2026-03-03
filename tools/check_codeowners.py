#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class CodeownersEntry:
    line_no: int
    pattern: str


def _split_line(raw: str) -> tuple[str, list[str]]:
    content = raw.split("#", 1)[0].strip()
    if not content:
        return "", []
    parts = content.split()
    if len(parts) < 2:
        return "", []
    return parts[0], parts[1:]


def parse_codeowners_entries(text: str) -> list[CodeownersEntry]:
    out: list[CodeownersEntry] = []
    for line_no, raw in enumerate(text.splitlines(), start=1):
        pattern, owners = _split_line(raw)
        if not pattern or not owners:
            continue
        out.append(CodeownersEntry(line_no=line_no, pattern=pattern))
    return out


def _matches_for_pattern(repo_root: Path, pattern: str) -> list[Path]:
    normalized = pattern.strip().lstrip("/")
    if not normalized:
        return []
    has_glob = any(ch in normalized for ch in "*?[")
    if has_glob:
        return sorted([p for p in repo_root.glob(normalized) if p.exists()], key=lambda p: p.as_posix())
    candidate = repo_root / normalized
    if candidate.exists():
        return [candidate]
    return []


def find_missing_codeowners_patterns(repo_root: Path, codeowners_path: Path) -> list[str]:
    text = codeowners_path.read_text(encoding="utf-8", errors="strict")
    entries = parse_codeowners_entries(text)
    try:
        codeowners_rel = codeowners_path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        codeowners_rel = codeowners_path.as_posix()
    missing: list[str] = []
    for entry in entries:
        if _matches_for_pattern(repo_root, entry.pattern):
            continue
        missing.append(f"{codeowners_rel}:{entry.line_no}:{entry.pattern}")
    return sorted(missing)


def run_check(*, repo_root: Path, codeowners_rel: str) -> int:
    path = (repo_root / codeowners_rel).resolve()
    try:
        rel = path.relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        print(f"NO-GO: CODEOWNERS path must be under repo root: {path}")
        return 2
    if not path.exists() or not path.is_file() or path.is_symlink():
        print(f"NO-GO: missing/invalid CODEOWNERS file: {rel}")
        return 2

    missing = find_missing_codeowners_patterns(repo_root, path)
    if missing:
        print("NO-GO: CODEOWNERS entries match no files:")
        for row in missing:
            print(f" - {row}")
        return 1

    print(f"PASS: CODEOWNERS entries resolve to existing repo paths ({rel})")
    return 0


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="check_codeowners",
        description="Deterministic CODEOWNERS path checker (fail-closed on dead paths).",
    )
    ap.add_argument("--repo", default=".", help="Repository root (default: .)")
    ap.add_argument("--codeowners", default=".github/CODEOWNERS", help="CODEOWNERS path (repo-relative)")
    ns = ap.parse_args(list(argv) if argv is not None else None)

    repo_root = Path(ns.repo).resolve()
    if not repo_root.exists() or not repo_root.is_dir():
        print(f"NO-GO: invalid repo root: {repo_root}")
        return 2
    return run_check(repo_root=repo_root, codeowners_rel=str(ns.codeowners))


if __name__ == "__main__":
    raise SystemExit(main())
