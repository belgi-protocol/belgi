#!/usr/bin/env python3
"""Project Byte Guard: authoritative CRLF normalization.

This tool is a first-class, deterministic guard that protects byte-addressed
integrity (sha256(bytes)) across OSes by ensuring repository text artifacts do
not contain CRLF (\r\n) or lone CR (\r) bytes.

- --check: detect drift and fail closed.
- --fix: normalize bytes atomically to LF, then orchestrate subordinate rehash,
         then self-audit via a second scan.

Security / determinism posture:
- Repo-root confinement: reject path escape, absolute paths, NUL bytes.
- Symlink defense: reject symlink targets and any symlink parent.
- Binary-safe: never decode/encode for fixing; operates on bytes only.
- Atomic replace: write temp file, fsync, os.replace.
- Stable ordering: git enumeration + sorted paths.

Notes on "Mekanik Namus":
- All *text-mode* writes in this tool use newline="\n" explicitly.
- Byte rewrites use binary mode (no newline translation).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, List, Optional, Sequence, Tuple


_REPO_ROOT_FOR_IMPORTS = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT_FOR_IMPORTS) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT_FOR_IMPORTS))

from belgi.core.jail import normalize_repo_rel as _normalize_repo_rel
from belgi.core.jail import resolve_repo_rel_path as _resolve_repo_rel_path


DEFAULT_EXCLUDE_ROOTS = [
    ".git",
    ".venv",
    "__pycache__",
    "archive",
]

# Extensions that are treated as definitely-binary and will never be rewritten.
BINARY_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
    ".7z",
    ".exe",
    ".dll",
    ".pyd",
    ".so",
    ".dylib",
}

# Filenames that are treated as safe-to-normalize even without an extension.
FORCE_TEXT_FILENAMES = {
    "LICENSE",
    "VERSION",
    "CANONICALS.md",
    "CHANGELOG.md",
    "README.md",
    "TRADEMARK.md",
    "terminology.md",
    "trust-model.md",
    ".gitattributes",
    ".gitignore",
    "CODEOWNERS",
}

# Extensions that we consider safe-to-normalize (even if they include high-bit bytes).
FORCE_TEXT_EXTENSIONS = {
    "",
    ".py",
    ".md",
    ".txt",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".ps1",
    ".sh",
    ".schema.json",
    ".svg",
}


@dataclass(frozen=True)
class DriftHit:
    path: str  # repo-relative posix
    crlf_pairs: int
    lone_cr: int
    safe_to_fix: bool
    reason: str


def _relposix(repo_root: Path, p: Path) -> str:
    return p.resolve().relative_to(repo_root.resolve()).as_posix()


def _validate_repo_rel(rel: str) -> str:
    return _normalize_repo_rel(rel, allow_backslashes=True)


def _is_under_excluded_roots(rel_posix: str, exclude_roots: List[str]) -> bool:
    parts = rel_posix.split("/")
    if not parts:
        return False
    top = parts[0]
    for r in exclude_roots:
        rr = r.strip().replace("\\", "/").strip("/")
        if not rr:
            continue
        # Top-level only, consistent with repo policy.
        if top == rr:
            return True
    return False


def _run_git(repo_root: Path, args: Sequence[str]) -> bytes:
    try:
        return subprocess.check_output(["git", *args], cwd=str(repo_root))
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"git command failed: git {' '.join(args)} (exit={e.returncode})") from e


def _iter_git_paths(repo_root: Path, *, include_untracked: bool) -> List[str]:
    tracked = _run_git(repo_root, ["ls-files", "-z"])
    paths = tracked.split(b"\x00")

    if include_untracked:
        others = _run_git(repo_root, ["ls-files", "--others", "--exclude-standard", "-z"])
        paths.extend(others.split(b"\x00"))

    out: List[str] = []
    for raw in paths:
        if not raw:
            continue
        s = raw.decode("utf-8", errors="strict")
        s = _validate_repo_rel(s)
        out.append(s)

    out = sorted(set(out))
    return out


def _classify_safe_to_fix(rel_posix: str, b: bytes) -> Tuple[bool, str]:
    name = rel_posix.split("/")[-1]

    # Hard binary extension deny.
    lower = name.lower()
    for ext in BINARY_EXTENSIONS:
        if lower.endswith(ext):
            return False, f"binary_extension:{ext}"

    # NUL byte is a strong binary signal.
    if b"\x00" in b:
        return False, "nul_byte_present"

    # Explicit known-text filenames.
    if name in FORCE_TEXT_FILENAMES:
        return True, "force_text_filename"

    # Known-text extensions, including .schema.json.
    if lower.endswith(".schema.json"):
        return True, "force_text_extension:.schema.json"

    suf = Path(name).suffix.lower()
    if suf in FORCE_TEXT_EXTENSIONS:
        return True, f"force_text_extension:{suf or '<none>'}"

    # Heuristic: allow high-bit bytes (non-UTF8 legacy text), but treat lots of
    # control chars (excluding \t \n \r) as binary-ish.
    if not b:
        return True, "empty_file"

    bad = 0
    for by in b:
        if by in (9, 10, 13):
            continue
        if 32 <= by <= 126:
            continue
        if by >= 128:
            continue
        # Remaining control chars (0-8, 11-12, 14-31)
        bad += 1

    ratio = bad / max(1, len(b))
    if ratio > 0.05:
        return False, f"binary_heuristic_control_ratio:{ratio:.3f}"

    return True, f"text_heuristic_control_ratio:{ratio:.3f}"


def _scan_one(repo_root: Path, rel_posix: str) -> Tuple[int, int, bool, str]:
    try:
        p = _resolve_repo_rel_path(
            repo_root,
            rel_posix,
            must_exist=True,
            must_be_file=True,
            allow_backslashes=False,
            forbid_symlinks=True,
        )
    except ValueError as e:
        raise RuntimeError(str(e)) from e

    b = p.read_bytes()
    crlf = b.count(b"\r\n")
    lone_cr = b.count(b"\r") - crlf

    safe, reason = _classify_safe_to_fix(rel_posix, b)
    return crlf, lone_cr, safe, reason


def scan_byte_guard(
    repo_root: Path,
    *,
    tracked_only: bool,
    exclude_roots: List[str] | None = None,
    exclude_paths: List[str] | None = None,
    allow_empty: bool = False,
    mode: str = "check",
) -> dict[str, Any]:
    # Deterministic scan: stable git enumeration + byte-level drift detection.
    if exclude_roots is None:
        exclude_roots = list(DEFAULT_EXCLUDE_ROOTS)

    include_untracked = not tracked_only
    rel_paths = _iter_git_paths(repo_root, include_untracked=include_untracked)
    rel_paths = [p for p in rel_paths if not _is_under_excluded_roots(p, exclude_roots)]

    exclude_set: set[str] = set()
    if exclude_paths:
        for p in exclude_paths:
            exclude_set.add(_validate_repo_rel(p))
        rel_paths = [p for p in rel_paths if p not in exclude_set]

    checked = 0
    skipped = 0
    drift: List[DriftHit] = []
    unsafe_drift: List[DriftHit] = []

    for rel in rel_paths:
        crlf, lone_cr, safe, reason = _scan_one(repo_root, rel)

        # Skip unquestionably-binary files from being "checked".
        # Still detect drift (for reporting), but do not auto-fix.
        is_binary_class = (not safe) and reason.startswith("binary_extension")
        if is_binary_class:
            skipped += 1
            if crlf or lone_cr:
                unsafe_drift.append(DriftHit(path=rel, crlf_pairs=crlf, lone_cr=lone_cr, safe_to_fix=False, reason=reason))
            continue

        checked += 1
        if crlf or lone_cr:
            hit = DriftHit(path=rel, crlf_pairs=crlf, lone_cr=lone_cr, safe_to_fix=safe, reason=reason)
            drift.append(hit)
            if not safe:
                unsafe_drift.append(hit)

    drift.sort(key=lambda h: h.path)
    unsafe_drift.sort(key=lambda h: h.path)

    report: dict[str, Any] = {
        "tool": "normalize",
        "mode": str(mode),
        "surface": {
            "tracked_only": bool(tracked_only),
            "include_untracked": bool(include_untracked),
            "excluded_roots": [r.replace("\\", "/") for r in exclude_roots],
            "excluded_paths": sorted(exclude_set),
        },
        "counts": {
            "candidates": len(rel_paths),
            "checked": checked,
            "skipped": skipped,
            "drift_files": len(drift),
            "unsafe_drift_files": len(unsafe_drift),
        },
        "drift_files": [
            {
                "path": h.path,
                "crlf_pairs": h.crlf_pairs,
                "lone_cr": h.lone_cr,
                "safe_to_fix": h.safe_to_fix,
                "reason": h.reason,
            }
            for h in drift
        ],
        "unsafe_drift_files": [
            {
                "path": h.path,
                "crlf_pairs": h.crlf_pairs,
                "lone_cr": h.lone_cr,
                "safe_to_fix": h.safe_to_fix,
                "reason": h.reason,
            }
            for h in unsafe_drift
        ],
        "status": "PASS" if (checked > 0 or allow_empty) and not drift else "FAIL",
    }
    return report


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp.normalize")
    # Binary write: no newline translation.
    with tmp.open("wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(str(tmp), str(path))


def _rehash(repo_root: Path) -> None:
    # Subordinate repair tool. Fail-closed on any non-zero exit.
    py = sys.executable
    rehash_py = (repo_root / "tools" / "rehash.py").resolve()
    if not rehash_py.exists():
        raise RuntimeError("Missing tools/rehash.py (required for --fix)")

    # Rehash every tracked EvidenceManifest.json deterministically.
    # Avoid pathspec globs for portability; filter the tracked surface.
    manifests = [
        p
        for p in _iter_git_paths(repo_root, include_untracked=False)
        if p.endswith("/EvidenceManifest.json") or p == "EvidenceManifest.json"
    ]

    for rel in manifests:
        subprocess.check_call(
            # rehash.py routes subcommand args through argparse.REMAINDER; use '--' sentinel.
            [py, str(rehash_py), "evidence-manifest", "--", "--manifest", rel],
            cwd=str(repo_root),
        )

    # Rehash required report ObjectRefs for public Gate R fixture set.
    cases = "policy/fixtures/public/gate_r/cases.json"
    cases_path = (repo_root / cases).resolve()
    if cases_path.exists():
        subprocess.check_call(
            [py, str(rehash_py), "required-reports", "--", "--cases", cases],
            cwd=str(repo_root),
        )


def _write_report(path: Path, obj: object) -> None:
    # Mekanik Namus: explicit newline enforcement for text-mode writes.
    with path.open("w", encoding="utf-8", errors="strict", newline="\n") as f:
        f.write(json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=True) + "\n")


def _parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Project Byte Guard (CRLF normalization)")
    ap.add_argument("--repo", default=".", help="Repo root")

    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Detect drift (default)")
    mode.add_argument("--fix", action="store_true", help="Normalize CRLF->LF (atomic), then rehash")

    ap.add_argument(
        "--tracked-only",
        action="store_true",
        help="Scan only git-tracked files (CI-safe deterministic surface)",
    )
    ap.add_argument(
        "--exclude",
        default=",".join(DEFAULT_EXCLUDE_ROOTS),
        help="Comma-separated top-level roots to exclude (default: .git,.venv,__pycache__,archive)",
    )
    ap.add_argument(
        "--allow-empty",
        action="store_true",
        help="Allow empty scan surface (default: fail closed)",
    )
    ap.add_argument(
        "--report-out",
        default="",
        help="Optional repo-relative JSON report path",
    )
    ap.add_argument(
        "--no-rehash",
        action="store_true",
        help="In --fix mode, do not run subordinate tools/rehash.py (default: run)",
    )
    ap.add_argument(
        "--rehash-always",
        action="store_true",
        help="In --fix mode, run subordinate rehash even if no files were changed by normalization",
    )
    return ap.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    ns = _parse_args(argv)
    repo_root = Path(ns.repo).resolve()

    exclude_roots = [p.strip() for p in str(ns.exclude).split(",") if p.strip()]

    if not ns.check and not ns.fix:
        ns.check = True

    report = scan_byte_guard(
        repo_root,
        tracked_only=bool(ns.tracked_only),
        exclude_roots=exclude_roots,
        allow_empty=bool(ns.allow_empty),
        mode="fix" if ns.fix else "check",
    )

    if ns.report_out:
        out_rel = _validate_repo_rel(str(ns.report_out))
        out_path = (repo_root / out_rel).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        _write_report(out_path, report)

    checked = int((report.get("counts") or {}).get("checked") or 0)
    skipped = int((report.get("counts") or {}).get("skipped") or 0)
    drift = report.get("drift_files") if isinstance(report.get("drift_files"), list) else []
    unsafe_drift_files = int((report.get("counts") or {}).get("unsafe_drift_files") or 0)

    if checked == 0 and not ns.allow_empty:
        print("NO-GO: empty scan surface (checked_files==0)")
        return 4

    if ns.check:
        if drift:
            print(f"NO-GO: CRLF drift detected in {len(drift)}/{checked} file(s)")
            for h in drift[:50]:
                if not isinstance(h, dict):
                    continue
                print(
                    f"- {h.get('path')} (crlf_pairs={h.get('crlf_pairs')}, lone_cr={h.get('lone_cr')}, safe_to_fix={h.get('safe_to_fix')})"
                )
            if len(drift) > 50:
                print("...")
            return 2
        print(f"PASS: no CRLF drift (checked {checked} files; skipped {skipped})")
        return 0

    # --fix mode
    if unsafe_drift_files:
        print(f"NO-GO: unsafe drift in {unsafe_drift_files} file(s); refusing to auto-fix")
        unsafe = report.get("unsafe_drift_files") if isinstance(report.get("unsafe_drift_files"), list) else []
        unsafe_paths = [
            str(h.get("path"))
            for h in unsafe
            if isinstance(h, dict) and isinstance(h.get("path"), str)
        ]
        unsafe_paths = sorted(set(unsafe_paths))
        for p in unsafe_paths[:50]:
            print(f"- {p}")
        if len(unsafe_paths) > 50:
            print("...")
        return 3

    changed = 0
    for h in drift:
        if not isinstance(h, dict):
            continue
        rel_path = str(h.get("path") or "")
        if not rel_path:
            continue
        p = (repo_root / rel_path).resolve()
        b = p.read_bytes()
        b2 = b.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        if b2 != b:
            _atomic_write_bytes(p, b2)
            changed += 1

    print(f"Fixed drift files: {changed}/{len(drift)}")

    if (changed or ns.rehash_always) and not ns.no_rehash:
        _rehash(repo_root)

    # Self-audit: re-scan after fix and subordinate rehash to detect reinjection.
    post = main(["--repo", str(repo_root), "--check"] + (["--tracked-only"] if ns.tracked_only else []))
    if post != 0:
        print("NO-GO: post-fix self-audit failed (possible CRLF reinjection)")
        return 5

    print("PASS: normalization complete; post-fix self-audit clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
