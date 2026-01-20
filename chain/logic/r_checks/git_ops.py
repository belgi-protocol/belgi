from __future__ import annotations

import os
import subprocess
from pathlib import Path

from belgi.core.jail import safe_relpath


def is_fixture_context(repo_root: Path, locked_spec_path: Path, evidence_manifest_path: Path) -> bool:
    """Return True iff this Gate R invocation appears to be running on tracked fixtures.

    We only allow the diff-bytes fallback for fixture runs to avoid accidentally
    weakening scope enforcement for real repo evaluations.
    """

    try:
        locked_rel = safe_relpath(repo_root, locked_spec_path)
        evidence_rel = safe_relpath(repo_root, evidence_manifest_path)
    except Exception:
        return False

    return locked_rel.startswith("policy/fixtures/") and evidence_rel.startswith("policy/fixtures/")


def parse_unified_diff_paths(diff_bytes: bytes) -> list[str]:
    """Parse a unified diff into a stable list of changed repo-relative paths.

    Deterministic + fixture-friendly:
    - Prefers `diff --git a/... b/...` headers when present.
    - Falls back to `+++ b/...` when needed.
    - Ignores /dev/null entries.
    """

    try:
        text = diff_bytes.decode("utf-8", errors="replace")
    except Exception:
        return []

    def clean(p: str) -> str | None:
        p = (p or "").strip()
        if not p:
            return None
        if p.startswith("a/") or p.startswith("b/"):
            p = p[2:]
        if p == "/dev/null":
            return None
        return p

    paths: set[str] = set()
    for line in text.splitlines():
        if line.startswith("diff --git "):
            parts = line.split()
            # diff --git a/<old> b/<new>
            if len(parts) >= 4:
                p = clean(parts[3])
                if p:
                    paths.add(p)
        elif line.startswith("+++ "):
            p = clean(line[4:])
            if p:
                paths.add(p)

    return sorted(paths)


def parse_unified_diff_loc_delta(diff_bytes: bytes) -> tuple[int, int]:
    """Return (added, removed) counted from unified diff bytes.

    Deterministic and fixture-friendly:
    - Counts lines starting with '+' excluding '+++' headers.
    - Counts lines starting with '-' excluding '---' headers.
    """

    try:
        text = diff_bytes.decode("utf-8", errors="replace")
    except Exception:
        return 0, 0

    added = 0
    removed = 0
    for line in text.splitlines():
        if not line:
            continue
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            added += 1
        elif line.startswith("-"):
            removed += 1

    return added, removed


def _git_env() -> dict[str, str]:
    env = dict(os.environ)
    # Deterministic parsing: avoid localized output.
    env.setdefault("LANG", "C")
    env.setdefault("LC_ALL", "C")
    return env


def _run_git(repo_root: Path, args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args],
        cwd=str(repo_root),
        env=_git_env(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def git_resolve_commit(repo_root: Path, rev: str) -> str:
    if not isinstance(rev, str) or not rev.strip():
        raise ValueError("revision missing/empty")
    # Resolve to a concrete commit id.
    cp = _run_git(repo_root, ["rev-parse", "--verify", f"{rev.strip()}^{{commit}}"])
    if cp.returncode != 0:
        raise ValueError(f"git rev-parse failed for revision: {rev.strip()}")
    sha = cp.stdout.decode("utf-8", errors="strict").strip()
    if not sha or len(sha) < 7:
        raise ValueError("resolved commit sha missing/invalid")
    return sha


def git_changed_paths(repo_root: Path, base_commit: str, evaluated_commit: str) -> list[str]:
    # Use NUL-delimited output to avoid platform quoting differences.
    cp = _run_git(
        repo_root,
        [
            "-c",
            "core.quotePath=false",
            "diff",
            "--name-only",
            "--no-renames",
            "-z",
            f"{base_commit}..{evaluated_commit}",
        ],
    )
    if cp.returncode != 0:
        raise ValueError("git diff --name-only failed")
    raw = cp.stdout
    parts = [p for p in raw.split(b"\x00") if p]
    paths = [p.decode("utf-8", errors="surrogateescape") for p in parts]
    # Deterministic ordering.
    return sorted(paths)


def git_loc_delta(repo_root: Path, base_commit: str, evaluated_commit: str) -> tuple[int, int]:
    cp = _run_git(
        repo_root,
        [
            "-c",
            "core.quotePath=false",
            "diff",
            "--numstat",
            "--no-renames",
            f"{base_commit}..{evaluated_commit}",
        ],
    )
    if cp.returncode != 0:
        raise ValueError("git diff --numstat failed")

    added = 0
    removed = 0
    text = cp.stdout.decode("utf-8", errors="strict")
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            raise ValueError("unexpected numstat line")
        a, d = parts[0], parts[1]
        # Binary files produce '-' which we fail-closed on for deterministic LOC delta.
        if a == "-" or d == "-":
            raise ValueError("binary diff entry in numstat")
        try:
            a_i = int(a)
            d_i = int(d)
        except Exception:
            raise ValueError("non-integer numstat counts")
        if a_i < 0 or d_i < 0:
            raise ValueError("negative numstat counts")
        added += a_i
        removed += d_i

    return added, removed
