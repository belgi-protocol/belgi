from __future__ import annotations

import os
import subprocess
from pathlib import Path


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
        except ValueError as e:
            raise ValueError("non-integer numstat counts") from e
        if a_i < 0 or d_i < 0:
            raise ValueError("negative numstat counts")
        added += a_i
        removed += d_i

    return added, removed
