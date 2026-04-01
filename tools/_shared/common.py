from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any, Iterable, List, Sequence

from belgi.core.jail import normalize_repo_rel as _normalize_repo_rel
from belgi.core.jail import resolve_repo_rel_path as _resolve_repo_rel_path

CANONICAL_SWEEP_OUT = "policy/consistency_sweep.json"

CANONICAL_SWEEP_SUMMARY = "policy/consistency_sweep.summary.md"

CONSISTENCY_SPEC_DOC = "docs/operations/consistency-sweep.md"

class _UserInputError(RuntimeError):
    pass

def _validate_repo_rel(rel: str) -> str:
    try:
        return _normalize_repo_rel(rel, allow_backslashes=True)
    except ValueError as e:
        raise _UserInputError(str(e)) from e

def _resolve_repo_path(
    repo_root: Path,
    rel: str,
    *,
    must_exist: bool,
    must_be_file: bool | None = None,
) -> Path:
    rel_posix = _validate_repo_rel(rel)
    try:
        return _resolve_repo_rel_path(
            repo_root,
            rel_posix,
            must_exist=must_exist,
            must_be_file=must_be_file,
            allow_backslashes=False,
            forbid_symlinks=True,
        )
    except ValueError as e:
        raise _UserInputError(str(e)) from e

def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="strict")

def find_fenced_blocks(md: str, fence_lang: str | None = None) -> List[str]:
    """Returns content of fenced code blocks.

    If fence_lang is provided, only returns blocks where opening fence is ```<lang>.
    """

    blocks: List[str] = []
    pattern = r"^```([a-zA-Z0-9_-]*)\s*$"
    lines = md.splitlines()
    i = 0
    in_block = False
    buf: List[str] | None = []
    while i < len(lines):
        m = re.match(pattern, lines[i])
        if not in_block and m:
            lang = (m.group(1) or "").strip()
            if fence_lang is None or lang.lower() == fence_lang.lower():
                in_block = True
                buf = []
            else:
                in_block = True
                buf = None
            i += 1
            continue

        if in_block and lines[i].strip() == "```":
            if buf is not None:
                blocks.append("\n".join(buf))
            in_block = False
            buf = []
            i += 1
            continue

        if in_block and buf is not None:
            buf.append(lines[i])

        i += 1
    return blocks

def markdown_heading_section(md: str, heading: str) -> str:
    lines = md.splitlines()
    wanted = str(heading or "").strip()
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped != wanted:
            continue
        lstripped = line.lstrip()
        level = len(lstripped) - len(lstripped.lstrip("#"))
        if level <= 0:
            raise _UserInputError(f"section heading is not markdown heading: {heading!r}")

        end = len(lines)
        for probe in range(index + 1, len(lines)):
            probe_line = lines[probe]
            probe_lstripped = probe_line.lstrip()
            probe_level = len(probe_lstripped) - len(probe_lstripped.lstrip("#"))
            if probe_level <= 0:
                continue
            if not probe_lstripped.startswith("#" * probe_level + " "):
                continue
            if probe_level <= level:
                end = probe
                break
        return "\n".join(lines[index:end])
    raise _UserInputError(f"missing markdown heading: {heading!r}")

def markdown_marker_slice(md: str, *, start_marker: str, end_marker: str | None = None) -> str:
    start = md.find(start_marker)
    if start < 0:
        raise _UserInputError(f"missing start marker: {start_marker!r}")
    end = len(md)
    if end_marker is not None:
        next_start = md.find(end_marker, start + len(start_marker))
        if next_start < 0:
            raise _UserInputError(f"missing end marker: {end_marker!r}")
        end = next_start
    return md[start:end]

def load_json(path: Path) -> Any:
    return json.loads(read_text(path))

def json_pointer(doc: Any, pointer: str) -> Any:
    """Resolve an in-document RFC6901 JSON Pointer (only '#/a/b' form)."""

    if not pointer.startswith("#/"):
        raise ValueError("Only in-document JSON Pointers are supported")
    cur: Any = doc
    for part in pointer[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, list):
            cur = cur[int(part)]
        else:
            cur = cur[part]
    return cur

def repo_path(root: Path, rel: str) -> Path:
    # Backwards-compat shim for internal callers.
    return _resolve_repo_path(root, rel, must_exist=False)

def _run_git(
    repo_root: Path,
    args: Sequence[str],
    *,
    env: dict[str, str] | None = None,
    input_bytes: bytes | None = None,
) -> str:
    cmd = ["git", *args]
    if input_bytes is None:
        cp = subprocess.run(cmd, cwd=str(repo_root), env=env, capture_output=True, text=True)
        if cp.returncode != 0:
            raise _UserInputError(f"git {' '.join(args)} failed: {cp.stderr.strip()}")
        return cp.stdout

    cp = subprocess.run(cmd, cwd=str(repo_root), env=env, input=input_bytes, capture_output=True)
    if cp.returncode != 0:
        stderr = cp.stderr.decode("utf-8", errors="strict") if cp.stderr else ""
        raise _UserInputError(f"git {' '.join(args)} failed: {stderr.strip()}")
    return cp.stdout.decode("utf-8", errors="strict")

def _git_tree_sha(repo_root: Path) -> str:
    try:
        out = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=str(repo_root))
    except Exception as e:
        raise _UserInputError("git rev-parse HEAD^{tree} failed") from e
    s = out.decode("utf-8", errors="strict").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", s):
        raise _UserInputError(f"unexpected git tree sha: {s!r}")
    return s

def _git_tree_sha_excluding(
    repo_root: Path,
    exclude_paths: Sequence[str],
    *,
    blob_overrides: dict[str, bytes] | None = None,
) -> str:
    @contextlib.contextmanager
    def _temp_git_index_dir() -> Iterable[Path]:
        # Windows + Python 3.13: os.mkdir(path, 0o700) can produce an unreadable directory,
        # and tempfile.TemporaryDirectory() uses 0o700. Avoid mode=0o700 on Windows.
        if os.name != "nt":
            with tempfile.TemporaryDirectory() as td:
                yield Path(td)
            return

        base = repo_root / "temp" / "_git_index_tmp"
        base.mkdir(parents=True, exist_ok=True)
        for _ in range(100):
            td = base / f"tmp{uuid.uuid4().hex}"
            try:
                os.mkdir(td)
            except FileExistsError:
                continue
            try:
                yield td
            finally:
                shutil.rmtree(td, ignore_errors=True)
            return
        raise _UserInputError("failed to create temporary directory for git index")

    exclude_set = {_validate_repo_rel(p) for p in (exclude_paths or [])}
    override_bytes = {_validate_repo_rel(k): v for k, v in (blob_overrides or {}).items()}

    if not exclude_set and not override_bytes:
        return _git_tree_sha(repo_root)

    for rel in override_bytes.keys():
        if rel in exclude_set:
            raise _UserInputError(f"override path is excluded: {rel}")

    with _temp_git_index_dir() as td:
        index_path = str(td / "index")
        env = dict(os.environ)
        env["GIT_INDEX_FILE"] = index_path

        # IMPORTANT:
        # We intentionally write objects into the repo's object database here.
        # Callers/tests may run plain `git ls-tree <sha>` without our env, so the tree must exist in repo objects.
        _run_git(repo_root, ["read-tree", "HEAD"], env=env)

        for rel in sorted(exclude_set):
            ls = _run_git(repo_root, ["ls-files", "--stage", "--", rel], env=env).strip()
            if not ls:
                continue
            _run_git(repo_root, ["update-index", "--remove", "--force-remove", "--", rel], env=env)

        for rel, data in sorted(override_bytes.items()):
            ls = _run_git(repo_root, ["ls-files", "--stage", "--", rel], env=env).strip()
            if not ls:
                raise _UserInputError(f"override path not found in HEAD: {rel}")
            mode = ls.split(" ", 1)[0]
            if mode not in ("100644", "100755"):
                raise _UserInputError(f"override path is not a regular file blob: {rel}")

            # Write override blob into repo objects (required so the resulting tree is resolvable by plain git commands).
            oid = _run_git(repo_root, ["hash-object", "-w", "--stdin"], env=env, input_bytes=data).strip()
            if not re.fullmatch(r"[0-9a-f]{40}", oid):
                raise _UserInputError(f"unexpected git blob sha: {oid!r}")

            _run_git(
                repo_root,
                ["update-index", "--add", "--cacheinfo", mode, oid, rel],
                env=env,
            )

        s = _run_git(repo_root, ["write-tree"], env=env).strip()
        if not re.fullmatch(r"[0-9a-f]{40}", s):
            raise _UserInputError(f"unexpected git tree sha: {s!r}")
        return s

def _missing_needles(haystack: str, needles: Sequence[str]) -> list[str]:
    """Return needles missing from haystack.

    Contract: returns a list[str] (empty means "all present"); this is NOT a boolean.
    """

    return [n for n in needles if n not in haystack]
