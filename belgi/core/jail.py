from __future__ import annotations

from pathlib import Path


def normalize_repo_rel(rel: str, *, allow_backslashes: bool) -> str:
    """Normalize a repo-relative path to POSIX separators and reject escapes.
    """

    if not isinstance(rel, str) or not rel:
        raise ValueError("path missing/empty")
    if "\x00" in rel:
        raise ValueError("path contains NUL")

    s = str(rel)
    if "\\" in s:
        if not allow_backslashes:
            raise ValueError("path must use '/' separators")
        s = s.replace("\\", "/")

    if "//" in s:
        raise ValueError("path must not contain '//' segments")
    if s.startswith("./"):
        raise ValueError("path must not start with './'")

    if s.startswith("/"):
        raise ValueError("absolute paths are not allowed")
    if len(s) >= 2 and s[1] == ":":
        raise ValueError("drive-qualified paths are not allowed")
    if ":" in s:
        raise ValueError("path must not contain ':'")

    parts = [p for p in s.split("/") if p]
    if not parts:
        raise ValueError("empty path not allowed")
    if any(p in (".", "..") for p in parts):
        raise ValueError("path must not contain '.' or '..' segments")
    return "/".join(parts)


def normalize_repo_rel_path(s: str) -> str:
    """CANONICAL Gate R repo-rel path normalization (R3 v1).

    This is a stricter policy than normalize_repo_rel():
    - Disallows backslashes and wildcards
    - Disallows scheme/colon, '//' and leading './'
    - Disallows '.' and '..' segments

    Returns the input string unchanged when valid.
    """

    if not isinstance(s, str) or not s:
        raise ValueError("empty")
    if s.startswith("/"):
        raise ValueError("starts with /")
    if "\\" in s:
        raise ValueError("contains backslash")
    if "*" in s or "?" in s:
        raise ValueError("contains wildcard")
    if "://" in s or ":" in s:
        raise ValueError("contains scheme/colon")
    if "//" in s:
        raise ValueError("contains //")
    if s.startswith("./"):
        raise ValueError("starts with ./")
    segments = s.split("/")
    for seg in segments:
        if seg in (".", ".."):
            raise ValueError("contains . or .. segment")
    return s


def is_under_prefix(path: str, prefix: str) -> bool:
    p = normalize_repo_rel_path(path)
    x = normalize_repo_rel_path(prefix)
    if x.endswith("/"):
        return p.startswith(x)
    return p == x or p.startswith(x + "/")


def safe_relpath(repo_root: Path, p: Path) -> str:
    try:
        return p.resolve().relative_to(repo_root.resolve()).as_posix()
    except Exception:
        return p.as_posix()


def ensure_within_root(root: Path, target: Path) -> None:
    root_resolved = root.resolve()
    target_resolved = target.resolve()
    if root_resolved not in target_resolved.parents and root_resolved != target_resolved:
        raise ValueError("Resolved path escapes repo root")


def resolve_storage_ref(repo_root: Path, storage_ref: str) -> Path:
    if not isinstance(storage_ref, str) or not storage_ref:
        raise ValueError("storage_ref missing/empty")

    # Deterministic hardening. Schema already constrains, but we re-check.
    if storage_ref.startswith("/"):
        raise ValueError("storage_ref must be repo-relative")
    if storage_ref.startswith("./"):
        raise ValueError("storage_ref must not start with ./")
    if "\\" in storage_ref:
        raise ValueError("storage_ref must not contain backslashes")
    if ".." in storage_ref:
        raise ValueError("storage_ref must not contain '..'")
    if "://" in storage_ref or ":" in storage_ref:
        raise ValueError("storage_ref must not contain scheme or drive colon")
    if "//" in storage_ref:
        raise ValueError("storage_ref must not contain '//' segments")

    # Treat storage_ref as POSIX-style relative path.
    p = Path(*storage_ref.split("/"))
    resolved = repo_root / p

    # Authenticate the filesystem boundary: keep all authoritative paths within repo_root.
    ensure_within_root(repo_root, resolved)

    # Fail-closed on symlinks for security-relevant scopes.
    cur = repo_root
    for part in p.parts:
        cur = cur / part
        if cur.exists() and cur.is_symlink():
            raise ValueError("storage_ref must not traverse symlinks")

    return resolved


def _is_symlink_or_has_symlink_parent(p: Path, *, stop_at: Path | None) -> bool:
    try:
        if p.is_symlink():
            return True
    except OSError:
        return True

    stop = stop_at.resolve() if stop_at is not None else None
    for parent in p.parents:
        try:
            if parent.is_symlink():
                return True
        except OSError:
            return True
        if stop is not None and parent.resolve() == stop:
            break
    return False


def resolve_repo_rel_path(
    repo_root: Path,
    rel: str,
    *,
    must_exist: bool,
    must_be_file: bool | None = None,
    allow_backslashes: bool,
    forbid_symlinks: bool = True,
) -> Path:
    """Resolve a repo-relative path within repo_root.
    """

    rel_posix = normalize_repo_rel(rel, allow_backslashes=allow_backslashes)
    candidate = repo_root / rel_posix

    # Authenticate the filesystem boundary: keep all authoritative paths within repo_root.
    if forbid_symlinks and _is_symlink_or_has_symlink_parent(candidate, stop_at=repo_root):
        raise ValueError(f"symlink not allowed in scope: {rel_posix}")

    resolved = candidate.resolve()
    try:
        resolved.relative_to(repo_root.resolve())
    except Exception as e:
        raise ValueError(f"scope escape: {rel_posix}") from e

    if must_exist:
        if not resolved.exists():
            raise ValueError(f"missing path in scope: {rel_posix}")
        if must_be_file is True and resolved.is_dir():
            raise ValueError(f"expected file but found directory: {rel_posix}")
        if must_be_file is False and not resolved.is_dir():
            raise ValueError(f"expected directory but found file: {rel_posix}")

    return resolved
