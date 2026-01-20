from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


# Bunlar chain.logic.base'ten import edilmeyecek (SSOT belgi.core.*)
FORBIDDEN_NAMES = {
    # schema / timestamps
    "SchemaError",
    "validate_schema",
    "parse_rfc3339",
    # paths / jail-ish helpers
    "resolve_repo_rel_path",
    "normalize_repo_rel",
    "safe_relpath",
    # hash
    "sha256_bytes",
}

# no false-positives
SKIP_PATH_PARTS = {
    ".venv",
    ".venv_packtest",
    "venv",
    "__pycache__",
    ".pytest_cache",
    "build",
    "dist",
    ".git",
    "site-packages",
}

@dataclass(frozen=True)
class Hit:
    path: str
    lineno: int
    name: str


def iter_py_files(repo_root: Path) -> Iterable[Path]:
    for p in repo_root.rglob("*.py"):
        s = p.as_posix()
        if any(part in p.parts for part in SKIP_PATH_PARTS):
            continue
        # protocol pack data-only; ama yine de taramak istersen kaldır
        if "belgi/_protocol_packs" in s:
            continue
        yield p


def find_forbidden_imports(repo_root: Path) -> list[Hit]:
    hits: list[Hit] = []
    for p in iter_py_files(repo_root):
        if p.name in {"test_no_chain_base_canon_imports.py", "test_no_chain_base_cannon_imports.py"}:
            continue

        try:
            src = p.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(src, filename=str(p))
        except Exception:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "chain.logic.base":
                for alias in node.names:
                    if alias.name in FORBIDDEN_NAMES:
                        hits.append(Hit(path=p.as_posix(), lineno=getattr(node, "lineno", 0), name=alias.name))

    hits.sort(key=lambda h: (h.path, h.lineno, h.name))
    return hits


def test_no_forbidden_canon_imports_from_chain_base():
    repo_root = Path(__file__).resolve().parents[1]
    hits = find_forbidden_imports(repo_root)
    if hits:
        msg = "\n".join([f"{h.path}:{h.lineno} imports forbidden name from chain.logic.base -> {h.name}" for h in hits])
        raise AssertionError("Forbidden imports detected (SSOT must be belgi.core.*):\n" + msg)
