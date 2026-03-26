from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.repo_local

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_ROOT = REPO_ROOT / "tests"
FORBIDDEN_CHAIN_LOGIC_BASE_IMPORTS = {
    "SchemaError",
    "validate_schema",
    "parse_rfc3339",
    "sha256_bytes",
    "safe_relpath",
    "resolve_storage_ref",
    "normalize_repo_rel",
    "normalize_repo_rel_path",
    "resolve_repo_rel_path",
    "is_under_prefix",
}
HELPER_ALLOWLIST = {"tests/helpers/repo_imports.py"}
SKIP_PATH_PARTS = {
    ".git",
    ".pytest_cache",
    ".venv",
    ".venv_packtest",
    "__pycache__",
    "belgi.egg-info",
    "build",
    "dist",
    "housekeeping",
    "site-packages",
    "venv",
}


def _iter_repo_py_files() -> list[Path]:
    files: list[Path] = []
    for path in sorted(REPO_ROOT.rglob("*.py")):
        rel = path.relative_to(REPO_ROOT).as_posix()
        if any(part in SKIP_PATH_PARTS for part in path.parts):
            continue
        if rel.startswith("belgi/_protocol_packs/"):
            continue
        files.append(path)
    return files


def _iter_test_py_files() -> list[Path]:
    files: list[Path] = []
    for path in sorted(TESTS_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        files.append(path)
    return files


def _is_sys_modules_attr(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "modules"
        and isinstance(node.value, ast.Name)
        and node.value.id == "sys"
    )


def _is_sys_modules_subscript(node: ast.AST) -> bool:
    return isinstance(node, ast.Subscript) and _is_sys_modules_attr(node.value)


def _is_sys_modules_pop_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "pop"
        and _is_sys_modules_attr(node.func.value)
    )


def test_chain_logic_base_import_boundary_guard_has_single_ast_owner() -> None:
    owners: list[str] = []
    for path in _iter_test_py_files():
        rel = path.relative_to(REPO_ROOT).as_posix()
        text = path.read_text(encoding="utf-8", errors="strict")
        if 'node.module == "chain.logic.base"' in text or "node.module == 'chain.logic.base'" in text:
            owners.append(rel)

    assert owners == ["tests/meta/test_import_hygiene.py"]


def test_no_forbidden_canonical_imports_from_chain_logic_base() -> None:
    offenders: list[str] = []

    for path in _iter_repo_py_files():
        rel = path.relative_to(REPO_ROOT).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="strict"), filename=rel)
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "chain.logic.base":
                for alias in node.names:
                    if alias.name in FORBIDDEN_CHAIN_LOGIC_BASE_IMPORTS:
                        offenders.append(
                            f"{rel}:{getattr(node, 'lineno', '?')} imports {alias.name} from chain.logic.base"
                        )

    assert offenders == [], "\n".join(offenders)


def test_sys_modules_surgery_is_helper_owned() -> None:
    offenders: list[str] = []

    for path in _iter_test_py_files():
        rel = path.relative_to(REPO_ROOT).as_posix()
        if rel in HELPER_ALLOWLIST:
            continue

        tree = ast.parse(path.read_text(encoding="utf-8", errors="strict"), filename=rel)
        for node in ast.walk(tree):
            if isinstance(node, ast.Delete):
                for target in node.targets:
                    if _is_sys_modules_subscript(target):
                        offenders.append(f"{rel}:{getattr(node, 'lineno', '?')} uses direct del sys.modules[...]")
            elif _is_sys_modules_pop_call(node):
                offenders.append(f"{rel}:{getattr(node, 'lineno', '?')} uses sys.modules.pop(...)")

    assert offenders == [], "\n".join(offenders)
