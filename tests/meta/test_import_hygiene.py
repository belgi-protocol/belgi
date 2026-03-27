from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.repo_local

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_ROOT = REPO_ROOT / "tests"
FORBIDDEN_BOUNDARY_MODULE = "chain.logic.base"
OWNER_BOUNDARY_GUARD = "tests/meta/test_import_hygiene.py:_collect_chain_logic_base_boundary_hits"
FORBIDDEN_CHAIN_LOGIC_BASE_IMPORTS = frozenset(
    {
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
)
HELPER_ALLOWLIST = {"tests/helpers/repo_imports.py"}
FRESH_BELGI_CLI_SURFACE_TARGET = "tests.helpers.repo_imports.import_fresh_belgi_cli_surface"
SYSPATH_MUTATION_ALLOWLIST = {
    "tests/conftest.py",
    "tests/helpers/repo_imports.py",
    "tests/helpers/subprocess_cli.py",
    "tests/meta/test_sweep_semantics.py",
    "tests/tools/test_github_vars_sanitize_contracts.py",
}
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


def _module_string_constants(tree: ast.AST) -> dict[str, str]:
    bindings: dict[str, str] = {}
    if not isinstance(tree, ast.Module):
        return bindings
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            bindings[node.targets[0].id] = node.value.value
    return bindings


def _module_import_bindings(tree: ast.AST) -> dict[str, str]:
    bindings: dict[str, str] = {}
    if not isinstance(tree, ast.Module):
        return bindings
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                bindings[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            for alias in node.names:
                local_name = alias.asname or alias.name
                bindings[local_name] = f"{node.module}.{alias.name}"
    return bindings


def _expr_resolves_to_boundary_module(node: ast.AST, *, string_bindings: dict[str, str]) -> bool:
    return (
        (
            isinstance(node, ast.Constant)
            and node.value == FORBIDDEN_BOUNDARY_MODULE
        )
        or (
            isinstance(node, ast.Name)
            and string_bindings.get(node.id) == FORBIDDEN_BOUNDARY_MODULE
        )
    )


def _is_importfrom_module_attr(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "module"
        and isinstance(node.value, ast.Name)
    )


def _is_ast_walk_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "ast"
        and node.func.attr == "walk"
    )


def _is_importfrom_isinstance_check(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "isinstance"
        and len(node.args) >= 2
        and isinstance(node.args[1], ast.Attribute)
        and isinstance(node.args[1].value, ast.Name)
        and node.args[1].value.id == "ast"
        and node.args[1].attr == "ImportFrom"
    )


def _function_scans_for_forbidden_chain_logic_base_boundary(
    node: ast.AST,
    *,
    string_bindings: dict[str, str],
) -> bool:
    saw_ast_walk = False
    saw_importfrom_isinstance = False
    saw_boundary_module_match = False

    for child in ast.walk(node):
        if _is_ast_walk_call(child):
            saw_ast_walk = True
        elif _is_importfrom_isinstance_check(child):
            saw_importfrom_isinstance = True
        elif isinstance(child, ast.Compare) and len(child.ops) == 1 and isinstance(child.ops[0], ast.Eq):
            left = child.left
            comparators = child.comparators
            if len(comparators) == 1:
                right = comparators[0]
                if _is_importfrom_module_attr(left) and _expr_resolves_to_boundary_module(
                    right, string_bindings=string_bindings
                ):
                    saw_boundary_module_match = True
                elif _is_importfrom_module_attr(right) and _expr_resolves_to_boundary_module(
                    left, string_bindings=string_bindings
                ):
                    saw_boundary_module_match = True

    return saw_ast_walk and saw_importfrom_isinstance and saw_boundary_module_match


def _collect_chain_logic_base_boundary_guard_owners() -> list[str]:
    owners: list[str] = []
    for path in _iter_test_py_files():
        rel = path.relative_to(REPO_ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8", errors="strict"), filename=rel)
        string_bindings = _module_string_constants(tree)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _function_scans_for_forbidden_chain_logic_base_boundary(
                node,
                string_bindings=string_bindings,
            ):
                owners.append(f"{rel}:{node.name}")
    return sorted(owners)


def _collect_chain_logic_base_boundary_hits(tree: ast.AST, *, rel: str) -> list[str]:
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == FORBIDDEN_BOUNDARY_MODULE:
            for alias in node.names:
                if alias.name in FORBIDDEN_CHAIN_LOGIC_BASE_IMPORTS:
                    offenders.append(
                        f"{rel}:{getattr(node, 'lineno', '?')} imports {alias.name} from {FORBIDDEN_BOUNDARY_MODULE}"
                    )
    return offenders


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


def _call_target_name(node: ast.Call, *, import_bindings: dict[str, str]) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return import_bindings.get(func.id, func.id)
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        base = import_bindings.get(func.value.id, func.value.id)
        return f"{base}.{func.attr}"
    return None


def _is_sys_path_attr(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "path"
        and isinstance(node.value, ast.Name)
        and node.value.id == "sys"
    )


def _is_sys_path_mutation_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"insert", "append"}
        and _is_sys_path_attr(node.func.value)
    )


def _collect_top_level_fresh_belgi_cli_surface_inits(*, tree: ast.AST, rel: str) -> list[str]:
    offenders: list[str] = []
    if not isinstance(tree, ast.Module):
        return offenders

    import_bindings = _module_import_bindings(tree)
    for node in tree.body:
        value: ast.AST | None = None
        if isinstance(node, ast.Assign):
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            value = node.value
        elif isinstance(node, ast.Expr):
            value = node.value
        if not isinstance(value, ast.Call):
            continue
        target_name = _call_target_name(value, import_bindings=import_bindings)
        if target_name == FRESH_BELGI_CLI_SURFACE_TARGET:
            offenders.append(
                f"{rel}:{getattr(node, 'lineno', '?')} caches a fresh BELGI CLI surface at module import time"
            )
    return offenders


def test_chain_logic_base_import_boundary_guard_has_single_ast_owner() -> None:
    assert _collect_chain_logic_base_boundary_guard_owners() == [OWNER_BOUNDARY_GUARD]


def test_no_forbidden_canonical_imports_from_chain_logic_base() -> None:
    offenders: list[str] = []

    for path in _iter_repo_py_files():
        rel = path.relative_to(REPO_ROOT).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="strict"), filename=rel)
        except SyntaxError:
            continue

        offenders.extend(_collect_chain_logic_base_boundary_hits(tree, rel=rel))

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


def test_fresh_belgi_cli_surface_is_not_cached_at_module_import_time() -> None:
    offenders: list[str] = []

    for path in _iter_test_py_files():
        rel = path.relative_to(REPO_ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8", errors="strict"), filename=rel)
        offenders.extend(_collect_top_level_fresh_belgi_cli_surface_inits(tree=tree, rel=rel))

    assert offenders == [], "\n".join(offenders)


def test_sys_path_surgery_is_allowlisted_only() -> None:
    offenders: list[str] = []

    for path in _iter_test_py_files():
        rel = path.relative_to(REPO_ROOT).as_posix()
        if rel in SYSPATH_MUTATION_ALLOWLIST:
            continue

        tree = ast.parse(path.read_text(encoding="utf-8", errors="strict"), filename=rel)
        for node in ast.walk(tree):
            if _is_sys_path_mutation_call(node):
                offenders.append(
                    f"{rel}:{getattr(node, 'lineno', '?')} uses ad hoc sys.path.{node.func.attr}(...) outside the allowlist"
                )

    assert offenders == [], "\n".join(offenders)
