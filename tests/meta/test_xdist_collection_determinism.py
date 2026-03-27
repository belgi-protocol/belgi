from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.repo_local

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_ROOT = REPO_ROOT / "tests"


def _is_pytest_mark_parametrize(node: ast.Call) -> bool:
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "parametrize"
        and isinstance(node.func.value, ast.Attribute)
        and node.func.value.attr == "mark"
        and isinstance(node.func.value.value, ast.Name)
        and node.func.value.value.id == "pytest"
    )


def _parametrize_argvalues_node(node: ast.Call) -> ast.AST | None:
    if len(node.args) >= 2:
        return node.args[1]
    for keyword in node.keywords:
        if keyword.arg == "argvalues":
            return keyword.value
    return None


def _is_unordered_parametrize_literal(node: ast.AST) -> bool:
    return isinstance(node, ast.Set) or (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "set"
    )


def test_parallel_safe_lanes_forbid_set_based_parametrize_argvalues() -> None:
    offenders: list[str] = []

    for path in sorted(TESTS_ROOT.rglob("test_*.py")):
        if "__pycache__" in path.parts or "serial" in path.parts:
            continue
        rel = path.relative_to(REPO_ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8", errors="strict"), filename=rel)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not _is_pytest_mark_parametrize(node):
                continue
            argvalues = _parametrize_argvalues_node(node)
            if argvalues is not None and _is_unordered_parametrize_literal(argvalues):
                offenders.append(
                    f"{rel}:{getattr(node, 'lineno', '?')} uses a set-based parametrize argvalues literal"
                )

    assert offenders == [], "\n".join(offenders)
