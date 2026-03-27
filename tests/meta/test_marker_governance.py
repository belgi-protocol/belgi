from __future__ import annotations

import ast
import configparser
from pathlib import Path

import pytest

pytestmark = pytest.mark.repo_local

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_ROOT = REPO_ROOT / "tests"
REGISTERED_CUSTOM_MARKERS = {"repo_local", "serial"}
BUILTIN_PYTEST_MARKERS = {
    "filterwarnings",
    "parametrize",
    "skip",
    "skipif",
    "usefixtures",
    "xfail",
}
BANNED_TOPIC_MARKERS = {
    "cli",
    "docs",
    "gates",
    "important",
    "integration",
    "slow",
}


def _registered_marker_names() -> set[str]:
    parser = configparser.ConfigParser()
    parser.read(REPO_ROOT / "pytest.ini", encoding="utf-8")
    raw = parser.get("pytest", "markers")
    names: set[str] = set()
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        names.add(stripped.split(":", 1)[0].strip())
    return names


def _marker_name_from_expr(node: ast.AST) -> str | None:
    target = node
    if isinstance(target, ast.Call):
        target = target.func
    if not (
        isinstance(target, ast.Attribute)
        and isinstance(target.value, ast.Attribute)
        and isinstance(target.value.value, ast.Name)
        and target.value.value.id == "pytest"
        and target.value.attr == "mark"
    ):
        return None
    return target.attr


def _collect_used_marker_names() -> set[str]:
    names: set[str] = set()
    for path in sorted(TESTS_ROOT.rglob("test_*.py")):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8", errors="strict"), filename=path.as_posix())
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                for decorator in node.decorator_list:
                    name = _marker_name_from_expr(decorator)
                    if name is not None:
                        names.add(name)
            elif isinstance(node, ast.Assign):
                if any(isinstance(target, ast.Name) and target.id == "pytestmark" for target in node.targets):
                    values = node.value.elts if isinstance(node.value, ast.List) else [node.value]
                    for value in values:
                        name = _marker_name_from_expr(value)
                        if name is not None:
                            names.add(name)
    return names


def test_custom_marker_vocabulary_is_registered_and_bounded() -> None:
    registered = _registered_marker_names()
    assert registered == REGISTERED_CUSTOM_MARKERS
    assert registered.isdisjoint(BANNED_TOPIC_MARKERS)


def test_suite_uses_only_builtins_and_registered_custom_markers() -> None:
    used = _collect_used_marker_names()
    unknown = used - BUILTIN_PYTEST_MARKERS - REGISTERED_CUSTOM_MARKERS
    assert unknown == set(), f"unknown or unregistered pytest markers: {sorted(unknown)}"


def test_topic_markers_are_not_used() -> None:
    used = _collect_used_marker_names()
    assert used.isdisjoint(BANNED_TOPIC_MARKERS)
