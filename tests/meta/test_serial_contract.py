from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.repo_local

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_ROOT = REPO_ROOT / "tests"
SERIAL_ROOT = TESTS_ROOT / "serial"
SERIAL_MARK_PATTERNS = (
    re.compile(r"@pytest\.mark\.serial\b"),
    re.compile(r"pytestmark\s*=\s*pytest\.mark\.serial\b"),
    re.compile(r"pytestmark\s*=\s*\[[^\]]*pytest\.mark\.serial\b", re.DOTALL),
)


def _has_serial_marker(text: str) -> bool:
    return any(pattern.search(text) for pattern in SERIAL_MARK_PATTERNS)


def test_pytest_registers_serial_marker() -> None:
    text = (REPO_ROOT / "pytest.ini").read_text(encoding="utf-8", errors="strict")
    assert re.search(r"(?m)^\s*serial:\s+", text) is not None


def test_serial_lane_budget_is_zero_until_an_explicit_exception_is_admitted() -> None:
    readme = (SERIAL_ROOT / "README.md").read_text(encoding="utf-8", errors="strict")
    assert "Serial is an exception protocol, not a dumping ground." in readme
    assert "Current admitted serial test module budget: 0." in readme
    assert sorted(SERIAL_ROOT.glob("test_*.py")) == []


def test_serial_marks_are_forbidden_outside_serial_lane() -> None:
    offenders: list[str] = []
    for path in sorted(TESTS_ROOT.rglob("test_*.py")):
        if "__pycache__" in path.parts or "serial" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="strict")
        if _has_serial_marker(text):
            offenders.append(path.relative_to(REPO_ROOT).as_posix())

    assert offenders == [], "\n".join(offenders)


def test_serial_lane_requires_explicit_marker_on_every_test_module() -> None:
    offenders: list[str] = []
    for path in sorted(SERIAL_ROOT.glob("test_*.py")):
        text = path.read_text(encoding="utf-8", errors="strict")
        if not _has_serial_marker(text):
            offenders.append(path.relative_to(REPO_ROOT).as_posix())

    assert offenders == [], "\n".join(offenders)
