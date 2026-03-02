from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

ERGONOMIC_FILES = [
    REPO_ROOT / "scripts" / "belgi_latest_run.ps1",
    REPO_ROOT / "scripts" / "belgi_latest_run.sh",
    REPO_ROOT / "scripts" / "belgi_latest_run.py",
    REPO_ROOT / "scripts" / "belgi_wip_commit_run_reset.ps1",
    REPO_ROOT / "docs" / "operations" / "cli.md",
]


def test_helpers_are_adopter_agnostic() -> None:
    blocklist = [
        "portfoly",
        "overlay-capsule",
        "/users/batu/documents/github/portfoly",
    ]
    offenders: list[str] = []

    for path in ERGONOMIC_FILES:
        text = path.read_text(encoding="utf-8", errors="strict").lower()
        for token in blocklist:
            if token in text:
                offenders.append(f"{path.relative_to(REPO_ROOT).as_posix()}: {token}")

    assert offenders == [], "adopter identifiers leaked into canonical ergonomics surfaces:\n" + "\n".join(offenders)


def test_wip_helper_has_required_safety_guardrails() -> None:
    helper = REPO_ROOT / "scripts" / "belgi_wip_commit_run_reset.ps1"
    text = helper.read_text(encoding="utf-8", errors="strict")

    checks: list[tuple[str, str]] = [
        ("merge detection", r"MERGE_HEAD"),
        ("rebase detection", r"rebase-merge"),
        ("rebase apply detection", r"rebase-apply"),
        ("staged preflight abort", r"git diff --cached --quiet --exit-code"),
        ("tracked-only staging", r"git add -u"),
        ("try/finally restore", r"\btry\s*\{[\s\S]*\bfinally\s*\{"),
        ("head restoration check", r"\$headAfterRestore\s*-ne\s*\$originalHead"),
    ]

    missing = [name for (name, pattern) in checks if re.search(pattern, text, flags=re.IGNORECASE) is None]
    assert missing == [], "missing WIP safety guardrails:\n" + "\n".join(missing)


@pytest.mark.parametrize("path", ERGONOMIC_FILES)
def test_ergonomic_files_exist(path: Path) -> None:
    assert path.is_file(), f"expected file missing: {path.relative_to(REPO_ROOT).as_posix()}"
