from __future__ import annotations

"""Generic repo-fixture primitives for tools-lane owner contract tests.

This module does not own any family inventory; each test module passes the
explicit patterns it wants to materialize.
"""

import json
import re
import shutil
from pathlib import Path
from typing import Any, Callable

from tests.helpers import builders, markdown_sections

REPO_ROOT = Path(__file__).resolve().parents[2]


def _expand_pattern(pattern: str) -> list[str]:
    if any(ch in pattern for ch in "*?[]"):
        return sorted(
            path.relative_to(REPO_ROOT).as_posix()
            for path in REPO_ROOT.glob(pattern)
            if path.is_file()
        )

    path = REPO_ROOT / pattern
    if path.is_dir():
        return sorted(
            child.relative_to(REPO_ROOT).as_posix()
            for child in path.rglob("*")
            if child.is_file()
        )

    if not path.is_file():
        raise FileNotFoundError(pattern)
    return [pattern]


def resolve_repo_patterns(patterns: tuple[str, ...], *, extra_patterns: tuple[str, ...] = ()) -> list[str]:
    selected_patterns = tuple(patterns) + tuple(extra_patterns)
    relpaths: set[str] = set()
    for pattern in selected_patterns:
        relpaths.update(_expand_pattern(pattern))
    return sorted(relpaths)


def copy_repo_relpaths(root: Path, relpaths: list[str]) -> None:
    for rel in relpaths:
        src = REPO_ROOT / rel
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def build_repo_fixture(
    tmp_path: Path,
    name: str,
    *,
    patterns: tuple[str, ...],
    extra_patterns: tuple[str, ...] = (),
    init_git: bool = True,
) -> Path:
    # Tests must pass their own explicit patterns; this helper only materializes them.
    root = tmp_path / name
    root.mkdir(parents=True, exist_ok=True)
    copy_repo_relpaths(root, resolve_repo_patterns(patterns, extra_patterns=extra_patterns))
    if init_git:
        builders.init_git_repo(root)
    return root


def replace_text(root: Path, rel: str, old: str, new: str) -> None:
    path = root / rel
    text = path.read_text(encoding="utf-8", errors="strict")
    assert old in text, f"expected to find {old!r} in {rel}"
    path.write_text(text.replace(old, new, 1), encoding="utf-8", errors="strict", newline="\n")


def replace_text_in_markdown_section(root: Path, rel: str, heading: str, old: str, new: str) -> None:
    path = root / rel
    text = path.read_text(encoding="utf-8", errors="strict")
    section = markdown_sections.markdown_heading_section(text, heading)
    assert old in section, f"expected to find {old!r} in {rel} section {heading!r}"
    path.write_text(
        text.replace(section, section.replace(old, new, 1), 1),
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )


def replace_text_in_markdown_slice(
    root: Path,
    rel: str,
    *,
    start_marker: str,
    end_marker: str,
    old: str,
    new: str,
) -> None:
    path = root / rel
    text = path.read_text(encoding="utf-8", errors="strict")
    section = markdown_sections.markdown_marker_slice(text, start_marker=start_marker, end_marker=end_marker)
    assert old in section, f"expected to find {old!r} in {rel} slice {start_marker!r}"
    path.write_text(
        text.replace(section, section.replace(old, new, 1), 1),
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )


def replace_regex(root: Path, rel: str, pattern: str, repl: str, *, count: int = 1) -> None:
    path = root / rel
    text = path.read_text(encoding="utf-8", errors="strict")
    new_text, replaced = re.subn(pattern, repl, text, count=count, flags=re.MULTILINE)
    assert replaced == count, f"expected {count} regex replacement(s) in {rel}: {pattern!r}"
    path.write_text(new_text, encoding="utf-8", errors="strict", newline="\n")


def append_text(root: Path, rel: str, text: str) -> None:
    path = root / rel
    current = path.read_text(encoding="utf-8", errors="strict")
    path.write_text(current + text, encoding="utf-8", errors="strict", newline="\n")


def mutate_json(root: Path, rel: str, mutator: Callable[[dict[str, Any]], None]) -> None:
    path = root / rel
    payload = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    assert isinstance(payload, dict), f"expected JSON object in {rel}"
    mutator(payload)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )


def remove_file(root: Path, rel: str) -> None:
    path = root / rel
    assert path.exists(), f"expected file to remove: {rel}"
    path.unlink()


def assert_invariants_pass(
    root: Path,
    cases: list[tuple[str, Callable[[Path], object]]],
) -> None:
    for invariant_id, check in cases:
        result = check(root)
        assert result.invariant_id == invariant_id
        assert result.status == "PASS", f"{invariant_id}: {result.remediation}"


def assert_invariant_fails(
    root: Path,
    invariant_id: str,
    check: Callable[[Path], object],
    expected_fragment: str,
) -> None:
    result = check(root)
    assert result.invariant_id == invariant_id
    assert result.status == "FAIL"
    evidence = "\n".join(result.evidence)
    remediation = result.remediation
    combined = f"{evidence}\n{remediation}"
    assert expected_fragment in combined, combined
