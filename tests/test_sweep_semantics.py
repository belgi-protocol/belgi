"""Regression tests for sweep helper semantics.

Goal: prevent list-returning helpers from being misread as booleans.

This specifically guards against the historic inversion bug where a check
used `if not <missing_list>:` and accidentally failed/passed the wrong way.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.repo_local


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def test_helper_contract() -> None:
    from tools import sweep as sweep_mod

    result = sweep_mod._missing_needles("abc", ["a", "b", "c"])
    assert isinstance(result, list)
    assert result == []

    result2 = sweep_mod._missing_needles("abc", ["a", "z"])
    assert isinstance(result2, list)
    assert result2 == ["z"]


def test_known_good_must_pass(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    (tmp_path / "gates").mkdir(parents=True, exist_ok=True)
    (tmp_path / "gates" / "GATE_Q.md").write_text(
        "\n".join(
            [
                "# Gate Q",
                "Q-INTENT-001",
                "Q-INTENT-002",
                "Q-INTENT-003",
                "IntentSpec.core.md",
                "belgi/templates/IntentSpec.core.template.md",
                "schemas/IntentSpec.schema.json",
                "schemas/LockedSpec.schema.json",
            ]
        ),
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    res = sweep_mod.check_cs_is_003(tmp_path)
    assert res.invariant_id == "CS-IS-003"
    assert res.status == "PASS"


def test_known_bad_must_fail(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    # Minimal synthetic repo root sufficient for CS-IS-003 (it only reads gates/GATE_Q.md).
    (tmp_path / "gates").mkdir(parents=True, exist_ok=True)
    (tmp_path / "gates" / "GATE_Q.md").write_text(
        "\n".join(
            [
                "# Gate Q",
                "Q-INTENT-001",
                "Q-INTENT-002",
                # Intentionally omit Q-INTENT-003 and other required strings.
                "IntentSpec.core.md",
            ]
        ),
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    res = sweep_mod.check_cs_is_003(tmp_path)
    assert res.invariant_id == "CS-IS-003"
    assert res.status == "FAIL"


def test_abuse_no_boolean_negation_of_missing_needles() -> None:
    txt = (REPO_ROOT / "tools" / "sweep.py").read_text(encoding="utf-8", errors="strict")

    # Guardrail: reintroducing the old inverted pattern should immediately trip CI.
    assert "if not _missing_needles(" not in txt

    # Also block the positive truthiness form; callers must name the variable explicitly.
    assert re.search(r"\bif\s+_missing_needles\(", txt) is None


def test_abuse_no_boolean_truthiness_of_seal_payload_list_helpers() -> None:
    txt = (REPO_ROOT / "tools" / "sweep.py").read_text(encoding="utf-8", errors="strict")

    helpers = [
        "_seal_payload_paths_in_fixture_dir",
    ]

    for name in helpers:
        assert f"if not {name}(" not in txt
        assert re.search(rf"\bif\s+{re.escape(name)}\(", txt) is None


def _init_tracked_temp_repo(root: Path, files: dict[str, str]) -> None:
    subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True, text=True)
    subprocess.run(["git", "config", "user.email", "sweep-tests@local"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Sweep Tests"], cwd=root, check=True)
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8", errors="strict", newline="\n")
    subprocess.run(["git", "add", "--all"], cwd=root, check=True)


def test_cs_term_001_fails_on_validation_posture_phrase(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    _init_tracked_temp_repo(
        tmp_path,
        {
            "README.md": "Two-phase validation posture\n",
            "CANONICALS.md": "Deterministic verification of probabilistic proposals.\n",
        },
    )

    res = sweep_mod.check_cs_term_001(tmp_path)
    assert res.invariant_id == "CS-TERM-001"
    assert res.status == "FAIL"
    assert "README.md:1" in res.remediation
    assert "validation posture" in res.remediation


def test_cs_term_001_allows_schema_validation_context(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    _init_tracked_temp_repo(
        tmp_path,
        {
            "README.md": "schema validation for EvidenceManifest.schema.json\n",
            "CANONICALS.md": "Deterministic verification of probabilistic proposals.\n",
        },
    )

    res = sweep_mod.check_cs_term_001(tmp_path)
    assert res.invariant_id == "CS-TERM-001"
    assert res.status == "PASS"
