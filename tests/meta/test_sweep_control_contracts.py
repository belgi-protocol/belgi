"""Regression tests for sweep helper and control-plane contracts.

Direct invariant-family semantics live in tests/tools after the family split.
This file stays on helper return shape and control-plane guard coverage only.
"""

from __future__ import annotations

import re
import runpy
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.repo_local


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def test_helper_contract() -> None:
    common_ns = runpy.run_path(str(REPO_ROOT / "tools" / "_shared" / "common.py"))
    missing_needles = common_ns["_missing_needles"]

    result = missing_needles("abc", ["a", "b", "c"])
    assert isinstance(result, list)
    assert result == []

    result2 = missing_needles("abc", ["a", "z"])
    assert isinstance(result2, list)
    assert result2 == ["z"]


def test_abuse_no_boolean_negation_of_missing_needles() -> None:
    txt = (REPO_ROOT / "tools" / "_shared" / "common.py").read_text(encoding="utf-8", errors="strict")

    assert "if not _missing_needles(" not in txt
    assert re.search(r"\bif\s+_missing_needles\(", txt) is None


def test_abuse_no_boolean_truthiness_of_seal_payload_list_helpers() -> None:
    txt = (REPO_ROOT / "tools" / "sweep.py").read_text(encoding="utf-8", errors="strict")

    helpers = ["_seal_payload_paths_in_fixture_dir"]

    for name in helpers:
        assert f"if not {name}(" not in txt
        assert re.search(rf"\bif\s+{re.escape(name)}\(", txt) is None


def test_sweep_shell_source_does_not_define_legacy_internal_alias_shims() -> None:
    txt = (REPO_ROOT / "tools" / "sweep.py").read_text(encoding="utf-8", errors="strict")

    forbidden_defs = [
        "def _canonical_inputs(",
        "def _sweep_managed_surface_files(",
        "def _invariant_registry(",
    ]
    forbidden_imports = [
        "from tools._sweep.model import InvariantResult",
    ]

    for needle in [*forbidden_defs, *forbidden_imports]:
        assert needle not in txt
