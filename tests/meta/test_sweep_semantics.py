"""Regression tests for sweep helper semantics.

Direct invariant-family semantics live in tests/tools after the family split.
This file stays on sweep helper and control-plane guard coverage only.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.repo_local


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def test_helper_contract() -> None:
    from tools.consistency import common as common_mod

    result = common_mod._missing_needles("abc", ["a", "b", "c"])
    assert isinstance(result, list)
    assert result == []

    result2 = common_mod._missing_needles("abc", ["a", "z"])
    assert isinstance(result2, list)
    assert result2 == ["z"]


def test_abuse_no_boolean_negation_of_missing_needles() -> None:
    txt = (REPO_ROOT / "tools" / "consistency" / "common.py").read_text(encoding="utf-8", errors="strict")

    assert "if not _missing_needles(" not in txt
    assert re.search(r"\bif\s+_missing_needles\(", txt) is None


def test_abuse_no_boolean_truthiness_of_seal_payload_list_helpers() -> None:
    txt = (REPO_ROOT / "tools" / "sweep.py").read_text(encoding="utf-8", errors="strict")

    helpers = ["_seal_payload_paths_in_fixture_dir"]

    for name in helpers:
        assert f"if not {name}(" not in txt
        assert re.search(rf"\bif\s+{re.escape(name)}\(", txt) is None
