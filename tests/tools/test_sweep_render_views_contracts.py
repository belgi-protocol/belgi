from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers.consistency_owner_fixtures import (
    assert_invariant_fails,
    assert_invariants_pass,
    build_repo_fixture,
    replace_text,
)
from tools._sweep.invariants import render_views as owner
from tools.render import get_all_target_names, get_target_evidence_files

pytestmark = pytest.mark.repo_local

def _render_views_owner_relpaths() -> tuple[str, ...]:
    """Owner-derived render evidence files plus the tool entrypoint itself."""

    relpaths = {"tools/render.py"}
    for target_name in get_all_target_names():
        relpaths.update(get_target_evidence_files(target_name))
    return tuple(sorted(relpaths))


def build_render_views_repo(tmp_path: Path) -> Path:
    return build_repo_fixture(tmp_path, "render_views", patterns=_render_views_owner_relpaths())


def test_render_views_owner_invariant_passes_on_owner_derived_repo(tmp_path: Path) -> None:
    root = build_render_views_repo(tmp_path)
    assert_invariants_pass(root, [("CS-RENDER-001", owner.check_cs_render_001)])


def test_render_views_owner_invariant_fails_on_generated_view_drift(tmp_path: Path) -> None:
    root = build_render_views_repo(tmp_path)
    replace_text(root, "tiers/tier-packs.md", "## 1. Tier IDs", "## 1. Tier Drift")
    assert_invariant_fails(root, "CS-RENDER-001", owner.check_cs_render_001, "tiers/tier-packs.md")
