from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers.consistency_owner_fixtures import (
    assert_invariant_fails,
    assert_invariants_pass,
    build_owner_family_repo,
    replace_text,
)
from tools._sweep.invariants import render_views as owner

pytestmark = pytest.mark.repo_local


def test_render_views_owner_invariant_passes_on_owner_derived_repo(tmp_path: Path) -> None:
    root = build_owner_family_repo(tmp_path, "render_views")
    assert_invariants_pass(root, [("CS-RENDER-001", owner.check_cs_render_001)])


def test_render_views_owner_invariant_fails_on_generated_view_drift(tmp_path: Path) -> None:
    root = build_owner_family_repo(tmp_path, "render_views")
    replace_text(root, "tiers/tier-packs.md", "## 1. Tier IDs", "## 1. Tier Drift")
    assert_invariant_fails(root, "CS-RENDER-001", owner.check_cs_render_001, "tiers/tier-packs.md")
