from __future__ import annotations

from pathlib import PurePosixPath

import pytest

from tools._shared import common as _common
from tools._sweep import input_surface_spec as spec
from tools._sweep.inputs import _iter_declared_fixed_input_files

pytestmark = pytest.mark.repo_local


def _flatten_declared_fixed_input_families() -> list[str]:
    return [
        rel
        for _family_name, members in spec.DECLARED_FIXED_INPUT_FAMILIES
        for rel in members
    ]


def test_declared_fixed_input_families_keep_expected_owner_order() -> None:
    assert [name for name, _members in spec.DECLARED_FIXED_INPUT_FAMILIES] == [
        "FIXED_PROTOCOL_SINGLETONS",
        "GATE_AND_FAILURE_SURFACES",
        "TIER_SURFACES",
        "WRAPPER_ENTRYPOINT_SURFACES",
        "RUN_SPINE_SURFACES",
        "TEMPLATE_SURFACES",
        "TRUST_ANCHOR_SURFACES",
        "REPO_LOCAL_RESEARCH_INPUTS",
        "TOOLING_SURFACES",
        "R_CHECK_WIRING_SURFACES",
        "TOOL_CONTROL_PLANE_OWNER_FILES",
    ]


def test_tool_control_plane_owner_family_keeps_spec_and_composer_seams() -> None:
    assert spec.TOOL_CONTROL_PLANE_OWNER_FILES == (
        "tools/_sweep/input_surface_spec.py",
        "tools/_sweep/managed_surface_spec.py",
        "tools/_sweep/inputs.py",
        "tools/_sweep/managed_surfaces.py",
        "tools/_sweep/registry.py",
        "tools/sweep.py",
    )


def test_repo_local_research_inputs_stay_fixed_explicit_family_members() -> None:
    assert spec.REPO_LOCAL_RESEARCH_INPUTS == (
        "docs/research/README.md",
        "docs/research/experiment-design.md",
        "docs/research/metrics.md",
    )


def test_declared_fixed_input_families_have_unique_repo_relative_normalized_members() -> None:
    flattened = _flatten_declared_fixed_input_families()

    assert len(flattened) == len(set(flattened))
    for rel in flattened:
        assert not PurePosixPath(rel).is_absolute()
        assert _common._validate_repo_rel(rel) == rel


def test_declared_fixed_input_file_iterator_matches_flattened_family_owner_set() -> None:
    flattened = _flatten_declared_fixed_input_families()

    assert set(_iter_declared_fixed_input_files()) == set(flattened)


def test_repo_local_research_inputs_match_current_tracked_research_surface() -> None:
    tracked_research = tuple(
        sorted(
            line.strip()
            for line in _common._run_git(
                _common.Path(__file__).resolve().parents[2],
                ["ls-files", "docs/research"],
            ).splitlines()
            if line.strip().endswith(".md")
        )
    )

    assert spec.REPO_LOCAL_RESEARCH_INPUTS == tracked_research, (
        "docs/research changed. Decide whether REPO_LOCAL_RESEARCH_INPUTS should stay "
        "explicit or move to its own declarative owner before widening this family."
    )
