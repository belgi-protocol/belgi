from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.repo_local
REPO_ROOT = Path(__file__).resolve().parents[2]


def _inputs_section_lines() -> list[str]:
    text = (REPO_ROOT / "docs" / "operations" / "consistency-sweep.md").read_text(
        encoding="utf-8",
        errors="strict",
    )
    start = text.index("### Inputs (authoritative, read-only)")
    end = text.index("### Output of the sweep")
    return text[start:end].splitlines()


def _inputs_section_bullets() -> dict[str, list[str]]:
    bullets: dict[str, list[str]] = {}
    current_heading = ""
    for line in _inputs_section_lines():
        if line.startswith("#### "):
            current_heading = line.removeprefix("#### ")
            bullets[current_heading] = []
            continue
        if line.startswith("- "):
            bullets.setdefault(current_heading, []).append(line)
    return bullets


def test_inputs_section_keeps_family_pointer_owner_blocks() -> None:
    bullets = _inputs_section_bullets()

    assert bullets["Fixed explicit owner families"] == [
        "- `tools/_sweep/input_surface_spec.py::FIXED_PROTOCOL_SINGLETONS`",
        "- `tools/_sweep/input_surface_spec.py::GATE_AND_FAILURE_SURFACES`",
        "- `tools/_sweep/input_surface_spec.py::TIER_SURFACES`",
        "- `tools/_sweep/input_surface_spec.py::WRAPPER_ENTRYPOINT_SURFACES`",
        "- `tools/_sweep/input_surface_spec.py::RUN_SPINE_SURFACES`",
        "- `tools/_sweep/input_surface_spec.py::TEMPLATE_SURFACES`",
        "- `tools/_sweep/input_surface_spec.py::TRUST_ANCHOR_SURFACES`",
        "- `tools/_sweep/input_surface_spec.py::REPO_LOCAL_RESEARCH_INPUTS`",
        "- `tools/_sweep/input_surface_spec.py::TOOLING_SURFACES`",
        "- `tools/_sweep/input_surface_spec.py::R_CHECK_WIRING_SURFACES`",
        "- `tools/_sweep/input_surface_spec.py::TOOL_CONTROL_PLANE_OWNER_FILES`",
    ]
    assert bullets["Managed operational surface family"] == [
        "- `tools/_sweep/managed_surface_spec.py::MANAGED_SURFACE_INCLUDE_PATTERNS`",
        "- `tools/_sweep/managed_surface_spec.py::MANAGED_WORKFLOW_FILES`",
        "- `tools/_sweep/managed_surface_spec.py::MANAGED_SURFACE_EXCLUDE_PATTERNS`",
        "- `tools/_sweep/managed_surfaces.py::_sweep_managed_surface_files`",
    ]
    assert bullets["Derived dynamic families"] == [
        "- `tools/_sweep/inputs.py::_iter_schema_files`",
        "- `tools/_sweep/inputs.py::_iter_builtin_protocol_pack_files`",
    ]
    assert bullets["Exact checked-set authority"] == [
        "- `tools/_sweep/inputs.py::_canonical_inputs` composes the governed input set from the declared families above.",
        "- The exact concrete checked input ledger lives in generated `policy/consistency_sweep.json` `inputs[]`.",
        "- `CS-SWEEP-001` and `CS-SWEEP-002` MUST prove that exact artifact payload from the declared owners above.",
    ]


def test_inputs_section_does_not_reintroduce_raw_file_ledger_bullets() -> None:
    raw_ledger_bullets = [
        line
        for line in _inputs_section_lines()
        if re.fullmatch(r"- `[^`]+`", line) and "::" not in line
    ]

    assert raw_ledger_bullets == []
