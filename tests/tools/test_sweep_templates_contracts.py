from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers.consistency_owner_fixtures import (
    assert_invariant_fails,
    assert_invariants_pass,
    build_repo_fixture,
    mutate_json,
    replace_text,
    replace_text_in_markdown_section,
)
from tools._sweep.invariants import templates as owner

pytestmark = pytest.mark.repo_local

def _templates_read_relpaths() -> tuple[str, ...]:
    """Exact union of files read by CS-TPL-001..005."""

    return (
        "CANONICALS.md",
        "schemas/EvidenceManifest.schema.json",
        "schemas/LockedSpec.schema.json",
        "gates/GATE_R.md",
        "tiers/tier-packs.md",
        "belgi/templates/PromptBundle.blocks.md",
        "belgi/templates/DocsCompiler.template.md",
    )


def build_templates_repo(tmp_path: Path) -> Path:
    return build_repo_fixture(tmp_path, "templates", patterns=_templates_read_relpaths())


def test_templates_owner_invariants_pass_on_owner_derived_repo(tmp_path: Path) -> None:
    root = build_templates_repo(tmp_path)
    assert_invariants_pass(
        root,
        [
            ("CS-TPL-001", owner.check_cs_tpl_001),
            ("CS-TPL-002", owner.check_cs_tpl_002),
            ("CS-TPL-003", owner.check_cs_tpl_003),
            ("CS-TPL-004", owner.check_cs_tpl_004),
            ("CS-TPL-005", owner.check_cs_tpl_005),
        ],
    )


@pytest.mark.parametrize(
    ("invariant_id", "mutate", "check", "expected_fragment"),
    [
        (
            "CS-TPL-001",
            lambda root: replace_text_in_markdown_section(
                root,
                "belgi/templates/PromptBundle.blocks.md",
                "### A5.1 Required evidence artifact (policy_report)",
                "block_hashes",
                "block_digests",
            ),
            owner.check_cs_tpl_001,
            "belgi/templates/PromptBundle.blocks.md#a51-required-evidence-artifact-policy_report",
        ),
        (
            "CS-TPL-002",
            lambda root: mutate_json(
                root,
                "schemas/LockedSpec.schema.json",
                lambda payload: payload["required"].remove("prompt_bundle_ref"),
            ),
            owner.check_cs_tpl_002,
            "schemas/LockedSpec.schema.json#/required",
        ),
        (
            "CS-TPL-003",
            lambda root: replace_text_in_markdown_section(
                root,
                "belgi/templates/DocsCompiler.template.md",
                "### B4.2 Required evidence artifact: docs_compilation_log",
                "docs_compilation_log",
                "docs_compilation_trace",
            ),
            owner.check_cs_tpl_003,
            "belgi/templates/DocsCompiler.template.md#b42-required-evidence-artifact-docs_compilation_log",
        ),
        (
            "CS-TPL-004",
            lambda root: replace_text(root, "gates/GATE_R.md", "MUST match **exactly one**", "MAY match one or many"),
            owner.check_cs_tpl_004,
            "gates/GATE_R.md#521-required-report-artifact-integrity--payload-validation-required",
        ),
        (
            "CS-TPL-005",
            lambda root: replace_text(root, "belgi/templates/DocsCompiler.template.md", "post-verification", "pre-verification"),
            owner.check_cs_tpl_005,
            "belgi/templates/DocsCompiler.template.md#b1-purpose",
        ),
    ],
)
def test_templates_owner_invariants_fail_closed_on_owner_derived_mutations(
    tmp_path: Path,
    invariant_id: str,
    mutate,
    check,
    expected_fragment: str,
) -> None:
    root = build_templates_repo(tmp_path)
    mutate(root)
    assert_invariant_fails(root, invariant_id, check, expected_fragment)
