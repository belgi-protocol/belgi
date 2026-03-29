from __future__ import annotations

from dataclasses import replace

from tests.helpers.repo_imports import reset_repo_local_imports
from tests.helpers.tier_fixtures import tier_policy

reset_repo_local_imports("belgi", "chain")

import chain.compiler_c1_intent as c1


def _tier_policy(tier_id: str):
    return tier_policy(tier_id)


def test_prompt_bundle_selection_matches_current_tier1_policy() -> None:
    selected = c1._prompt_block_ids_for_tier_policy(_tier_policy("tier-1"))

    assert "PB-009" in selected
    assert "PB-010" in selected
    assert "PB-011" in selected


def test_prompt_bundle_selection_is_driven_by_individual_policy_fields() -> None:
    tier0 = _tier_policy("tier-0")
    base = c1._prompt_block_ids_for_tier_policy(tier0)
    assert "PB-009" not in base
    assert "PB-010" not in base
    assert "PB-011" not in base

    structured_only = c1._prompt_block_ids_for_tier_policy(replace(tier0, command_log_mode="structured"))
    assert "PB-009" in structured_only
    assert "PB-010" not in structured_only
    assert "PB-011" not in structured_only

    tests_required_only = c1._prompt_block_ids_for_tier_policy(replace(tier0, test_policy_required="yes"))
    assert "PB-009" not in tests_required_only
    assert "PB-010" in tests_required_only
    assert "PB-011" not in tests_required_only

    attestation_only = c1._prompt_block_ids_for_tier_policy(
        replace(tier0, envelope_policy_requires_attestation="yes")
    )
    assert "PB-009" not in attestation_only
    assert "PB-010" not in attestation_only
    assert "PB-011" in attestation_only
