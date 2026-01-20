from __future__ import annotations

from types import ModuleType

from . import (
    q_intent_001,
    q_intent_002,
    q_intent_003,
    q1_lockedspec_schema,
    q_prompt_001,
    q_evidence_001,
    q_evidence_002,
    q2_intent_completeness,
    q3_invariants_compiled,
    q4_constraints_present,
    q_constraint_001_prefixes,
    q5_environment_envelope,
    q6_waivers_validity,
    q7_tier_supported,
    q_hotl_001,
    q_doc_001,
    q_doc_002,
)


def get_checks() -> list[ModuleType]:
    return [
        q_intent_001,
        q_intent_002,
        q_intent_003,
        q1_lockedspec_schema,
        q_prompt_001,
        q_evidence_001,
        q_evidence_002,
        q2_intent_completeness,
        q3_invariants_compiled,
        q4_constraints_present,
        q_constraint_001_prefixes,
        q5_environment_envelope,
        q6_waivers_validity,
        q7_tier_supported,
        q_hotl_001,
        q_doc_001,
        q_doc_002,
    ]
