from __future__ import annotations

from typing import Callable

from chain.logic.base import CheckResult

from .context import RCheckContext
from . import (
    r0_evidence_sufficiency,
    r1_intent_invariants,
    r2_scope_budgets,
    r3_policy_invariants,
    r_doc_001_doc_impact,
    r4_schema_contract,
    r5_tests_policy,
    r6_attestation,
    r7_supplychain_scan,
    r8_adversarial_scan,
)


CheckFn = Callable[[RCheckContext], list[CheckResult]]


def get_checks() -> list[CheckFn]:
    # Fixed order for deterministic output.
    return [
        # 1. Evidence sufficiency (Gate R §4)
        r0_evidence_sufficiency.run,

        # 2. Deterministic checks in Gate R spec order
        r1_intent_invariants.run,  # R1
        r2_scope_budgets.run,  # R2
        r3_policy_invariants.run,  # R3
        r_doc_001_doc_impact.run,  # R-DOC-001
        r4_schema_contract.run,  # R4
        r5_tests_policy.run,  # R5
        r6_attestation.run,  # R6
        r7_supplychain_scan.run,  # R7
        r8_adversarial_scan.run,  # R8
    ]
