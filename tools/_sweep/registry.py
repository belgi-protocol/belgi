from __future__ import annotations

from pathlib import Path
from typing import Callable

from tools._sweep.invariants.canonicals import (
    check_cs_can_001,
    check_cs_can_002,
    check_cs_can_003,
    check_cs_can_004,
    check_cs_can_005,
    check_cs_term_001,
)
from tools._sweep.invariants.evidence import (
    check_cs_ev_001,
    check_cs_ev_002,
    check_cs_ev_003,
    check_cs_ev_004,
    check_cs_ev_005,
)
from tools._sweep.invariants.gate_schema import (
    check_cs_gs_001,
    check_cs_gs_002,
    check_cs_gs_003,
    check_cs_gs_004,
    check_cs_gs_005,
    check_cs_gv_001,
    check_cs_ls_001,
    check_cs_ls_002,
)
from tools._sweep.invariants.intentspec import (
    check_cs_is_002,
    check_cs_is_003,
    check_cs_is_004,
    check_cs_is_005,
    check_intentspec_yaml_single_block,
)
from tools._sweep.invariants.orchestration import (
    check_cs_byte_001,
    check_cs_fixture_zero_001,
    check_cs_protocol_identity_001,
    check_cs_r0_enforcement_wired_001,
    check_cs_sweep_001,
    check_cs_sweep_002,
)
from tools._sweep.invariants.render_views import check_cs_render_001
from tools._sweep.invariants.run_contract import check_cs_run_001, check_cs_run_002
from tools._sweep.invariants.schema_catalog import check_cs_schema_001
from tools._sweep.invariants.templates import (
    check_cs_tpl_001,
    check_cs_tpl_002,
    check_cs_tpl_003,
    check_cs_tpl_004,
    check_cs_tpl_005,
)
from tools._sweep.invariants.tiers import (
    check_cs_tier_001,
    check_cs_tier_002,
    check_cs_tier_003,
    check_cs_tier_004,
    check_cs_tier_005,
)
from tools._sweep.invariants.verification_spine import (
    check_cs_gate_r_mandates_verify_bundle_001,
    check_cs_ref_001,
    check_cs_verify_bundle_001,
    check_cs_verify_bundle_gateverdict_binding_001,
)
from tools._sweep.invariants.waivers import (
    check_cs_wvr_001,
    check_cs_wvr_002,
    check_cs_wvr_003,
    check_cs_wvr_004,
    check_cs_wvr_005,
)
from tools._sweep.model import InvariantResult

ORDERED_INVARIANTS: tuple[tuple[str, Callable[[Path], InvariantResult]], ...] = (
    ('CS-CAN-001', check_cs_can_001),
    ('CS-CAN-004', check_cs_can_004),
    ('CS-CAN-002', check_cs_can_002),
    ('CS-CAN-003', check_cs_can_003),
    ('CS-CAN-005', check_cs_can_005),
    ('CS-TERM-001', check_cs_term_001),
    ('CS-GS-001', check_cs_gs_001),
    ('CS-GS-002', check_cs_gs_002),
    ('CS-GS-003', check_cs_gs_003),
    ('CS-GS-004', check_cs_gs_004),
    ('CS-GS-005', check_cs_gs_005),
    ('CS-IS-001', check_intentspec_yaml_single_block),
    ('CS-IS-002', check_cs_is_002),
    ('CS-IS-003', check_cs_is_003),
    ('CS-IS-004', check_cs_is_004),
    ('CS-IS-005', check_cs_is_005),
    ('CS-RUN-001', check_cs_run_001),
    ('CS-RUN-002', check_cs_run_002),
    ('CS-SCHEMA-001', check_cs_schema_001),
    ('CS-EV-001', check_cs_ev_001),
    ('CS-EV-002', check_cs_ev_002),
    ('CS-EV-003', check_cs_ev_003),
    ('CS-EV-004', check_cs_ev_004),
    ('CS-EV-005', check_cs_ev_005),
    ('CS-TIER-001', check_cs_tier_001),
    ('CS-TIER-002', check_cs_tier_002),
    ('CS-TIER-003', check_cs_tier_003),
    ('CS-TIER-004', check_cs_tier_004),
    ('CS-TIER-005', check_cs_tier_005),
    ('CS-WVR-001', check_cs_wvr_001),
    ('CS-WVR-002', check_cs_wvr_002),
    ('CS-WVR-003', check_cs_wvr_003),
    ('CS-WVR-004', check_cs_wvr_004),
    ('CS-WVR-005', check_cs_wvr_005),
    ('CS-TPL-001', check_cs_tpl_001),
    ('CS-TPL-002', check_cs_tpl_002),
    ('CS-TPL-003', check_cs_tpl_003),
    ('CS-TPL-004', check_cs_tpl_004),
    ('CS-TPL-005', check_cs_tpl_005),
    ('CS-VERIFY_BUNDLE-001', check_cs_verify_bundle_001),
    ('CS-GATE_R-MANDATES-VERIFY_BUNDLE-001', check_cs_gate_r_mandates_verify_bundle_001),
    ('CS-VERIFY_BUNDLE-GATEVERDICT-BINDING-001', check_cs_verify_bundle_gateverdict_binding_001),
    ('CS-BYTE-001', check_cs_byte_001),
    ('CS-FIXTURE-ZERO-001', check_cs_fixture_zero_001),
    ('CS-PROTOCOL-IDENTITY-001', check_cs_protocol_identity_001),
    ('CS-SWEEP-001', check_cs_sweep_001),
    ('CS-SWEEP-002', check_cs_sweep_002),
    ('CS-GV-001', check_cs_gv_001),
    ('CS-LS-001', check_cs_ls_001),
    ('CS-LS-002', check_cs_ls_002),
    ('CS-REF-001', check_cs_ref_001),
    ('CS-R0-ENFORCEMENT-WIRED-001', check_cs_r0_enforcement_wired_001),
    ('CS-RENDER-001', check_cs_render_001),
)

def invariant_registry() -> dict[str, Callable[[Path], InvariantResult]]:
    return dict(ORDERED_INVARIANTS)
