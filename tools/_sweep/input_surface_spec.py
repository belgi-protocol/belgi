from __future__ import annotations

"""Declarative owner for fixed explicit sweep input families."""

FIXED_PROTOCOL_SINGLETONS: tuple[str, ...] = (
    "VERSION",
    ".github/CODEOWNERS",
    "schemas/README.md",
    "belgi/_protocol_packs/v1/schemas/README.md",
)

GATE_AND_FAILURE_SURFACES: tuple[str, ...] = (
    "gates/GATE_Q.md",
    "gates/GATE_R.md",
    "gates/GATE_S.md",
    "gates/failure-taxonomy.md",
)

TIER_SURFACES: tuple[str, ...] = (
    "tiers/tier-packs.md",
    "tiers/tier-packs.json",
    "tiers/tier-packs.template.md",
)

WRAPPER_ENTRYPOINT_SURFACES: tuple[str, ...] = (
    "wrapper/gate_Q.py",
    "wrapper/gate_R.py",
    "wrapper/comp_C1.py",
    "wrapper/comp_C3.py",
    "wrapper/seal_S.py",
)

RUN_SPINE_SURFACES: tuple[str, ...] = (
    "belgi/cli_app/parser/run.py",
    "belgi/cli_app/commands/run.py",
    "chain/gate_q_verify.py",
    "chain/gate_r_verify.py",
    "chain/gate_s_verify.py",
    "chain/compiler_c1_intent.py",
    "chain/seal_bundle.py",
    "chain/compiler_c3_docs.py",
    "chain/logic/locked_object_schema.py",
    "chain/logic/q_checks/q_intent_003.py",
    "chain/logic/q_checks/q4_constraints_present.py",
    "chain/logic/q_checks/q5_environment_envelope.py",
    "chain/logic/toolchain_set.py",
    "chain/logic/tolerances.py",
    "chain/logic/r_checks/r2_scope_budgets.py",
)

TEMPLATE_SURFACES: tuple[str, ...] = (
    "belgi/templates/IntentSpec.core.template.md",
    "belgi/templates/PromptBundle.blocks.md",
    "belgi/templates/DocsCompiler.template.md",
)

TRUST_ANCHOR_SURFACES: tuple[str, ...] = (
    "belgi/anchor/v1/TrustAnchor.json",
    "belgi/genesis/GenesisSealPayload.json",
    "belgi/genesis/README.md",
    "belgi/trust_anchor.py",
)

# Keep repo-local research explicit while this family is intentionally tiny.
# If that surface grows, decide whether it should stay explicit or move to its
# own declarative owner rather than letting it drift by accident.
REPO_LOCAL_RESEARCH_INPUTS: tuple[str, ...] = (
    "docs/research/README.md",
    "docs/research/experiment-design.md",
    "docs/research/metrics.md",
)

TOOLING_SURFACES: tuple[str, ...] = (
    "tools/README.md",
    "tools/render.py",
    "tools/normalize.py",
    "tools/rehash.py",
    "tools/canonicals_report.py",
    "tools/check_codeowners.py",
    "tools/report.py",
    "tools/wheel_boundary.py",
)

R_CHECK_WIRING_SURFACES: tuple[str, ...] = (
    "chain/logic/r_checks/context.py",
    "chain/logic/r_checks/registry.py",
    "chain/logic/r_checks/r0_evidence_sufficiency.py",
    "chain/logic/r_checks/r_doc_001_doc_impact.py",
    "chain/logic/r_checks/r4_schema_contract.py",
)

# The control-plane owner family includes the spec files themselves so sweep can
# prove the declared owner chain without leaving those owner bytes ungoverned.
TOOL_CONTROL_PLANE_OWNER_FILES: tuple[str, ...] = (
    "tools/_sweep/input_surface_spec.py",
    "tools/_sweep/managed_surface_spec.py",
    "tools/_sweep/inputs.py",
    "tools/_sweep/managed_surfaces.py",
    "tools/_sweep/registry.py",
    "tools/sweep.py",
)

DECLARED_FIXED_INPUT_FAMILIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("FIXED_PROTOCOL_SINGLETONS", FIXED_PROTOCOL_SINGLETONS),
    ("GATE_AND_FAILURE_SURFACES", GATE_AND_FAILURE_SURFACES),
    ("TIER_SURFACES", TIER_SURFACES),
    ("WRAPPER_ENTRYPOINT_SURFACES", WRAPPER_ENTRYPOINT_SURFACES),
    ("RUN_SPINE_SURFACES", RUN_SPINE_SURFACES),
    ("TEMPLATE_SURFACES", TEMPLATE_SURFACES),
    ("TRUST_ANCHOR_SURFACES", TRUST_ANCHOR_SURFACES),
    ("REPO_LOCAL_RESEARCH_INPUTS", REPO_LOCAL_RESEARCH_INPUTS),
    ("TOOLING_SURFACES", TOOLING_SURFACES),
    ("R_CHECK_WIRING_SURFACES", R_CHECK_WIRING_SURFACES),
    ("TOOL_CONTROL_PLANE_OWNER_FILES", TOOL_CONTROL_PLANE_OWNER_FILES),
)
