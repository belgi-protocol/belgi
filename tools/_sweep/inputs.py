from __future__ import annotations

from tools._shared import common as _common

_SWEEP_ENGINE_OWNER_FILES: tuple[str, ...] = (
    "tools/_sweep/model.py",
    "tools/_sweep/report_writer.py",
    "tools/_sweep/runner.py",
)

_SWEEP_CONTROL_PLANE_OWNER_FILES: tuple[str, ...] = (
    "tools/_sweep/inputs.py",
    "tools/_sweep/registry.py",
    "tools/sweep.py",
)

_SWEEP_INVARIANT_OWNER_FILES: tuple[str, ...] = (
    "tools/_sweep/invariants/canonicals.py",
    "tools/_sweep/invariants/evidence.py",
    "tools/_sweep/invariants/gate_schema.py",
    "tools/_sweep/invariants/intentspec.py",
    "tools/_sweep/invariants/orchestration.py",
    "tools/_sweep/invariants/render_views.py",
    "tools/_sweep/invariants/run_contract.py",
    "tools/_sweep/invariants/schema_catalog.py",
    "tools/_sweep/invariants/templates.py",
    "tools/_sweep/invariants/tiers.py",
    "tools/_sweep/invariants/verification_spine.py",
    "tools/_sweep/invariants/waivers.py",
)


def _governed_sweep_owner_files() -> tuple[str, ...]:
    return _SWEEP_ENGINE_OWNER_FILES + _SWEEP_CONTROL_PLANE_OWNER_FILES + _SWEEP_INVARIANT_OWNER_FILES


def _iter_schema_files(repo_root: _common.Path) -> list[str]:
    schemas_dir = _common._resolve_repo_path(repo_root, "schemas", must_exist=True, must_be_file=False)

    out: list[str] = []
    for p in sorted(schemas_dir.glob("*.schema.json"), key=lambda x: x.name):
        rel = p.resolve().relative_to(repo_root.resolve()).as_posix()
        out.append(rel)
    return out

def _iter_builtin_protocol_pack_files(repo_root: _common.Path) -> list[str]:
    """Deterministically enumerate builtin protocol pack files.

    These are part of the governed surface because the active builtin pack
    identity is authoritative and the manifest is validated against its tree.
    Fail-closed on symlinks.
    """

    pack_root = _common._resolve_repo_path(repo_root, "belgi/_protocol_packs/v1", must_exist=True, must_be_file=False)
    if not pack_root.is_dir():
        raise _common._UserInputError("builtin protocol pack root is not a directory: belgi/_protocol_packs/v1")

    out: list[str] = []
    for dirpath, dirnames, filenames in _common.os.walk(pack_root, followlinks=False):
        d = _common.Path(dirpath)
        if d.is_symlink():
            raise _common._UserInputError(f"symlink directory not allowed under belgi/_protocol_packs/v1: {d}")
        dirnames.sort()
        filenames.sort()
        for name in filenames:
            p = d / name
            if p.is_symlink():
                raise _common._UserInputError(f"symlink file not allowed under belgi/_protocol_packs/v1: {p}")
            rel = p.resolve().relative_to(repo_root.resolve()).as_posix()
            out.append(rel)

    out.sort()
    return out

def _canonical_inputs(repo_root: _common.Path) -> list[str]:
    # Core, explicitly governed files.
    base = [
        "CANONICALS.md",
        "README.md",
        "CHANGELOG.md",
        "WHITEPAPER.md",
        "TRADEMARK.md",
        "VERSION",
        "terminology.md",
        "trust-model.md",
        "gates/GATE_Q.md",
        "gates/GATE_R.md",
        "gates/GATE_S.md",
        "gates/failure-taxonomy.md",
        ".github/scripts/check_external_action_pins.py",
        ".github/scripts/resolve_belgi_workflow_inputs.py",
        ".github/scripts/run_belgi_smoke.py",
        ".github/scripts/validate_belgi_ref_pin.py",
        ".github/workflows/pinned-install-proof.yml",
        ".github/workflows/pull-request-proof.yml",
        ".github/workflows/repository-verification.yml",
        ".github/CODEOWNERS",
        "tiers/tier-packs.md",
        "tiers/tier-packs.json",
        "tiers/tier-packs.template.md",
        # Human-facing wrapper entrypoints
        "wrapper/gate_Q.py",
        "wrapper/gate_R.py",
        "wrapper/comp_C1.py",
        "wrapper/comp_C3.py",
        "wrapper/seal_S.py",
        # Canonical templates / runbooks
        "belgi/templates/IntentSpec.core.template.md",
        "belgi/templates/PromptBundle.blocks.md",
        "belgi/templates/DocsCompiler.template.md",
        "docs/operations/cli.md",
        "docs/operations/evidence-bundles.md",
        "docs/operations/evidence-ownership.md",
        "docs/operations/exit-codes.md",
        "docs/operations/operator-anchors.md",
        "docs/operations/running-belgi.md",
        "docs/operations/security.md",
        "docs/operations/consistency-sweep.md",
        "docs/operations/waivers.md",
        "docs/operations/workflows.md",
        "docs/research/README.md",
        "docs/research/experiment-design.md",
        "docs/research/metrics.md",
        "belgi/_protocol_packs/v1/schemas/README.md",
        # Package canonical mirror (must stay byte-identical to source docs)
        "belgi/canonicals/CANONICALS.md",
        "belgi/canonicals/terminology.md",
        "belgi/canonicals/trust-model.md",
        "belgi/canonicals/docs/operations/consistency-sweep.md",
        "belgi/canonicals/docs/operations/cli.md",
        "belgi/canonicals/docs/operations/evidence-bundles.md",
        "belgi/canonicals/docs/operations/evidence-ownership.md",
        "belgi/canonicals/docs/operations/operator-anchors.md",
        "belgi/canonicals/docs/operations/running-belgi.md",
        "belgi/canonicals/docs/operations/security.md",
        "belgi/canonicals/docs/operations/waivers.md",
        "belgi/canonicals/docs/research/README.md",
        "belgi/canonicals/docs/research/experiment-design.md",
        "belgi/canonicals/docs/research/metrics.md",
        # Tier-3 canonical authority surfaces
        "belgi/anchor/v1/TrustAnchor.json",
        "belgi/genesis/GenesisSealPayload.json",
        "belgi/genesis/README.md",
        "belgi/trust_anchor.py",
        # Operator convenience scripts (public ergonomics surface)
        "scripts/belgi_latest_run.ps1",
        "scripts/belgi_latest_run.py",
        "scripts/belgi_latest_run.sh",
        "scripts/belgi_wip_commit_run_reset.ps1",
        # CI template surface
        "templates/ci/github/belgi-tier1.yml",
        # Canonical deterministic verifier entrypoints
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
        "chain/logic/toolchain_set.py",
        "chain/logic/tolerances.py",
        "chain/logic/q_checks/q4_constraints_present.py",
        "chain/logic/q_checks/q5_environment_envelope.py",
        "chain/logic/r_checks/r2_scope_budgets.py",
        # Canonical tools
        "tools/README.md",
        "tools/render.py",
        "tools/normalize.py",
        "tools/rehash.py",
        "tools/canonicals_report.py",
        "tools/check_codeowners.py",
        "tools/report.py",
        "tools/wheel_boundary.py",
        # R-check wiring governance
        "chain/logic/r_checks/context.py",
        "chain/logic/r_checks/registry.py",
        "chain/logic/r_checks/r0_evidence_sufficiency.py",
        "chain/logic/r_checks/r_doc_001_doc_impact.py",
        "chain/logic/r_checks/r4_schema_contract.py",
        # Schema index doc
        "schemas/README.md",
    ]

    base.extend(_governed_sweep_owner_files())

    # Dynamic, authoritative schema surface.
    base.extend(_iter_schema_files(repo_root))

    # Dynamic, authoritative builtin protocol pack surface.
    base.extend(_iter_builtin_protocol_pack_files(repo_root))

    # Normalize, de-dup, stable order.
    canon = sorted(set(_common._validate_repo_rel(p) for p in base))
    return canon

def _sweep_managed_surface_files(root: _common.Path) -> list[str]:
    """Enumerate tracked managed surfaces that require explicit sweep listing.

    These surfaces change frequently across ops/workflow ergonomics work and
    must remain explicitly present in _canonical_inputs to avoid silent drift.
    """

    tracked = _common._run_git(root, ["ls-files"])
    out: set[str] = set()
    for raw in tracked.splitlines():
        rel = raw.strip()
        if not rel:
            continue
        rel = _common._validate_repo_rel(rel)
        if "/" not in rel and rel.endswith(".md"):
            out.add(rel)
            continue
        if rel.startswith("docs/operations/") and rel.endswith(".md"):
            out.add(rel)
            continue
        if rel.startswith("belgi/canonicals/") and rel.endswith(".md"):
            out.add(rel)
            continue
        if rel in {
            "belgi/anchor/v1/TrustAnchor.json",
            "belgi/genesis/GenesisSealPayload.json",
            "belgi/genesis/README.md",
            "belgi/trust_anchor.py",
            "tools/canonicals_report.py",
            "tools/report.py",
        }:
            out.add(rel)
            continue
        if rel in _governed_sweep_owner_files():
            out.add(rel)
            continue
        if rel.startswith(".github/workflows/") and rel.endswith((".yml", ".yaml")):
            out.add(rel)
            continue
        if rel.startswith(".github/scripts/") and rel.endswith(".py"):
            out.add(rel)
            continue
        if rel.startswith("scripts/belgi_") and rel.endswith((".py", ".sh", ".ps1")):
            out.add(rel)
            continue
        if rel.startswith("templates/ci/github/") and rel.endswith((".yml", ".yaml")):
            out.add(rel)
            continue
        if rel == "tools/README.md":
            out.add(rel)
            continue
        if rel in {
            "belgi/_protocol_packs/v1/schemas/README.md",
            "belgi/cli_app/parser/run.py",
            "belgi/cli_app/commands/run.py",
            "chain/compiler_c1_intent.py",
            "chain/logic/locked_object_schema.py",
            "chain/logic/q_checks/q_intent_003.py",
            "chain/logic/toolchain_set.py",
            "chain/logic/tolerances.py",
            "chain/logic/q_checks/q4_constraints_present.py",
            "chain/logic/q_checks/q5_environment_envelope.py",
            "chain/logic/r_checks/r2_scope_budgets.py",
        }:
            out.add(rel)
    return sorted(out)
