from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.repo_local

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_ROOT = REPO_ROOT / "tests"
RUN_CLI_ROOT = TESTS_ROOT / "run_cli"
LANE_DIRS = (
    "meta",
    "docs_authority",
    "run_cli",
    "run_orchestrator",
    "gates",
    "schemas",
    "shipped_surface",
    "tools",
    "serial",
)
LEGACY_TOP_LEVEL_LANE_MAP = {
    "tests/test_belgi_tools_run_tests.py": "tools",
    "tests/test_ci_result_parser.py": "tools",
    "tests/test_cli_usage_error_model.py": "tools",
    "tests/test_codeowners_checker.py": "tools",
    "tests/test_ergonomics_helpers.py": "tools",
    "tests/test_external_action_pin_guard.py": "tools",
    "tests/test_github_vars_sanitize.py": "tools",
    "tests/test_manifest_init.py": "tools",
    "tests/test_overlay_requirements.py": "tools",
    "tests/test_packaging_smoke.py": "shipped_surface",
    "tests/test_policy_stub_cli.py": "tools",
    "tests/test_resolve_belgi_workflow_inputs.py": "tools",
    "tests/test_stage_cli_forwarders.py": "tools",
    "tests/test_validate_belgi_ref_pin.py": "tools",
    "tests/test_waiver_cli.py": "tools",
    "tests/test_wheel_boundary.py": "shipped_surface",
}
FORBIDDEN_RUN_CLI_HELPERS = {"tests.helpers.run_cli_harness"}
FORBIDDEN_RUN_CLI_HANDLES = {"belgi_cli", "belgi_main", "run_orchestrator"}


def _classify_test_module(relpath: str) -> str:
    parts = Path(relpath).parts
    if len(parts) >= 3 and parts[0] == "tests" and parts[1] in LANE_DIRS:
        return parts[1]
    lane = LEGACY_TOP_LEVEL_LANE_MAP.get(relpath)
    assert lane is not None, f"unclassified test module: {relpath}"
    return lane


def test_lane_directories_exist_with_readmes() -> None:
    assert (TESTS_ROOT / "README.md").is_file(), "missing suite lane readme: tests/README.md"
    for lane in LANE_DIRS:
        lane_dir = TESTS_ROOT / lane
        assert lane_dir.is_dir(), f"missing lane directory: tests/{lane}/"
    assert (TESTS_ROOT / "serial" / "README.md").is_file(), "missing serial protocol readme: tests/serial/README.md"


def test_every_test_module_belongs_to_exactly_one_lane() -> None:
    relpaths = sorted(
        path.relative_to(REPO_ROOT).as_posix()
        for path in TESTS_ROOT.rglob("test_*.py")
        if "__pycache__" not in path.parts
    )
    assert relpaths, "expected tracked test modules"

    seen: set[str] = set()
    for relpath in relpaths:
        lane = _classify_test_module(relpath)
        assert lane in LANE_DIRS
        assert relpath not in seen
        seen.add(relpath)


def test_generated_run_docs_and_sweep_semantics_stay_out_of_docs_authority() -> None:
    assert _classify_test_module("tests/run_cli/test_init_cli_contracts.py") == "run_cli"
    assert _classify_test_module("tests/run_cli/test_manifest_cli_contracts.py") == "run_cli"
    assert _classify_test_module("tests/run_cli/test_run_new_cli_contracts.py") == "run_cli"
    assert _classify_test_module("tests/run_cli/test_run_cli_spine.py") == "run_cli"
    assert _classify_test_module("tests/run_cli/test_run_cli_output_contracts.py") == "run_cli"
    assert _classify_test_module("tests/run_cli/test_verify_cli_contracts.py") == "run_cli"
    assert _classify_test_module("tests/run_cli/test_run_cli_locked_input_contracts.py") == "run_cli"
    assert _classify_test_module("tests/run_cli/test_run_cli_tier1_contracts.py") == "run_cli"
    assert _classify_test_module("tests/run_orchestrator/test_run_orchestrator_cli_contracts.py") == "run_orchestrator"
    assert _classify_test_module("tests/run_orchestrator/test_run_orchestrator_cli_output_contracts.py") == "run_orchestrator"
    assert _classify_test_module("tests/run_orchestrator/test_run_orchestrator_hydration_contracts.py") == "run_orchestrator"
    assert _classify_test_module("tests/run_orchestrator/test_run_orchestrator_supplychain_contracts.py") == "run_orchestrator"
    assert _classify_test_module("tests/run_orchestrator/test_run_orchestrator_toolchain_input_contracts.py") == "run_orchestrator"
    assert _classify_test_module("tests/run_orchestrator/test_run_orchestrator_tolerances_contracts.py") == "run_orchestrator"
    assert _classify_test_module("tests/tools/test_run_belgi_smoke_script.py") == "tools"
    assert _classify_test_module("tests/meta/test_sweep_semantics.py") == "meta"
    assert _classify_test_module("tests/docs_authority/test_template_claim_contracts.py") == "docs_authority"
    assert _classify_test_module("tests/docs_authority/test_workflow_contracts.py") == "docs_authority"

    assert not (TESTS_ROOT / "test_sweep_semantics.py").exists()
    assert not (TESTS_ROOT / "test_no_chain_base_cannon_imports.py").exists()
    assert not (TESTS_ROOT / "test_template_claim_contracts.py").exists()
    assert not (TESTS_ROOT / "test_workflow_contracts.py").exists()
    assert not (TESTS_ROOT / "test_run_verify_cli.py").exists()
    assert not (TESTS_ROOT / "test_run_manifest_cli.py").exists()
    assert not (TESTS_ROOT / "test_run_belgi_smoke_script.py").exists()
    assert not (TESTS_ROOT / "test_run_orchestrator_template_hydration.py").exists()


def test_gate_hotspot_is_split_into_owner_lanes() -> None:
    assert _classify_test_module("tests/gates/test_gate_q_contracts.py") == "gates"
    assert _classify_test_module("tests/gates/test_gate_protocol_identity_contracts.py") == "gates"
    assert _classify_test_module("tests/gates/test_gate_q_waiver_contracts.py") == "gates"
    assert _classify_test_module("tests/gates/test_gate_q_constraints_contracts.py") == "gates"
    assert _classify_test_module("tests/gates/test_gate_q_hotl_contracts.py") == "gates"
    assert _classify_test_module("tests/gates/test_gate_r_contracts.py") == "gates"
    assert _classify_test_module("tests/gates/test_gate_r_diff_capture_contracts.py") == "gates"
    assert _classify_test_module("tests/gates/test_gate_r_attestation_signing_contracts.py") == "gates"
    assert _classify_test_module("tests/gates/test_gate_r_policy_scan_contracts.py") == "gates"
    assert _classify_test_module("tests/gates/test_gate_s_contracts.py") == "gates"
    assert _classify_test_module("tests/gates/test_objectref_contracts.py") == "gates"
    assert _classify_test_module("tests/gates/test_tier_contracts.py") == "gates"
    assert _classify_test_module("tests/gates/test_tier_evidence_contracts.py") == "gates"
    assert _classify_test_module("tests/gates/test_trust_anchor_contracts.py") == "gates"
    assert _classify_test_module("tests/tools/test_sweep_repo_revision_contracts.py") == "tools"
    assert _classify_test_module("tests/tools/test_byte_guard_contracts.py") == "tools"

    assert not (TESTS_ROOT / "test_gate_contracts.py").exists()
    assert not (TESTS_ROOT / "test_protocol_identity_ssot.py").exists()
    assert not (TESTS_ROOT / "test_q6_waiver_limits.py").exists()
    assert not (TESTS_ROOT / "test_q_constraints_tolerances_contract.py").exists()
    assert not (TESTS_ROOT / "test_q_hotl_contract.py").exists()
    assert not (TESTS_ROOT / "test_r2_r3_diff_capture_integration.py").exists()
    assert not (TESTS_ROOT / "test_r6_attestation_signing_integration.py").exists()
    assert not (TESTS_ROOT / "test_r7_r8_policy_scan_integration.py").exists()
    assert not (TESTS_ROOT / "test_tier_contract_enforcement.py").exists()
    assert not (TESTS_ROOT / "test_trust_anchor_contract.py").exists()


def test_shipped_surface_lane_owner_splits() -> None:
    assert _classify_test_module("tests/shipped_surface/test_builtin_protocol_pack_contracts.py") == "shipped_surface"
    assert _classify_test_module("tests/shipped_surface/test_c3_docs_bundle_contracts.py") == "shipped_surface"
    assert _classify_test_module("tests/shipped_surface/test_c3_engine_canonicals_integration.py") == "shipped_surface"
    assert _classify_test_module("tests/shipped_surface/test_docs_compiler_hash_contract.py") == "shipped_surface"
    assert _classify_test_module("tests/shipped_surface/test_protocol_pack_lifecycle_contracts.py") == "shipped_surface"
    assert _classify_test_module("tests/shipped_surface/test_protocol_pack_manifest_contracts.py") == "shipped_surface"

    assert not (TESTS_ROOT / "test_builtin_protocol_pack.py").exists()
    assert not (TESTS_ROOT / "test_c3_engine_canonicals_integration.py").exists()
    assert not (TESTS_ROOT / "test_docs_compiler_hash_contract.py").exists()
    assert not (TESTS_ROOT / "test_pack_lifecycle.py").exists()
    assert not (TESTS_ROOT / "test_protocol_pack_manifest.py").exists()


def test_run_cli_lane_stays_subprocess_black_box() -> None:
    failures: list[str] = []

    for path in sorted(RUN_CLI_ROOT.rglob("test_*.py")):
        rel = path.relative_to(REPO_ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8", errors="strict"), filename=rel)

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in FORBIDDEN_RUN_CLI_HELPERS:
                        failures.append(f"{rel}: imports forbidden helper `{alias.name}`")
            elif isinstance(node, ast.ImportFrom):
                if node.module in FORBIDDEN_RUN_CLI_HELPERS:
                    failures.append(f"{rel}: imports forbidden helper `{node.module}`")
                if node.module == "tests.helpers":
                    for alias in node.names:
                        if alias.name == "run_cli_harness":
                            failures.append(f"{rel}: imports forbidden helper `tests.helpers.run_cli_harness`")
            elif isinstance(node, ast.FunctionDef):
                args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
                if any(arg.arg == "monkeypatch" for arg in args):
                    failures.append(f"{rel}: uses forbidden `monkeypatch` fixture in subprocess lane")
            elif isinstance(node, ast.Name) and node.id in FORBIDDEN_RUN_CLI_HANDLES:
                failures.append(f"{rel}: uses forbidden in-process runtime handle `{node.id}`")

    assert not failures, "\n".join(failures)
