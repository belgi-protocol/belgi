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
    "tests/test_builders.py": "meta",
    "tests/test_builtin_protocol_pack.py": "shipped_surface",
    "tests/test_c3_engine_canonicals_integration.py": "shipped_surface",
    "tests/test_ci_result_parser.py": "tools",
    "tests/test_cli_usage_error_model.py": "tools",
    "tests/test_codeowners_checker.py": "tools",
    "tests/test_core_ssot_guards.py": "meta",
    "tests/test_docs_compiler_hash_contract.py": "shipped_surface",
    "tests/test_ergonomics_helpers.py": "tools",
    "tests/test_external_action_pin_guard.py": "tools",
    "tests/test_gate_contracts.py": "gates",
    "tests/test_github_vars_sanitize.py": "tools",
    "tests/test_import_graph_sanity.py": "meta",
    "tests/test_manifest_init.py": "tools",
    "tests/test_overlay_requirements.py": "tools",
    "tests/test_pack_lifecycle.py": "shipped_surface",
    "tests/test_packaging_smoke.py": "shipped_surface",
    "tests/test_policy_stub_cli.py": "tools",
    "tests/test_protocol_identity_ssot.py": "gates",
    "tests/test_protocol_pack_manifest.py": "shipped_surface",
    "tests/test_q6_waiver_limits.py": "gates",
    "tests/test_q_constraints_tolerances_contract.py": "gates",
    "tests/test_q_hotl_contract.py": "gates",
    "tests/test_r2_r3_diff_capture_integration.py": "gates",
    "tests/test_r6_attestation_signing_integration.py": "gates",
    "tests/test_r7_r8_policy_scan_integration.py": "gates",
    "tests/test_repo_jail_and_cmdlog.py": "meta",
    "tests/test_resolve_belgi_workflow_inputs.py": "tools",
    "tests/test_run_belgi_smoke_script.py": "run_cli",
    "tests/test_run_manifest_cli.py": "run_cli",
    "tests/test_run_orchestrator_template_hydration.py": "run_orchestrator",
    "tests/test_schema_authority_contracts.py": "schemas",
    "tests/test_stage_cli_forwarders.py": "tools",
    "tests/test_tier_contract_enforcement.py": "gates",
    "tests/test_tier_packs_schema.py": "schemas",
    "tests/test_trust_anchor_contract.py": "gates",
    "tests/test_validate_belgi_ref_pin.py": "tools",
    "tests/test_waiver_cli.py": "tools",
    "tests/test_wheel_boundary.py": "shipped_surface",
    "tests/test_yaml_subset_parser.py": "schemas",
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
    assert _classify_test_module("tests/test_run_manifest_cli.py") == "run_cli"
    assert _classify_test_module("tests/run_cli/test_run_cli_spine.py") == "run_cli"
    assert _classify_test_module("tests/run_cli/test_run_cli_output_contracts.py") == "run_cli"
    assert _classify_test_module("tests/run_cli/test_verify_cli_contracts.py") == "run_cli"
    assert _classify_test_module("tests/run_cli/test_run_cli_locked_input_contracts.py") == "run_cli"
    assert _classify_test_module("tests/run_cli/test_run_cli_tier1_contracts.py") == "run_cli"
    assert _classify_test_module("tests/run_orchestrator/test_run_orchestrator_cli_contracts.py") == "run_orchestrator"
    assert _classify_test_module("tests/run_orchestrator/test_run_orchestrator_cli_output_contracts.py") == "run_orchestrator"
    assert _classify_test_module("tests/meta/test_sweep_semantics.py") == "meta"
    assert _classify_test_module("tests/docs_authority/test_template_claim_contracts.py") == "docs_authority"
    assert _classify_test_module("tests/docs_authority/test_workflow_contracts.py") == "docs_authority"

    assert not (TESTS_ROOT / "test_sweep_semantics.py").exists()
    assert not (TESTS_ROOT / "test_no_chain_base_cannon_imports.py").exists()
    assert not (TESTS_ROOT / "test_template_claim_contracts.py").exists()
    assert not (TESTS_ROOT / "test_workflow_contracts.py").exists()
    assert not (TESTS_ROOT / "test_run_verify_cli.py").exists()


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
