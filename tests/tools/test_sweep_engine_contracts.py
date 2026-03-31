from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools._sweep import inputs as inputs_owner
from tools._sweep import registry as registry_owner
from tools._sweep.model import InvariantResult
from tools._sweep.runner import run_consistency_sweep

pytestmark = pytest.mark.repo_local


EXPECTED_REGISTRY_ORDER = [
    "CS-CAN-001",
    "CS-CAN-004",
    "CS-CAN-002",
    "CS-CAN-003",
    "CS-CAN-005",
    "CS-TERM-001",
    "CS-GS-001",
    "CS-GS-002",
    "CS-GS-003",
    "CS-GS-004",
    "CS-GS-005",
    "CS-IS-001",
    "CS-IS-002",
    "CS-IS-003",
    "CS-IS-004",
    "CS-IS-005",
    "CS-RUN-001",
    "CS-RUN-002",
    "CS-SCHEMA-001",
    "CS-EV-001",
    "CS-EV-002",
    "CS-EV-003",
    "CS-EV-004",
    "CS-EV-005",
    "CS-TIER-001",
    "CS-TIER-002",
    "CS-TIER-003",
    "CS-TIER-004",
    "CS-TIER-005",
    "CS-WVR-001",
    "CS-WVR-002",
    "CS-WVR-003",
    "CS-WVR-004",
    "CS-WVR-005",
    "CS-TPL-001",
    "CS-TPL-002",
    "CS-TPL-003",
    "CS-TPL-004",
    "CS-TPL-005",
    "CS-VERIFY_BUNDLE-001",
    "CS-GATE_R-MANDATES-VERIFY_BUNDLE-001",
    "CS-VERIFY_BUNDLE-GATEVERDICT-BINDING-001",
    "CS-BYTE-001",
    "CS-FIXTURE-ZERO-001",
    "CS-PROTOCOL-IDENTITY-001",
    "CS-SWEEP-001",
    "CS-SWEEP-002",
    "CS-GV-001",
    "CS-LS-001",
    "CS-LS-002",
    "CS-REF-001",
    "CS-R0-ENFORCEMENT-WIRED-001",
    "CS-RENDER-001",
]


def _resolve_existing_repo_file(root: Path, rel: str) -> Path:
    path = root / Path(*rel.split("/"))
    if not path.is_file():
        raise FileNotFoundError(rel)
    return path


def test_registry_owner_preserves_explicit_invariant_order() -> None:
    assert [invariant_id for invariant_id, _fn in registry_owner.ORDERED_INVARIANTS] == EXPECTED_REGISTRY_ORDER


def test_runner_executes_registry_order_and_renders_sorted_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    call_order: list[str] = []
    ordered_ids = [invariant_id for invariant_id, _fn in registry_owner.ORDERED_INVARIANTS[:2]]
    (tmp_path / "tracked.txt").write_text("hello\n", encoding="utf-8", errors="strict", newline="\n")

    exit_code = run_consistency_sweep(
        root=tmp_path,
        out_path=tmp_path / "policy" / "consistency_sweep.json",
        output_label="policy/consistency_sweep.json",
        tool_name="consistency-sweep",
        tool_version="1.0.0",
        extra_inputs=[],
        canonical_sweep_out="policy/consistency_sweep.json",
        canonical_sweep_summary="policy/consistency_sweep.summary.md",
        consistency_spec_doc="docs/operations/consistency-sweep.md",
        validate_repo_rel=lambda rel: rel.replace("\\", "/"),
        extract_spec_invariant_ids=lambda _root: ordered_ids,
        invariant_registry=lambda: {
            ordered_ids[0]: lambda _root: _record_result(call_order, ordered_ids[0], "PASS"),
            ordered_ids[1]: lambda _root: _record_result(call_order, ordered_ids[1], "PASS"),
        },
        canonical_inputs=lambda _root: ["tracked.txt"],
        repo_revision_getter=lambda _root, _exclude: "a" * 40,
        resolve_existing_repo_file=_resolve_existing_repo_file,
    )

    assert exit_code == 0
    assert call_order == ordered_ids
    assert (tmp_path / "policy" / "consistency_sweep.json").exists()
    assert (tmp_path / "policy" / "consistency_sweep.summary.md").exists()

    stdout = capsys.readouterr().out
    assert "Wrote: policy/consistency_sweep.json" in stdout
    assert "Summary: total=2 passed=2 failed=0" in stdout


def test_runner_fails_closed_on_spec_registry_drift(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = run_consistency_sweep(
        root=tmp_path,
        out_path=tmp_path / "policy" / "consistency_sweep.json",
        output_label="policy/consistency_sweep.json",
        tool_name="consistency-sweep",
        tool_version="1.0.0",
        extra_inputs=[],
        canonical_sweep_out="policy/consistency_sweep.json",
        canonical_sweep_summary="policy/consistency_sweep.summary.md",
        consistency_spec_doc="docs/operations/consistency-sweep.md",
        validate_repo_rel=lambda rel: rel.replace("\\", "/"),
        extract_spec_invariant_ids=lambda _root: ["CS-A-001"],
        invariant_registry=lambda: {
            "CS-A-001": lambda _root: InvariantResult("CS-A-001", "PASS", [], ""),
            "CS-B-001": lambda _root: InvariantResult("CS-B-001", "PASS", [], ""),
        },
        canonical_inputs=lambda _root: [],
        repo_revision_getter=lambda _root, _exclude: "a" * 40,
        resolve_existing_repo_file=_resolve_existing_repo_file,
    )

    assert exit_code == 2
    assert not (tmp_path / "policy" / "consistency_sweep.json").exists()

    stderr = capsys.readouterr().err
    assert "Spec-sync NO-GO" in stderr
    assert "CS-B-001" in stderr


def test_runner_writes_artifacts_and_primary_failure_without_repo_live_parity_roots(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "tracked.txt").write_text("hello\n", encoding="utf-8", errors="strict", newline="\n")

    exit_code = run_consistency_sweep(
        root=tmp_path,
        out_path=tmp_path / "policy" / "consistency_sweep.json",
        output_label="policy/consistency_sweep.json",
        tool_name="consistency-sweep",
        tool_version="1.0.0",
        extra_inputs=[],
        canonical_sweep_out="policy/consistency_sweep.json",
        canonical_sweep_summary="policy/consistency_sweep.summary.md",
        consistency_spec_doc="docs/operations/consistency-sweep.md",
        validate_repo_rel=lambda rel: rel.replace("\\", "/"),
        extract_spec_invariant_ids=lambda _root: ["CS-FAIL-001", "CS-PASS-001"],
        invariant_registry=lambda: {
            "CS-FAIL-001": lambda _root: InvariantResult("CS-FAIL-001", "FAIL", ["synthetic.md"], "Schema invalid for synthetic fixture"),
            "CS-PASS-001": lambda _root: InvariantResult("CS-PASS-001", "PASS", ["synthetic.md"], ""),
        },
        canonical_inputs=lambda _root: ["tracked.txt"],
        repo_revision_getter=lambda _root, _exclude: "b" * 40,
        resolve_existing_repo_file=_resolve_existing_repo_file,
    )

    assert exit_code == 1

    report = json.loads((tmp_path / "policy" / "consistency_sweep.json").read_text(encoding="utf-8", errors="strict"))
    assert report["repo_revision"] == "b" * 40
    assert (tmp_path / "policy" / "consistency_sweep.summary.md").exists()

    streams = capsys.readouterr()
    assert "Summary: total=2 passed=1 failed=1" in streams.out
    assert "PRIMARY_CAUSE: CS-FAIL-001: Schema invalid for synthetic fixture" in streams.err


def test_sweep_shell_keeps_registry_and_input_compatibility_shims(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import tools.sweep as sweep

    monkeypatch.setattr(
        registry_owner,
        "invariant_registry",
        lambda: {"CS-SWEEP-001": lambda _root: InvariantResult("CS-SWEEP-001", "PASS", [], "")},
    )
    monkeypatch.setattr(inputs_owner, "_canonical_inputs", lambda _root: ["tracked.txt"])
    monkeypatch.setattr(inputs_owner, "_sweep_managed_surface_files", lambda _root: ["README.md"])

    assert list(sweep._invariant_registry().keys()) == ["CS-SWEEP-001"]
    assert sweep._canonical_inputs(tmp_path) == ["tracked.txt"]
    assert sweep._sweep_managed_surface_files(tmp_path) == ["README.md"]
    assert sweep.InvariantResult is InvariantResult


def test_sweep_shell_retires_moved_invariant_namespace() -> None:
    import tools.sweep as sweep

    retired_symbols = [
        "_C3_CANONICAL_MIRROR_BINDINGS",
        "_FIXTURE_ZERO_GOVERNED_PUBLIC_PATHS",
        "_PROTOCOL_IDENTITY_SOURCE_FORBIDDEN_PATTERNS",
        "_PROTOCOL_IDENTITY_SOURCE_GUARD_FILES",
        "_extract_cs_can_001_definitional_subject",
        "_extract_cs_can_001_term_map_subjects",
        "_iter_builtin_protocol_pack_files",
        "_iter_schema_files",
        "_missing_needles",
        "_normalize_cs_can_001_subject",
        "check_cs_byte_001",
        "check_cs_can_001",
        "check_cs_ev_001",
        "check_cs_fixture_zero_001",
        "check_cs_gs_001",
        "check_cs_is_002",
        "check_cs_ls_001",
        "check_cs_protocol_identity_001",
        "check_cs_ref_001",
        "check_cs_render_001",
        "check_cs_run_001",
        "check_cs_schema_001",
        "check_cs_sweep_001",
        "check_cs_tier_001",
        "check_cs_tpl_001",
        "check_cs_wvr_001",
        "check_intentspec_yaml_single_block",
    ]

    for name in retired_symbols:
        assert not hasattr(sweep, name), name


def test_sweep_shell_rejects_noncanonical_output_path(tmp_path: Path) -> None:
    import tools.sweep as sweep

    with pytest.raises(SystemExit) as excinfo:
        sweep.main(["consistency", "--repo", str(tmp_path), "--out", "policy/not-the-canonical-report.json"])

    assert excinfo.value.code == 2


def _record_result(call_order: list[str], invariant_id: str, status: str) -> InvariantResult:
    call_order.append(invariant_id)
    return InvariantResult(invariant_id, status, [f"{invariant_id}.md"], "")
