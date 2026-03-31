from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.consistency.model import InvariantResult
from tools.consistency.runner import run_consistency_sweep

pytestmark = pytest.mark.repo_local


def _resolve_existing_repo_file(root: Path, rel: str) -> Path:
    path = root / Path(*rel.split("/"))
    if not path.is_file():
        raise FileNotFoundError(rel)
    return path


def test_runner_executes_spec_order_and_renders_sorted_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    call_order: list[str] = []
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
        extract_spec_invariant_ids=lambda _root: ["CS-Z-002", "CS-A-001"],
        invariant_registry=lambda: {
            "CS-Z-002": lambda _root: _record_result(call_order, "CS-Z-002", "PASS"),
            "CS-A-001": lambda _root: _record_result(call_order, "CS-A-001", "PASS"),
        },
        canonical_inputs=lambda _root: ["tracked.txt"],
        repo_revision_getter=lambda _root, _exclude: "a" * 40,
        resolve_existing_repo_file=_resolve_existing_repo_file,
    )

    assert exit_code == 0
    assert call_order == ["CS-Z-002", "CS-A-001"]

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


def test_runner_writes_artifacts_and_primary_failure_without_repo_live_parity_roots(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
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
            "CS-FAIL-001": lambda _root: InvariantResult(
                "CS-FAIL-001",
                "FAIL",
                ["synthetic.md"],
                "Schema invalid for synthetic fixture",
            ),
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


def test_sweep_shell_rejects_noncanonical_output_path(tmp_path: Path) -> None:
    import tools.sweep as sweep

    with pytest.raises(SystemExit) as excinfo:
        sweep.main(["consistency", "--repo", str(tmp_path), "--out", "policy/not-the-canonical-report.json"])

    assert excinfo.value.code == 2


def _record_result(call_order: list[str], invariant_id: str, status: str) -> InvariantResult:
    call_order.append(invariant_id)
    return InvariantResult(invariant_id, status, [f"{invariant_id}.md"], "")
