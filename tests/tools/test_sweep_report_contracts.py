from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools._sweep.model import InvariantResult, inventory_witness_details
from tools._sweep.report_writer import (
    render_consistency_report,
    write_consistency_artifacts,
    write_consistency_summary_md,
)

pytestmark = pytest.mark.repo_local


def _report_base() -> dict[str, object]:
    return {
        "artifact_id": "policy.consistency_sweep",
        "generated_at": "1970-01-01T00:00:00Z",
        "sweep_started_at": "1970-01-01T00:00:00Z",
        "sweep_finished_at": "1970-01-01T00:00:00Z",
        "tool": {"name": "consistency-sweep", "version": "1.0.0"},
        "repo_revision": "a" * 40,
        "inputs": [{"path": "tracked.txt", "sha256": "b" * 64}],
    }


def test_render_consistency_report_emits_canonical_json_bytes() -> None:
    rendered = render_consistency_report(
        _report_base(),
        [
            InvariantResult("CS-PASS-001", "PASS", ["synthetic.md"], ""),
            InvariantResult("CS-FAIL-001", "FAIL", ["synthetic.md"], "Schema invalid for synthetic fixture"),
        ],
    )

    expected_payload = {
        "artifact_id": "policy.consistency_sweep",
        "generated_at": "1970-01-01T00:00:00Z",
        "sweep_started_at": "1970-01-01T00:00:00Z",
        "sweep_finished_at": "1970-01-01T00:00:00Z",
        "tool": {"name": "consistency-sweep", "version": "1.0.0"},
        "repo_revision": "a" * 40,
        "inputs": [{"path": "tracked.txt", "sha256": "b" * 64}],
        "invariants": [
            {
                "invariant_id": "CS-FAIL-001",
                "status": "FAIL",
                "evidence": ["synthetic.md"],
                "remediation": "Schema invalid for synthetic fixture",
            },
            {
                "invariant_id": "CS-PASS-001",
                "status": "PASS",
                "evidence": ["synthetic.md"],
                "remediation": "",
            },
        ],
        "summary": {"total": 2, "passed": 1, "failed": 1},
        "failures": [{"check_id": "CS-FAIL-001", "message": "Schema invalid for synthetic fixture"}],
    }

    expected_bytes = (
        json.dumps(expected_payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8", errors="strict")

    assert rendered.payload == expected_payload
    assert rendered.canonical_bytes == expected_bytes


def test_write_consistency_summary_md_renders_exact_failure_markdown(tmp_path: Path) -> None:
    summary_path = tmp_path / "policy" / "consistency_sweep.summary.md"
    write_consistency_summary_md(
        summary_path,
        total=2,
        passed=1,
        failed=1,
        results=[
            InvariantResult("CS-PASS-001", "PASS", ["synthetic.md"], ""),
            InvariantResult("CS-FAIL-001", "FAIL", ["synthetic.md"], "Schema invalid for synthetic fixture"),
        ],
    )

    assert summary_path.read_text(encoding="utf-8", errors="strict") == (
        "## Consistency sweep\n"
        "- total: **2**  passed: **1**  failed: **1**\n"
        "\n"
        "### Failures\n"
        "#### CS-FAIL-001\n"
        "- message: Schema invalid for synthetic fixture\n"
        "- remediation: Fix JSON to satisfy the referenced schema (missing/extra fields).\n"
    )


def test_write_consistency_summary_md_renders_cs_byte_details_branch(tmp_path: Path) -> None:
    summary_path = tmp_path / "policy" / "consistency_sweep.summary.md"
    write_consistency_summary_md(
        summary_path,
        total=1,
        passed=0,
        failed=1,
        results=[
            InvariantResult(
                "CS-BYTE-001",
                "FAIL",
                ["tools/normalize.py"],
                "Run python -m tools.normalize --fix --tracked-only to eliminate CRLF drift, then rerun the sweep.",
                {
                    "counts": {"drift_files": 2},
                    "drift_files": [{"path": "b.txt"}, {"path": "a.txt"}],
                },
            )
        ],
    )

    assert summary_path.read_text(encoding="utf-8", errors="strict") == (
        "## Consistency sweep\n"
        "- total: **1**  passed: **0**  failed: **1**\n"
        "\n"
        "### Failures\n"
        "#### CS-BYTE-001\n"
        "- message: Run python -m tools.normalize --fix --tracked-only to eliminate CRLF drift, then rerun the sweep.\n"
        "- remediation: Open policy/consistency_sweep.json and fix the reported check; re-run tools.sweep consistency.\n"
        "- details: drift_files=2 examples=a.txt, b.txt\n"
    )


def test_render_consistency_report_rejects_inventory_pass_without_checked_set_truth() -> None:
    with pytest.raises(ValueError, match="CS-SWEEP-001 requires structured inventory witness details"):
        render_consistency_report(
            _report_base(),
            [InvariantResult("CS-SWEEP-001", "PASS", ["tools/_sweep/inputs.py"], "")],
        )


def test_render_consistency_report_rejects_inventory_fail_without_checked_set_truth() -> None:
    with pytest.raises(ValueError, match="CS-RENDER-001 requires structured inventory witness details"):
        render_consistency_report(
            _report_base(),
            [InvariantResult("CS-RENDER-001", "FAIL", ["tools/render.py"], "Render drift detected.")],
        )


def test_render_consistency_report_keeps_inventory_witness_details_in_json_payload() -> None:
    result = InvariantResult(
        "CS-SWEEP-001",
        "PASS",
        ["tools/_sweep/inputs.py"],
        "",
        inventory_witness_details(
            checked_set=("CANONICALS.md", "schemas/IntentSpec.schema.json"),
            derived_from=("tools/_sweep/inputs.py::_canonical_inputs",),
        ),
    )

    rendered = render_consistency_report(_report_base(), [result])

    assert rendered.payload["invariants"] == [
        {
            "invariant_id": "CS-SWEEP-001",
            "status": "PASS",
            "evidence": ["tools/_sweep/inputs.py"],
            "remediation": "",
            "details": result.details,
        }
    ]


def test_write_consistency_summary_md_projects_inventory_witness_from_json_details(tmp_path: Path) -> None:
    summary_path = tmp_path / "policy" / "consistency_sweep.summary.md"
    details = inventory_witness_details(
        checked_set=("docs/operations/cli.md -> belgi/canonicals/docs/operations/cli.md",),
        missing=("belgi/canonicals/docs/operations/cli.md",),
        derived_from=("belgi/protocol/pack_surface_inventory.py::C3_CANONICAL_MIRROR_BINDINGS",),
    )
    write_consistency_summary_md(
        summary_path,
        total=1,
        passed=0,
        failed=1,
        results=[
            InvariantResult(
                "CS-CAN-005",
                "FAIL",
                ["docs/operations/consistency-sweep.md#cs-can-005--package-canonical-mirror-is-byte-identical-to-source-docs"],
                "Missing canonical mirror source/target file(s): belgi/canonicals/docs/operations/cli.md.",
                details,
            )
        ],
    )

    assert summary_path.read_text(encoding="utf-8", errors="strict") == (
        "## Consistency sweep\n"
        "- total: **1**  passed: **0**  failed: **1**\n"
        "\n"
        "### Failures\n"
        "#### CS-CAN-005\n"
        "- message: Missing canonical mirror source/target file(s): belgi/canonicals/docs/operations/cli.md.\n"
        "- remediation: Open policy/consistency_sweep.json and fix the reported check; re-run tools.sweep consistency.\n"
        f"- witness: checked_count=1 checked_set_sha256={details['checked_set_sha256']} missing=1 unexpected=0 mismatched=0\n"
        "- missing: belgi/canonicals/docs/operations/cli.md\n"
    )


def test_write_consistency_artifacts_writes_report_json_and_summary_markdown(tmp_path: Path) -> None:
    report_path = tmp_path / "policy" / "consistency_sweep.json"
    summary_path = tmp_path / "policy" / "consistency_sweep.summary.md"
    rendered = render_consistency_report(
        _report_base(),
        [InvariantResult("CS-PASS-001", "PASS", ["synthetic.md"], "")],
    )

    write_consistency_artifacts(report_path, summary_path, rendered)

    assert report_path.read_bytes() == rendered.canonical_bytes
    assert summary_path.read_text(encoding="utf-8", errors="strict") == (
        "## Consistency sweep\n"
        "- total: **1**  passed: **1**  failed: **0**\n"
        "\n"
        "✅ all checks passed\n"
    )
