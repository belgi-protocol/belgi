from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Sequence

from .model import (
    InvariantResult,
    RenderedConsistencyReport,
    validate_inventory_witness_details,
)


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp.sweep")
    with tmp.open("wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(str(tmp), str(path))


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp.sweep")
    with tmp.open("w", encoding="utf-8", errors="strict", newline="\n") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(str(tmp), str(path))


def _canonical_json_bytes(obj: object) -> bytes:
    rendered = json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n"
    return rendered.encode("utf-8", errors="strict")


def _remediation_for_message(msg: str) -> str:
    lowered = (msg or "").lower()
    if "run_id" in lowered and ("missing" in lowered or "empty" in lowered):
        return "Ensure all required artifacts include non-empty run_id; regenerate bundle."
    if "schema" in lowered and ("invalid" in lowered or "validation" in lowered):
        return "Fix JSON to satisfy the referenced schema (missing/extra fields)."
    return "Open policy/consistency_sweep.json and fix the reported check; re-run tools.sweep consistency."


def _validate_results_for_render(results: Sequence[InvariantResult]) -> None:
    for result in results:
        validate_inventory_witness_details(result.invariant_id, result.details)


def _inventory_witness_summary_lines(details: dict[str, Any]) -> list[str]:
    checked_count = details.get("checked_count")
    checked_set_sha256 = details.get("checked_set_sha256")
    missing = details.get("missing")
    unexpected = details.get("unexpected")
    mismatched = details.get("mismatched")
    if not (
        isinstance(checked_count, int)
        and isinstance(checked_set_sha256, str)
        and isinstance(missing, list)
        and isinstance(unexpected, list)
        and isinstance(mismatched, list)
    ):
        return []

    lines = [
        (
            "- witness: "
            f"checked_count={checked_count} "
            f"checked_set_sha256={checked_set_sha256} "
            f"missing={len(missing)} "
            f"unexpected={len(unexpected)} "
            f"mismatched={len(mismatched)}"
        )
    ]
    if missing:
        lines.append(f"- missing: {', '.join(missing[:5])}")
    if unexpected:
        lines.append(f"- unexpected: {', '.join(unexpected[:5])}")
    if mismatched:
        lines.append(f"- mismatched: {', '.join(mismatched[:5])}")
    return lines


def render_consistency_report(
    report_base: dict[str, Any],
    result_set: Sequence[InvariantResult],
) -> RenderedConsistencyReport:
    ordered = sorted(result_set, key=lambda result: result.invariant_id)
    _validate_results_for_render(ordered)
    passed_count = sum(1 for result in ordered if result.status == "PASS")
    failed_count = sum(1 for result in ordered if result.status == "FAIL")

    report = dict(report_base)
    report["invariants"] = [
        {
            "invariant_id": result.invariant_id,
            "status": result.status,
            "evidence": result.evidence,
            "remediation": result.remediation if result.status == "FAIL" else "",
            **({"details": result.details} if isinstance(result.details, dict) else {}),
        }
        for result in ordered
    ]
    report["summary"] = {"total": len(ordered), "passed": passed_count, "failed": failed_count}
    report["failures"] = [
        {
            "check_id": result.invariant_id,
            "message": result.remediation.replace("\n", " ").strip() if result.remediation else "",
        }
        for result in ordered
        if result.status == "FAIL"
    ]

    canonical_bytes = _canonical_json_bytes(report)
    return RenderedConsistencyReport(
        payload=report,
        canonical_bytes=canonical_bytes,
        sha256=hashlib.sha256(canonical_bytes).hexdigest(),
        ordered_results=list(ordered),
        passed_count=passed_count,
        failed_count=failed_count,
    )


def write_consistency_summary_md(
    path: Path,
    *,
    total: int,
    passed: int,
    failed: int,
    results: Sequence[InvariantResult],
) -> None:
    ordered_results = sorted(results, key=lambda result: result.invariant_id)
    _validate_results_for_render(ordered_results)

    lines: list[str] = []
    lines.append("## Consistency sweep")
    lines.append(f"- total: **{total}**  passed: **{passed}**  failed: **{failed}**")
    lines.append("")

    if failed == 0:
        lines.append("✅ all checks passed")
    else:
        lines.append("### Failures")
        failures = sorted(
            [result for result in ordered_results if result.status == "FAIL"],
            key=lambda result: result.invariant_id,
        )
        for result in failures:
            message = result.remediation.replace("\n", " ").strip() if result.remediation else "(no message)"
            remediation = _remediation_for_message(message)
            lines.append(f"#### {result.invariant_id}")
            lines.append(f"- message: {message}")
            lines.append(f"- remediation: {remediation}")

            if result.invariant_id == "CS-BYTE-001" and isinstance(result.details, dict):
                counts = result.details.get("counts") if isinstance(result.details.get("counts"), dict) else {}
                drift = result.details.get("drift_files") if isinstance(result.details.get("drift_files"), list) else []
                paths = [item.get("path") for item in drift if isinstance(item, dict) and isinstance(item.get("path"), str)]
                examples = ", ".join(sorted(set(paths))[:5])
                lines.append(
                    f"- details: drift_files={counts.get('drift_files')} examples={examples if examples else '<none>'}"
                )

            if isinstance(result.details, dict):
                lines.extend(_inventory_witness_summary_lines(result.details))

    _atomic_write_text(path, "\n".join(lines) + "\n")


def write_consistency_artifacts(
    out_path: Path,
    summary_path: Path,
    rendered: RenderedConsistencyReport,
) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write_bytes(out_path, rendered.canonical_bytes)
    write_consistency_summary_md(
        summary_path,
        total=len(rendered.ordered_results),
        passed=rendered.passed_count,
        failed=rendered.failed_count,
        results=rendered.ordered_results,
    )
