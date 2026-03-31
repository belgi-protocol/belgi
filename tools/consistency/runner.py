from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import Callable, Sequence

from .model import InvariantResult
from .report_writer import render_consistency_report, write_consistency_artifacts


def utc_now_rfc3339() -> str:
    """Deterministic timestamp for identical sweep inputs."""

    return "1970-01-01T00:00:00Z"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_inputs(
    root: Path,
    rel_paths: Sequence[str],
    *,
    validate_repo_rel: Callable[[str], str],
    resolve_existing_repo_file: Callable[[Path, str], Path],
    blob_overrides: dict[str, bytes] | None = None,
) -> list[dict[str, str]]:
    overrides = {validate_repo_rel(rel): data for rel, data in (blob_overrides or {}).items()}
    out: list[dict[str, str]] = []
    for rel in rel_paths:
        rel = validate_repo_rel(rel)
        if rel in overrides:
            digest = hashlib.sha256(overrides[rel]).hexdigest()
        else:
            digest = _sha256_file(resolve_existing_repo_file(root, rel))
        out.append({"path": rel, "sha256": digest})
    out.sort(key=lambda item: item["path"])
    return out


def run_consistency_sweep(
    *,
    root: Path,
    out_path: Path,
    output_label: str,
    tool_name: str,
    tool_version: str,
    extra_inputs: Sequence[str],
    canonical_sweep_out: str,
    canonical_sweep_summary: str,
    consistency_spec_doc: str,
    validate_repo_rel: Callable[[str], str],
    extract_spec_invariant_ids: Callable[[Path], list[str]],
    invariant_registry: Callable[[], dict[str, Callable[[Path], InvariantResult]]],
    canonical_inputs: Callable[[Path], list[str]],
    repo_revision_getter: Callable[[Path, Sequence[str]], str],
    resolve_existing_repo_file: Callable[[Path, str], Path],
) -> int:
    started = utc_now_rfc3339()

    spec_ids = extract_spec_invariant_ids(root)
    registry = invariant_registry()

    spec_set = set(spec_ids)
    registry_set = set(registry.keys())
    missing_in_code = sorted(spec_set - registry_set)
    extra_in_code = sorted(registry_set - spec_set)
    if missing_in_code or extra_in_code:
        if missing_in_code:
            print("Spec-sync NO-GO: invariant_ids missing in code registry:", file=sys.stderr)
            for invariant_id in missing_in_code:
                print(f"  - {invariant_id}", file=sys.stderr)
        if extra_in_code:
            print("Spec-sync NO-GO: invariant_ids present in code but not in spec:", file=sys.stderr)
            for invariant_id in extra_in_code:
                print(f"  - {invariant_id}", file=sys.stderr)
        return 2

    results: list[InvariantResult] = []
    for invariant_id in spec_ids:
        invariant_fn = registry[invariant_id]
        try:
            result = invariant_fn(root)
        except Exception as exc:
            result = InvariantResult(
                invariant_id,
                "FAIL",
                [consistency_spec_doc],
                f"Sweep check raised an exception: {exc}",
            )

        if result.invariant_id != invariant_id:
            print(
                f"Spec-sync NO-GO: invariant '{invariant_id}' returned mismatched id '{result.invariant_id}'",
                file=sys.stderr,
            )
            return 2
        results.append(result)

    finished = utc_now_rfc3339()

    canon_inputs = canonical_inputs(root)
    validated_extra_inputs = [validate_repo_rel(rel) for rel in extra_inputs]
    all_inputs = sorted(set(canon_inputs + validated_extra_inputs))
    excluded = {canonical_sweep_out, canonical_sweep_summary}
    filtered_inputs = [rel for rel in all_inputs if validate_repo_rel(rel) not in excluded]
    inputs = build_inputs(
        root,
        filtered_inputs,
        validate_repo_rel=validate_repo_rel,
        resolve_existing_repo_file=resolve_existing_repo_file,
    )

    report_base = {
        "artifact_id": "policy.consistency_sweep",
        "generated_at": finished,
        "sweep_started_at": started,
        "sweep_finished_at": finished,
        "tool": {"name": tool_name, "version": tool_version},
        "repo_revision": repo_revision_getter(root, [canonical_sweep_out, canonical_sweep_summary]),
        "inputs": inputs,
    }
    rendered = render_consistency_report(report_base, results)

    summary_path = out_path.with_suffix(".summary.md")
    write_consistency_artifacts(out_path, summary_path, rendered)

    print(f"Wrote: {output_label}")
    print(f"SHA-256 (report): {rendered.sha256}")
    print(
        "Summary: "
        f"total={len(rendered.ordered_results)} "
        f"passed={rendered.passed_count} "
        f"failed={rendered.failed_count}"
    )

    if rendered.failed_count > 0:
        primary = next((result for result in rendered.ordered_results if result.status == "FAIL"), None)
        if primary is not None:
            primary_message = str(primary.remediation or "").replace("\n", " ").strip()
            print(f"PRIMARY_CAUSE: {primary.invariant_id}: {primary_message}", file=sys.stderr)

    return 1 if rendered.failed_count > 0 else 0
