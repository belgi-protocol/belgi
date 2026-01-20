from __future__ import annotations

from typing import Any

from belgi.core.jail import safe_relpath
from belgi.core.jail import resolve_storage_ref
from belgi.core.schema import validate_schema
from chain.logic.base import CheckResult
from chain.logic.s_checks.context import SCheckContext


class _SchemaArtifactInvalid(ValueError):
    pass


def _require_object_ref(obj: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise ValueError(f"{field} must be an object")
    for k in ("id", "hash", "storage_ref"):
        if k not in obj:
            raise ValueError(f"{field} missing required '{k}'")
    storage_ref = obj.get("storage_ref")
    if not isinstance(storage_ref, str) or not storage_ref.strip():
        raise ValueError(f"{field}.storage_ref missing/invalid")
    return obj


def _multiset_counts(items: list[tuple[Any, ...]]) -> dict[tuple[Any, ...], int]:
    counts: dict[tuple[Any, ...], int] = {}
    for k in items:
        counts[k] = counts.get(k, 0) + 1
    return counts


def run(ctx: SCheckContext) -> list[CheckResult]:
    repo_root = ctx.repo_root

    errs = validate_schema(ctx.locked_spec, ctx.locked_spec_schema, root_schema=ctx.locked_spec_schema, path="LockedSpec")
    if errs:
        first = errs[0]
        return [
            CheckResult(
                check_id="S1",
                status="FAIL",
                category="FS-SCHEMA-ARTIFACT-INVALID",
                message=f"LockedSpec schema invalid at {first.path}: {first.message}",
                pointers=[safe_relpath(repo_root, ctx.locked_spec_path)],
                remediation_next_instruction="Do fix LockedSpec schema validation errors then re-run S.",
            )
        ]

    errs = validate_schema(ctx.seal_manifest, ctx.seal_manifest_schema, root_schema=ctx.seal_manifest_schema, path="SealManifest")
    if errs:
        first = errs[0]
        return [
            CheckResult(
                check_id="S1",
                status="FAIL",
                category="FS-SCHEMA-ARTIFACT-INVALID",
                message=f"SealManifest schema invalid at {first.path}: {first.message}",
                pointers=[safe_relpath(repo_root, ctx.seal_manifest_path)],
                remediation_next_instruction="Do fix SealManifest schema validation errors then re-run S.",
            )
        ]

    errs = validate_schema(
        ctx.evidence_manifest,
        ctx.evidence_manifest_schema,
        root_schema=ctx.evidence_manifest_schema,
        path="EvidenceManifest",
    )
    if errs:
        first = errs[0]
        return [
            CheckResult(
                check_id="S1",
                status="FAIL",
                category="FS-SCHEMA-ARTIFACT-INVALID",
                message=f"EvidenceManifest schema invalid at {first.path}: {first.message}",
                pointers=[safe_relpath(repo_root, ctx.evidence_manifest_path)],
                remediation_next_instruction="Do fix EvidenceManifest schema validation errors then re-run S.",
            )
        ]

    # Minimal binding sanity: run_id must match.
    sm_run_id = ctx.seal_manifest.get("run_id")
    if sm_run_id != ctx.run_id:
        return [
            CheckResult(
                check_id="S1",
                status="FAIL",
                category="FS-BINDING-MISMATCH",
                message=f"SealManifest.run_id mismatch (got {sm_run_id!r}, expected {ctx.run_id!r})",
                pointers=[safe_relpath(repo_root, ctx.seal_manifest_path), safe_relpath(repo_root, ctx.locked_spec_path)],
                remediation_next_instruction="Do regenerate SealManifest for the correct run_id then re-run S.",
            )
        ]

    # Bind user-provided --evidence-manifest to SealManifest.evidence_manifest_ref.storage_ref.
    sm_evidence_ref = _require_object_ref(ctx.seal_manifest.get("evidence_manifest_ref"), field="SealManifest.evidence_manifest_ref")
    expected_storage_ref = str(sm_evidence_ref.get("storage_ref") or "")
    actual_storage_ref = safe_relpath(repo_root, ctx.evidence_manifest_path)
    if expected_storage_ref != actual_storage_ref:
        return [
            CheckResult(
                check_id="S1",
                status="FAIL",
                category="FS-BINDING-MISMATCH",
                message=(
                    "--evidence-manifest path must equal SealManifest.evidence_manifest_ref.storage_ref "
                    f"(got {actual_storage_ref!r}, expected {expected_storage_ref!r})"
                ),
                pointers=[safe_relpath(repo_root, ctx.evidence_manifest_path), safe_relpath(repo_root, ctx.seal_manifest_path)],
                remediation_next_instruction="Do pass the correct --evidence-manifest referenced by SealManifest then re-run S.",
            )
        ]

    # Validate referenced GateVerdict(Q/R) schema + basic binding.
    seal_ptr = safe_relpath(repo_root, ctx.seal_manifest_path)
    evidence_ptr = safe_relpath(repo_root, ctx.evidence_manifest_path)
    gv_q_storage_ref: str | None = None
    gv_r_storage_ref: str | None = None
    r_snapshot_storage_ref: str | None = None

    try:
        for expected_gate_id, ref_field in (
            ("Q", "SealManifest.gate_q_verdict_ref"),
            ("R", "SealManifest.gate_r_verdict_ref"),
        ):
            obj_ref = _require_object_ref(ctx.seal_manifest.get(ref_field.split(".", 1)[1]), field=ref_field)
            gv_storage_ref = str(obj_ref["storage_ref"])
            if expected_gate_id == "Q":
                gv_q_storage_ref = gv_storage_ref
            if expected_gate_id == "R":
                gv_r_storage_ref = gv_storage_ref

            gv_path = resolve_storage_ref(repo_root, gv_storage_ref)
            from chain.logic.base import load_json

            gv = load_json(gv_path)
            if not isinstance(gv, dict):
                raise ValueError(f"{ref_field} must point to a JSON object")
            gverrs = validate_schema(gv, ctx.gate_verdict_schema, root_schema=ctx.gate_verdict_schema, path="GateVerdict")
            if gverrs:
                first = gverrs[0]
                raise _SchemaArtifactInvalid(f"{ref_field} schema invalid at {first.path}: {first.message}")
            if gv.get("gate_id") != expected_gate_id:
                raise ValueError(f"{ref_field} gate_id mismatch (got {gv.get('gate_id')!r}, expected {expected_gate_id!r})")
            if gv.get("run_id") != ctx.run_id:
                raise ValueError(f"{ref_field} run_id mismatch (got {gv.get('run_id')!r}, expected {ctx.run_id!r})")

        # Replay Integrity Rule (normative): Final EvidenceManifest must be an append-only extension of the R-snapshot.
        # Load R-snapshot EvidenceManifest referenced by GateVerdict(R).evidence_manifest_ref.
        sm = ctx.seal_manifest
        r_ref = _require_object_ref(sm.get("gate_r_verdict_ref"), field="SealManifest.gate_r_verdict_ref")
        r_path = resolve_storage_ref(repo_root, str(r_ref["storage_ref"]))
        from chain.logic.base import load_json

        r_gv = load_json(r_path)
        r_ev_ref = _require_object_ref(r_gv.get("evidence_manifest_ref"), field="GateVerdict(R).evidence_manifest_ref")
        r_snapshot_storage_ref = str(r_ev_ref.get("storage_ref") or "") or None
        r_ev_path = resolve_storage_ref(repo_root, str(r_ev_ref["storage_ref"]))
        r_snapshot = load_json(r_ev_path)
        if not isinstance(r_snapshot, dict):
            raise ValueError("GateVerdict(R).evidence_manifest_ref must point to a JSON object")
        rerrs = validate_schema(r_snapshot, ctx.evidence_manifest_schema, root_schema=ctx.evidence_manifest_schema, path="EvidenceManifest")
        if rerrs:
            first = rerrs[0]
            raise ValueError(f"R-snapshot EvidenceManifest schema invalid at {first.path}: {first.message}")

        final_ev = ctx.evidence_manifest

        # envelope_attestation must match exactly (deep equality).
        if final_ev.get("envelope_attestation") != r_snapshot.get("envelope_attestation"):
            raise ValueError("Final EvidenceManifest.envelope_attestation must equal R-snapshot envelope_attestation")

        # commands_executed: R-snapshot commands must be an exact prefix of final commands.
        r_cmds = r_snapshot.get("commands_executed")
        f_cmds = final_ev.get("commands_executed")
        if not isinstance(r_cmds, list) or not isinstance(f_cmds, list):
            raise ValueError("EvidenceManifest.commands_executed must be arrays")
        if f_cmds[: len(r_cmds)] != r_cmds:
            raise ValueError("Final EvidenceManifest.commands_executed must preserve R-snapshot commands as an exact prefix")

        # artifacts: every R-snapshot artifact entry must appear in final artifacts with identical fields.
        r_artifacts = r_snapshot.get("artifacts")
        f_artifacts = final_ev.get("artifacts")
        if not isinstance(r_artifacts, list) or not isinstance(f_artifacts, list):
            raise ValueError("EvidenceManifest.artifacts must be arrays")

        def _artifact_key(a: Any) -> tuple[Any, ...]:
            if not isinstance(a, dict):
                raise ValueError("EvidenceManifest.artifacts entries must be objects")
            return (
                a.get("id"),
                a.get("kind"),
                a.get("hash"),
                a.get("media_type"),
                a.get("storage_ref"),
                a.get("produced_by"),
            )

        r_keys = [_artifact_key(a) for a in r_artifacts]
        f_keys = [_artifact_key(a) for a in f_artifacts]
        r_counts = _multiset_counts(r_keys)
        f_counts = _multiset_counts(f_keys)
        missing = [k for k, n in r_counts.items() if f_counts.get(k, 0) < n]
        if missing:
            missing_one = missing[0]
            raise ValueError(
                "Final EvidenceManifest must be a superset of the R-snapshot artifacts; missing entry "
                f"(id={missing_one[0]!r}, kind={missing_one[1]!r}, storage_ref={missing_one[4]!r})"
            )

    except _SchemaArtifactInvalid as e:
        pointers: list[str] = [seal_ptr, evidence_ptr]
        for p in (gv_q_storage_ref, gv_r_storage_ref, r_snapshot_storage_ref):
            if isinstance(p, str) and p:
                pointers.append(p)
        # Stable, de-duplicated pointer list.
        seen: set[str] = set()
        pointers = [p for p in pointers if not (p in seen or seen.add(p))]
        return [
            CheckResult(
                check_id="S1",
                status="FAIL",
                category="FS-SCHEMA-ARTIFACT-INVALID",
                message=str(e),
                pointers=pointers,
                remediation_next_instruction="Do fix referenced artifact schema errors then re-run S.",
            )
        ]

    except ValueError as e:
        pointers = [seal_ptr, evidence_ptr]
        for p in (gv_q_storage_ref, gv_r_storage_ref, r_snapshot_storage_ref):
            if isinstance(p, str) and p:
                pointers.append(p)
        # Stable, de-duplicated pointer list.
        seen: set[str] = set()
        pointers = [p for p in pointers if not (p in seen or seen.add(p))]
        return [
            CheckResult(
                check_id="S1",
                status="FAIL",
                category="FS-BINDING-MISMATCH",
                message=str(e),
                pointers=pointers,
                remediation_next_instruction="Do correct the SealManifest and evidence bundle bindings then re-run S.",
            )
        ]

    # Tier sanity (already schema-locked, but keep deterministic message).
    tier = ctx.locked_spec.get("tier")
    tier_id = tier.get("tier_id") if isinstance(tier, dict) else None
    if tier_id != ctx.tier_id:
        return [
            CheckResult(
                check_id="S1",
                status="FAIL",
                category="FS-BINDING-MISMATCH",
                message="LockedSpec tier_id mismatch during context construction",
                pointers=[safe_relpath(repo_root, ctx.locked_spec_path)],
                remediation_next_instruction="Do regenerate LockedSpec deterministically then re-run S.",
            )
        ]

    return [CheckResult(check_id="S1", status="PASS", message="Schema contracts satisfied.", pointers=[])]
