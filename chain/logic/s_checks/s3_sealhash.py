from __future__ import annotations

from belgi.core.jail import safe_relpath
from chain.logic.base import CheckResult
from chain.logic.s_checks.context import SCheckContext


def _compute_seal_hash(seal_manifest: dict) -> str:
    # Reuse the canonical implementation.
    from chain.seal_bundle import _seal_hash  # type: ignore

    return str(_seal_hash(seal_manifest))


def run(ctx: SCheckContext) -> list[CheckResult]:
    repo_root = ctx.repo_root
    sm = ctx.seal_manifest

    declared = str(sm.get("seal_hash") or "").strip().lower()
    computed = _compute_seal_hash(sm).strip().lower()

    if not declared or declared != computed:
        return [
            CheckResult(
                check_id="S3",
                status="FAIL",
                category="FS-SEALHASH-MISMATCH",
                message=f"seal_hash mismatch: declared {declared or '<missing>'}, computed {computed}",
                pointers=[safe_relpath(repo_root, ctx.seal_manifest_path)],
                remediation_next_instruction="Do regenerate SealManifest so seal_hash matches the normative algorithm then re-run S.",
            )
        ]

    return [CheckResult(check_id="S3", status="PASS", message="seal_hash verifies.", pointers=[])]
