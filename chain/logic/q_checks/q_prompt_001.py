from __future__ import annotations

from chain.logic.base import CheckResult

from .context import QCheckContext


def run(ctx: QCheckContext) -> list[CheckResult]:
    """Q-PROMPT-001 — Prompt bundle source allowlist (prompt injection prevention)."""

    if ctx.locked_spec is None:
        return [
            CheckResult(
                check_id="Q-PROMPT-001",
                status="FAIL",
                message="LockedSpec missing/invalid; cannot evaluate prompt source allowlist.",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-PROMPT-SOURCE-INVALID",
                remediation_next_instruction="Do update prompt_bundle_ref to reference allowed repo or update allowed_repo_refs then re-run Q.",
            )
        ]

    allowed_refs = ctx.locked_spec.get("allowed_repo_refs")

    # If allowlist not declared, PASS (no enforcement).
    if not isinstance(allowed_refs, list) or len(allowed_refs) == 0:
        return [
            CheckResult(
                check_id="Q-PROMPT-001",
                status="PASS",
                message="Q-PROMPT-001 satisfied: allowed_repo_refs not declared; no allowlist enforcement.",
                pointers=[str(ctx.locked_spec_path)],
            )
        ]

    prompt_ref = ctx.locked_spec.get("prompt_bundle_ref")
    if not isinstance(prompt_ref, dict):
        return [
            CheckResult(
                check_id="Q-PROMPT-001",
                status="FAIL",
                message="allowed_repo_refs is declared but prompt_bundle_ref is missing/invalid.",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-PROMPT-SOURCE-INVALID",
                remediation_next_instruction="Do update prompt_bundle_ref to reference allowed repo or update allowed_repo_refs then re-run Q.",
            )
        ]

    storage_ref = prompt_ref.get("storage_ref")
    if not isinstance(storage_ref, str) or not storage_ref.strip():
        return [
            CheckResult(
                check_id="Q-PROMPT-001",
                status="FAIL",
                message="prompt_bundle_ref.storage_ref is missing/empty.",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-PROMPT-SOURCE-INVALID",
                remediation_next_instruction="Do update prompt_bundle_ref to reference allowed repo or update allowed_repo_refs then re-run Q.",
            )
        ]

    sr = storage_ref.strip()
    ok = False
    for allowed in allowed_refs:
        if not isinstance(allowed, str) or not allowed.strip():
            continue
        a = allowed.strip().rstrip("/")
        # Spec requires sr starts with "<owner>/<repo>/".
        if a.count("/") == 1 and sr.startswith(a + "/"):
            ok = True
            break

    if not ok:
        return [
            CheckResult(
                check_id="Q-PROMPT-001",
                status="FAIL",
                message="prompt_bundle_ref.storage_ref is not under any allowed_repo_refs entry.",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-PROMPT-SOURCE-INVALID",
                remediation_next_instruction="Do update prompt_bundle_ref to reference allowed repo or update allowed_repo_refs then re-run Q.",
            )
        ]

    return [
        CheckResult(
            check_id="Q-PROMPT-001",
            status="PASS",
            message="Q-PROMPT-001 satisfied: prompt bundle storage_ref matches allowed repo refs.",
            pointers=[str(ctx.locked_spec_path)],
        )
    ]
