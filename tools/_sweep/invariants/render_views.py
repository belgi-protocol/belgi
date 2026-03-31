from __future__ import annotations

from tools._shared import common as _common
from tools._sweep.model import InvariantResult


def check_cs_render_001(root: _common.Path) -> InvariantResult:
    """CS-RENDER-001 — Render targets must not drift.

    Verifies that all registered render targets (JSON canonical → MD generated view)
    have no drift. Uses tools/render.py check_target_drift() for comparison.
    """
    # Import render module (fail-closed if unavailable)
    try:
        from tools.render import (
            check_target_drift,
            get_all_target_names,
            get_target_evidence_files,
        )
    except ImportError as e:
        return InvariantResult(
            "CS-RENDER-001",
            "FAIL",
            [],
            f"Cannot import tools/render.py: {e}. Ensure render.py exists.",
        )

    target_names = get_all_target_names()
    if not target_names:
        # No registered targets is valid (no drift possible)
        return InvariantResult(
            "CS-RENDER-001",
            "PASS",
            ["tools/render.py"],
            "",
        )

    drift_targets: list[str] = []
    evidence: set[str] = {"tools/render.py"}

    for target_name in target_names:
        # Add target-specific evidence files
        evidence.update(get_target_evidence_files(target_name))
        has_drift, msg = check_target_drift(root, target_name)
        if has_drift:
            drift_targets.append(target_name)

    if drift_targets:
        regen_cmds = [f"python -m tools.render {t} --repo ." for t in drift_targets]
        return InvariantResult(
            "CS-RENDER-001",
            "FAIL",
            sorted(evidence),
            f"Render drift detected for: {', '.join(drift_targets)}. Regenerate: {'; '.join(regen_cmds)}",
        )

    return InvariantResult(
        "CS-RENDER-001",
        "PASS",
        sorted(evidence),
        "",
    )
