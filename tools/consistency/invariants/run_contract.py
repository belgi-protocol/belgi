from __future__ import annotations

from tools.consistency import common as _common
from tools.consistency.model import InvariantResult


def check_cs_run_001(root: _common.Path) -> InvariantResult:
    """CS-RUN-001 — Shipped run object-ref CLI contract matches parser and command semantics."""

    targets = {
        "docs/operations/cli.md": [
            "--toolchain-set-ref <object_id>=<repo-relative-path>",
            "--toolchain-ref <object_id>=<repo-relative-path>",
            "--tolerances-ref <object_id>=<repo-relative-path>",
            "the referenced ToolchainSet file is a pre-lock operator input; accepted only as the current run's canonical run-local object path: `.belgi/runs/<run_id>/inputs/environment/toolchain-set.json`",
            "ToolchainSet member declaration paths must still point at actual repo-relative dependency/toolchain declaration surfaces in the evaluated revision truth envelope",
            "the referenced Tolerances file is a pre-lock operator input; accepted only as the current run's canonical run-local object path: `.belgi/runs/<run_id>/inputs/environment/tolerances.json`",
            "`Tolerances.tier_id` must match the selected tier",
            "may equal or tighten the selected tier ceilings, but BELGI rejects wider values",
            "do not mix `--toolchain-set-ref` with shorthand `--toolchain-ref` values",
            "`toolchain.main` is reserved for the built-in generated run toolchain input",
        ],
        "belgi/cli_app/parser/run.py": ['"--toolchain-set-ref"', '"--toolchain-ref"', '"--tolerances-ref"'],
        "belgi/cli_app/commands/run.py": [
            "def _resolve_run_environment_object_ref(",
            "must point to the current run canonical input:",
            "`Tolerances.tier_id` must match the selected tier",
            "may equal or tighten the selected tier ceilings, but BELGI rejects wider values",
            "stays within that selected tier",
            "do not mix --toolchain-set-ref with shorthand --toolchain-ref values",
            "--toolchain-ref id `toolchain.main` is reserved for the built-in run toolchain input",
            "--toolchain-set-ref id `toolchain.main` is reserved for the built-in run toolchain input",
        ],
    }
    violations: list[str] = []
    for rel, needles in targets.items():
        path = _common.repo_path(root, rel)
        if not path.exists():
            violations.append(f"missing file: {rel}")
            continue
        text = _common.read_text(path)
        for needle in needles:
            if needle not in text:
                violations.append(f"{rel} missing {needle!r}")

    if violations:
        return InvariantResult(
            "CS-RUN-001",
            "FAIL",
            ["docs/operations/cli.md", "belgi/cli_app/parser/run.py", "belgi/cli_app/commands/run.py"],
            "Keep shipped run object-ref flags and guardrails aligned across CLI docs, parser wiring, and command enforcement.",
            {"violations_sample": violations[:12], "violations_total": len(violations)},
        )

    return InvariantResult(
        "CS-RUN-001",
        "PASS",
        ["docs/operations/cli.md", "belgi/cli_app/parser/run.py", "belgi/cli_app/commands/run.py"],
        "",
    )

def check_cs_run_002(root: _common.Path) -> InvariantResult:
    """CS-RUN-002 — run new guidance and non-owner operator docs stay owner-bounded."""

    violations: list[str] = []
    command_path = _common.repo_path(root, "belgi/cli_app/commands/run.py")
    if not command_path.exists():
        violations.append("missing file: belgi/cli_app/commands/run.py")
    else:
        from belgi.cli_app.commands.run import (
            _render_adopter_readme,
            _render_runbook_template,
        )

        rendered_targets = {
            "belgi/cli_app/commands/run.py::README.md(.belgi)": (
                _render_adopter_readme(workspace_rel=".belgi"),
                [
                    ".belgi/runs/run-001/inputs/environment/toolchain-set.json",
                    ".belgi/runs/run-001/inputs/environment/tolerances.json",
                    "--toolchain-set-ref env.toolchains=.belgi/runs/run-001/inputs/environment/toolchain-set.json",
                    "--tolerances-ref tier.tolerances=.belgi/runs/run-001/inputs/environment/tolerances.json",
                    "Optional shared run object inputs:",
                    "`Tolerances.tier_id` must match the selected tier.",
                    "may equal or tighten the selected tier ceilings, but BELGI rejects wider values",
                ],
            ),
            "belgi/cli_app/commands/run.py::RUN.md(run-001)": (
                _render_runbook_template(run_id="run-001"),
                [
                    ".belgi/runs/run-001/inputs/environment/toolchain-set.json",
                    ".belgi/runs/run-001/inputs/environment/tolerances.json",
                    "Optional shared environment objects:",
                    "cat > .belgi/runs/run-001/inputs/environment/toolchain-set.json <<'JSON'",
                    "cat > .belgi/runs/run-001/inputs/environment/tolerances.json <<'JSON'",
                    "--toolchain-set-ref env.toolchains=.belgi/runs/run-001/inputs/environment/toolchain-set.json",
                    "--tolerances-ref tier.tolerances=.belgi/runs/run-001/inputs/environment/tolerances.json",
                    "`Tolerances.tier_id` must match the selected tier.",
                    "may equal or tighten the selected tier ceilings, but BELGI rejects wider values",
                    "stays within that selected tier",
                ],
            ),
        }
        forbidden_rendered = {
            "belgi/cli_app/commands/run.py::README.md(.belgi)": [
                ".belgi/runs/run-001/toolchain.json",
                ".belgi/runs/run-001/tolerances.json",
            ],
            "belgi/cli_app/commands/run.py::RUN.md(run-001)": [
                ".belgi/runs/run-001/toolchain.json",
                ".belgi/runs/run-001/tolerances.json",
            ],
        }
        for rel, (text, needles) in rendered_targets.items():
            for needle in needles:
                if needle not in text:
                    violations.append(f"{rel} missing {needle!r}")
        for rel, forbidden in forbidden_rendered.items():
            text = rendered_targets[rel][0]
            for needle in forbidden:
                if needle in text:
                    violations.append(f"{rel} still advertises stale placeholder {needle!r}")

    doc_targets = {
        "docs/operations/running-belgi.md": [
            ".belgi/runs/<run_id>/inputs/environment/toolchain-set.json",
            ".belgi/runs/<run_id>/inputs/environment/tolerances.json",
            "`belgi run new`",
            "docs/operations/cli.md",
            "docs/operations/operator-anchors.md",
            "docs/operations/evidence-bundles.md",
            "../../CANONICALS.md",
            "`--toolchain-set` / `--tolerances`",
        ],
        "docs/operations/operator-anchors.md": [
            ".belgi/runs/<run_id>/inputs/anchors/approvals/",
            ".belgi/runs/<run_id>/inputs/anchors/keys/",
            ".belgi/runs/<run_id>/inputs/anchors/signing/",
            ".belgi/runs/<run_id>/inputs/evidence/genesis_seal.json",
            "docs/operations/cli.md",
            "docs/operations/evidence-bundles.md",
            "../../CANONICALS.md",
        ],
    }
    forbidden_docs = {
        "docs/operations/running-belgi.md": [
            ".belgi/runs/<run_id>/toolchain.json",
            ".belgi/runs/<run_id>/tolerances.json",
            "The explicit CLI flags remain repo-relative and do not require a hardcoded workspace location.",
            "--toolchain-set-ref <object_id>=<repo-relative-path>",
            "--tolerances-ref <object_id>=<repo-relative-path>",
            "--attestation-pubkey-ref <object_id>=<repo-relative-path>",
            "--seal-pubkey-ref <object_id>=<repo-relative-path>",
            "--hotl-approval-ref <repo-relative-path>",
            "--attestation-signing-key-ref <repo-relative-path>",
            "--seal-private-key-ref <repo-relative-path>",
            "--seal-signature-ref <repo-relative-path>",
            "--genesis-seal-ref <repo-relative-path>",
            "Tier-3 canonical authority is rooted in `belgi/anchor/v1/TrustAnchor.json`.",
            "`belgi/genesis/GenesisSealPayload.json` remains a historical repo-local genesis reference payload and is not authoritative for canonical Tier-3 trust-anchor verification.",
            "Internet publication of the Tier-3 trust anchor is secondary only; the repo artifact is the primary authority surface.",
        ],
        "docs/operations/operator-anchors.md": [
            "belgi run \\",
            "--repo .",
            "--tier tier-2",
            "--tier tier-3",
            "`belgi/anchor/v1/TrustAnchor.json` is not an Operator Anchor.",
            "`TrustAnchor.json` remains the canonical Tier-3 authority artifact.",
        ],
    }
    for rel, needles in doc_targets.items():
        path = _common.repo_path(root, rel)
        if not path.exists():
            violations.append(f"missing file: {rel}")
            continue
        text = _common.read_text(path)
        for needle in needles:
            if needle not in text:
                violations.append(f"{rel} missing {needle!r}")
    for rel, forbidden in forbidden_docs.items():
        path = _common.repo_path(root, rel)
        if not path.exists():
            continue
        text = _common.read_text(path)
        for needle in forbidden:
            if needle in text:
                violations.append(f"{rel} still advertises stale placeholder {needle!r}")

    if violations:
        return InvariantResult(
            "CS-RUN-002",
            "FAIL",
            [
                "belgi/cli_app/commands/run.py",
                "docs/operations/cli.md",
                "docs/operations/running-belgi.md",
                "docs/operations/operator-anchors.md",
            ],
            "Keep run new guidance authoritative, and keep non-owner operator docs pointer-bounded to the CLI owner instead of duplicating full shipped flag catalogs.",
            {"violations_sample": violations[:12], "violations_total": len(violations)},
        )

    return InvariantResult(
        "CS-RUN-002",
        "PASS",
        [
            "belgi/cli_app/commands/run.py",
            "docs/operations/cli.md",
            "docs/operations/running-belgi.md",
            "docs/operations/operator-anchors.md",
        ],
        "",
    )
