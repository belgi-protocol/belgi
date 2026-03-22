from __future__ import annotations

from typing import Any

import belgi.cli_app.commands.run as run_commands
from belgi.cli_app.registry import WaiverRegistry


def add_waiver_parsers(subparsers: Any) -> WaiverRegistry:
    p_waiver = subparsers.add_parser("waiver", help="[Tier A] Waiver wizard helpers (human-controlled)")
    waiver_subs = p_waiver.add_subparsers(dest="waiver_command", help="Waiver subcommand")

    p_waiver_new = waiver_subs.add_parser("new", help="Create a schema-valid waiver draft JSON")
    p_waiver_new.add_argument("--repo", default=".", help="Repo root (default: .)")
    p_waiver_new.add_argument(
        "--workspace",
        default=run_commands.DEFAULT_WORKSPACE_REL,
        help=f"Repo-relative workspace root (default: {run_commands.DEFAULT_WORKSPACE_REL})",
    )
    p_waiver_new.add_argument("--run-id", required=True, help="Run workspace identifier")
    p_waiver_new.add_argument("--gate", required=True, choices=("Q", "R"), help="Gate identifier")
    p_waiver_new.add_argument("--rule-id", required=True, help="Rule identifier for this waiver")
    p_waiver_new.add_argument("--waiver-id", required=True, help="Deterministic waiver id")
    p_waiver_new.add_argument("--expires-at", required=True, help="RFC3339 expiry timestamp")
    p_waiver_new.add_argument(
        "--out",
        default=None,
        help="Optional repo-relative output path (default: .belgi/runs/<run_id>/inputs/waivers/<waiver_id>.json)",
    )
    p_waiver_new.add_argument("--force", action="store_true", help="Overwrite output if it already exists")

    p_waiver_apply = waiver_subs.add_parser(
        "apply", help="Record a waiver reference in run-local waiver inputs for C1 consumption"
    )
    p_waiver_apply.add_argument("--repo", default=".", help="Repo root (default: .)")
    p_waiver_apply.add_argument(
        "--workspace",
        default=run_commands.DEFAULT_WORKSPACE_REL,
        help=f"Repo-relative workspace root (default: {run_commands.DEFAULT_WORKSPACE_REL})",
    )
    p_waiver_apply.add_argument("--run-id", required=True, help="Run workspace identifier")
    p_waiver_apply.add_argument("--waiver", required=True, help="Repo-relative path to waiver JSON")

    return WaiverRegistry(root=p_waiver, new=p_waiver_new, apply=p_waiver_apply)
