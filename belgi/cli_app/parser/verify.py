from __future__ import annotations

import argparse
from typing import Any

import belgi.cli_app.commands.run as run_commands


def add_verify_parser(subparsers: Any) -> argparse.ArgumentParser:
    p_verify = subparsers.add_parser("verify", help="[Tier A] Verify deterministic run summaries and manifests")
    p_verify.add_argument("--repo", default=".", help="Repo root (default: .)")
    p_verify.add_argument(
        "--in",
        dest="input",
        default=None,
        help="Repo-relative run summary, attempt directory, run_key directory, or runs root",
    )
    p_verify.add_argument(
        "--workspace",
        default=run_commands.DEFAULT_WORKSPACE_REL,
        help=f"Repo-relative workspace root (default: {run_commands.DEFAULT_WORKSPACE_REL})",
    )
    p_verify.add_argument(
        "--run-key",
        default=None,
        help="Explicit run_key to verify (64 lowercase hex)",
    )
    p_verify.add_argument(
        "--attempt-id",
        default=None,
        help="Explicit attempt id to verify (default: latest attempt for run_key)",
    )
    p_verify.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose human output (full paths and expanded open helpers)",
    )
    return p_verify
