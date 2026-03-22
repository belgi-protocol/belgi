from __future__ import annotations

from typing import Any

import belgi.cli_app.commands.run as run_commands
from belgi.cli_app.registry import RunRegistry


def add_run_parsers(subparsers: Any) -> RunRegistry:
    p_run = subparsers.add_parser("run", help="[Tier A] Run workspace helper commands")
    p_run.add_argument("--repo", default=".", help="Repo root (default: .)")
    p_run.add_argument("--tier", choices=sorted(run_commands.ALLOWED_RUN_TIERS), help="Tier ID for deterministic run scaffolding")
    p_run.add_argument(
        "--workspace",
        default=run_commands.DEFAULT_WORKSPACE_REL,
        help=f"Repo-relative workspace root (default: {run_commands.DEFAULT_WORKSPACE_REL})",
    )
    p_run.add_argument(
        "--intent-spec",
        default=None,
        help='Repo-relative intent/spec source to bind into run_key (default: auto-generated "(auto)")',
    )
    p_run.add_argument(
        "--base-revision",
        default=None,
        help=(
            "Optional 40-hex base commit SHA used only when CI base env and upstream merge-base "
            "discovery are unavailable"
        ),
    )
    p_run.add_argument(
        "--toolchain-set-ref",
        default=None,
        help=(
            "Optional authoritative ToolchainSet object ref in "
            "<object_id>=<repo-relative-path> form on the shared run spine."
        ),
    )
    p_run.add_argument(
        "--toolchain-ref",
        action="append",
        default=[],
        help=(
            "Optional repeatable shorthand toolchain/accounting ref in "
            "<object_id>=<repo-relative-path> form on the shared run spine."
        ),
    )
    p_run.add_argument(
        "--tolerances-ref",
        default=None,
        help=(
            "Optional locked tolerances object ref in "
            "<object_id>=<repo-relative-path> form on the shared run spine."
        ),
    )
    p_run.add_argument(
        "--attestation-pubkey-ref",
        default=None,
        help="Tier-2/Tier-3 Operator Anchor: local-only <object_id>=<repo-relative-path> for the attestation public key.",
    )
    p_run.add_argument(
        "--seal-pubkey-ref",
        default=None,
        help="Tier-2/Tier-3 Operator Anchor: local-only <object_id>=<repo-relative-path> for the seal public key.",
    )
    p_run.add_argument(
        "--hotl-approval-ref",
        default=None,
        help="Tier-2/Tier-3 Operator Anchor: repo-relative HOTLApproval JSON to index into the pre-Q EvidenceManifest.",
    )
    p_run.add_argument(
        "--attestation-signing-key-ref",
        default=None,
        help="Tier-2/Tier-3 Operator Anchor: repo-relative Ed25519 seed file used by belgi verify-attestation.",
    )
    p_run.add_argument(
        "--seal-private-key-ref",
        default=None,
        help="Tier-2/Tier-3 Operator Anchor: repo-relative seal private key file used by chain.seal_bundle.",
    )
    p_run.add_argument(
        "--seal-signature-ref",
        default=None,
        help="Tier-2/Tier-3 Operator Anchor: repo-relative file containing a base64 seal signature verified by chain.seal_bundle.",
    )
    p_run.add_argument(
        "--genesis-seal-ref",
        default=None,
        help="Tier-3 evidence input: repo-relative GenesisSealPayload JSON staged outside Operator Anchors on the shared run spine.",
    )
    p_run.add_argument("--verbose", action="store_true", help="Verbose human output (deep paths and full open helpers)")
    run_subs = p_run.add_subparsers(dest="run_command", help="Run subcommand")

    p_run_new = run_subs.add_parser("new", help="Create deterministic run workspace from adopter template")
    p_run_new.add_argument("--repo", default=".", help="Repo root (default: .)")
    p_run_new.add_argument(
        "--workspace",
        default=run_commands.DEFAULT_WORKSPACE_REL,
        help=f"Repo-relative workspace root (default: {run_commands.DEFAULT_WORKSPACE_REL})",
    )
    p_run_new.add_argument("--run-id", required=True, help="Deterministic run ID")
    p_run_new.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing run workspace files deterministically",
    )

    return RunRegistry(root=p_run, new=p_run_new)
