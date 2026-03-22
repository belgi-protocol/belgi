from __future__ import annotations

from typing import Any

from belgi.cli_app.registry import PolicyRegistry


def add_policy_parsers(subparsers: Any) -> PolicyRegistry:
    p_policy = subparsers.add_parser("policy", help="[Tier B] Policy helper commands")
    policy_subs = p_policy.add_subparsers(dest="policy_command", help="Policy subcommand")

    p_policy_stub = policy_subs.add_parser("stub", help="Generate deterministic PolicyReportPayload stub JSON")
    p_policy_stub.add_argument("--out", required=True, help="Output JSON path")
    p_policy_stub.add_argument("--run-id", required=True, help="Run ID for PolicyReportPayload")
    p_policy_stub.add_argument(
        "--check-id",
        action="append",
        default=[],
        help="Check ID to mark as passed (repeatable; at least one required)",
    )
    p_policy_stub.add_argument(
        "--generated-at",
        default="1970-01-01T00:00:00Z",
        help="RFC3339 generated_at value (default: 1970-01-01T00:00:00Z)",
    )

    p_policy_check_overlay = policy_subs.add_parser(
        "check-overlay",
        help="Evaluate adopter overlay requirements against an EvidenceManifest (overlay-only preflight)",
    )
    p_policy_check_overlay.add_argument("--repo", default=".", help="Repo root")
    p_policy_check_overlay.add_argument(
        "--evidence-manifest",
        required=True,
        help="Repo-relative path to EvidenceManifest.json",
    )
    p_policy_check_overlay.add_argument(
        "--overlay",
        required=True,
        help="Repo-relative path to overlay dir or DomainPackManifest.json",
    )

    return PolicyRegistry(root=p_policy, stub=p_policy_stub, check_overlay=p_policy_check_overlay)
