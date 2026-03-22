from __future__ import annotations

import argparse
from typing import NoReturn

import belgi.cli_app.commands.run as run_commands
from belgi.cli_app.parser.bundle import add_bundle_parsers
from belgi.cli_app.parser.pack import add_pack_parsers
from belgi.cli_app.parser.policy import add_policy_parsers
from belgi.cli_app.parser.run import add_run_parsers
from belgi.cli_app.parser.stage import add_stage_parsers
from belgi.cli_app.parser.verify import add_verify_parser
from belgi.cli_app.parser.waiver import add_waiver_parsers
from belgi.cli_app.registry import CliRegistry, ManifestRegistry


class CliUsageError(Exception):
    def __init__(self, message: str, parser: argparse.ArgumentParser | None) -> None:
        super().__init__(message)
        self.message = str(message or "").strip()
        self.parser = parser


class BelgiArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise CliUsageError(message, self)


def build_cli_registry() -> CliRegistry:
    parser = BelgiArgumentParser(
        prog="belgi",
        description="BELGI CLI — Protocol pack management and evidence generation tools",
    )
    subparsers = parser.add_subparsers(dest="command", help="Subcommand")

    p_about = subparsers.add_parser("about", help="[Tier A] Print package identity info")

    p_init = subparsers.add_parser("init", help="[Tier A] Initialize BELGI adopter defaults in a repository")
    p_init.add_argument("--repo", default=".", help="Repo root (default: .)")
    p_init.add_argument(
        "--workspace",
        default=run_commands.DEFAULT_WORKSPACE_REL,
        help=f"Repo-relative workspace root (default: {run_commands.DEFAULT_WORKSPACE_REL})",
    )
    p_init.add_argument(
        "--refresh-pin",
        action="store_true",
        help="Explicitly refresh protocol pack pins in adopter.toml (and overlay manifest if present)",
    )

    p_manifest = subparsers.add_parser("manifest", help="[Tier C] EvidenceManifest mutation helpers")
    manifest_subs = p_manifest.add_subparsers(dest="manifest_command", help="Manifest subcommand")
    p_manifest_add = manifest_subs.add_parser("add", help="Add or update an artifact entry in EvidenceManifest")
    p_manifest_add.add_argument("--repo", default=".", help="Repo root (default: .)")
    p_manifest_add.add_argument("--manifest", required=True, help="Repo-relative path to EvidenceManifest.json")
    p_manifest_add.add_argument("--artifact", required=True, help="Repo-relative path to artifact file")
    p_manifest_add.add_argument("--kind", required=True, help="Artifact kind (must exist in schema enum)")
    p_manifest_add.add_argument("--id", dest="artifact_id", required=True, help="Artifact id")
    p_manifest_add.add_argument("--media-type", required=True, help="Artifact media_type")
    p_manifest_add.add_argument("--produced-by", required=True, help="Artifact produced_by")

    p_supplychain_scan = subparsers.add_parser(
        "supplychain-scan",
        help="[Tier C] Run supplychain scan and produce policy.supplychain artifact",
    )
    p_supplychain_scan.add_argument("--repo", default=".", help="Repo root")
    p_supplychain_scan.add_argument(
        "--run-id",
        default="unknown",
        help="Run ID to embed in the PolicyReportPayload (default: unknown)",
    )
    p_supplychain_scan.add_argument(
        "--base-revision",
        default="HEAD~1",
        help="Git base revision for declared change accounting (default: HEAD~1)",
    )
    p_supplychain_scan.add_argument(
        "--evaluated-revision",
        default="HEAD",
        help="Git evaluated revision for declared change accounting (default: HEAD)",
    )
    p_supplychain_scan.add_argument(
        "--pinned-toolchain-ref",
        action="append",
        default=[],
        help="Declared pinned toolchain ref in ID=repo/relative/path form (repeatable)",
    )
    p_supplychain_scan.add_argument(
        "--out",
        default="out/policy-supplychain.json",
        help="Output JSON path (default: out/policy-supplychain.json)",
    )
    p_supplychain_scan.add_argument("--deterministic", action="store_true", help="Use fixed timestamps for deterministic output")

    p_adversarial_scan = subparsers.add_parser(
        "adversarial-scan",
        help="[Tier C] Run adversarial scan and produce policy.adversarial_scan artifact",
    )
    p_adversarial_scan.add_argument("--repo", default=".", help="Repo root")
    p_adversarial_scan.add_argument(
        "--run-id",
        default="unknown",
        help="Run ID to embed in the PolicyReportPayload (default: unknown)",
    )
    p_adversarial_scan.add_argument(
        "--base-revision",
        default="HEAD~1",
        help="Git base revision for diff-scoped scanning (default: HEAD~1)",
    )
    p_adversarial_scan.add_argument(
        "--evaluated-revision",
        default="HEAD",
        help="Git evaluated revision for diff-scoped scanning (default: HEAD)",
    )
    p_adversarial_scan.add_argument(
        "--out",
        default="out/policy-adversarial-scan.json",
        help="Output JSON path (default: out/policy-adversarial-scan.json)",
    )
    p_adversarial_scan.add_argument("--deterministic", action="store_true", help="Use fixed timestamps for deterministic output")

    return CliRegistry(
        parser=parser,
        about=p_about,
        init=p_init,
        manifest=ManifestRegistry(root=p_manifest, add=p_manifest_add),
        supplychain_scan=p_supplychain_scan,
        adversarial_scan=p_adversarial_scan,
        run=add_run_parsers(subparsers),
        verify=add_verify_parser(subparsers),
        waiver=add_waiver_parsers(subparsers),
        bundle=add_bundle_parsers(subparsers),
        pack=add_pack_parsers(subparsers),
        policy=add_policy_parsers(subparsers),
        stage=add_stage_parsers(subparsers),
    )
