from __future__ import annotations

from typing import Any

from belgi.cli_app.registry import BundleRegistry


def add_bundle_parsers(subparsers: Any) -> BundleRegistry:
    p_bundle = subparsers.add_parser("bundle", help="[Tier B] Evidence bundle commands")
    bundle_subs = p_bundle.add_subparsers(dest="bundle_command", help="Bundle subcommand")

    p_bundle_check = bundle_subs.add_parser("check", help="Check an evidence bundle (demo-grade checker)")
    p_bundle_check.add_argument("--in", dest="input", required=True, help="Bundle directory to check")
    p_bundle_check.add_argument(
        "--demo",
        action="store_true",
        help="Acknowledge this is a demo-grade checker (required)",
    )
    p_bundle_check.add_argument("--verbose", action="store_true", help="Verbose output")

    return BundleRegistry(root=p_bundle, check=p_bundle_check)
