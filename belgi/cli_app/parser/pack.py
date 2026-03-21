from __future__ import annotations

from typing import Any

from belgi.cli_app.registry import PackRegistry


def add_pack_parsers(subparsers: Any) -> PackRegistry:
    p_pack = subparsers.add_parser("pack", help="[Tier B] Protocol pack management commands")
    pack_subs = p_pack.add_subparsers(dest="pack_command", help="Pack subcommand")

    p_pack_build = pack_subs.add_parser("build", help="Build/update protocol pack manifest")
    p_pack_build.add_argument("--in", dest="input", help="Input pack directory")
    p_pack_build.add_argument("--out", dest="output", help="Output directory (default: same as --in)")
    p_pack_build.add_argument("--pack-name", default="belgi-protocol-pack-v1", help="Pack name for manifest")

    p_pack_verify = pack_subs.add_parser("verify", help="Verify protocol pack manifest")
    p_pack_verify.add_argument("--in", dest="input", help="Pack directory to verify")
    p_pack_verify.add_argument("--builtin", action="store_true", help="Verify builtin pack from installed package")
    p_pack_verify.add_argument("--verbose", action="store_true", help="Verbose output")

    return PackRegistry(root=p_pack, build=p_pack_build, verify=p_pack_verify)
