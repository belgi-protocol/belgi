from __future__ import annotations

import argparse
from typing import Any

from belgi.cli_app.commands import stage as stage_commands
from belgi.cli_app.registry import StageRegistry, StageSRegistry


def add_stage_parsers(subparsers: Any) -> StageRegistry:
    p_stage = subparsers.add_parser(
        "stage",
        help="[Tier C] Run repo-local stage forwarders (thin wrappers only)",
        description=stage_commands.STAGE_FORWARDER_NOTE,
        epilog=(
            "Use `belgi run` for end-to-end canonical spine execution. "
            "Use `belgi stage` for targeted stage operations."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    stage_subs = p_stage.add_subparsers(dest="stage_command", help="Stage subcommand")

    p_stage_c1 = stage_subs.add_parser(
        "c1",
        help="Forward to chain.compiler_c1_intent",
        epilog=(
            f"{stage_commands.STAGE_FORWARDER_NOTE}\n\n"
            "Abbreviated example (source checkout): "
            "belgi stage c1 --repo . --intent-spec IntentSpec.core.md --out out/LockedSpec.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p_stage_q = stage_subs.add_parser(
        "q",
        help="Forward to chain.gate_q_verify",
        epilog=(
            f"{stage_commands.STAGE_FORWARDER_NOTE}\n\n"
            "Abbreviated example (source checkout): "
            "belgi stage q --repo . --intent-spec IntentSpec.core.md "
            "--locked-spec out/LockedSpec.json --evidence-manifest out/EvidenceManifest.json "
            "--out out/GateVerdict.Q.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p_stage_r = stage_subs.add_parser(
        "r",
        help="Forward to chain.gate_r_verify",
        epilog=(
            f"{stage_commands.STAGE_FORWARDER_NOTE}\n\n"
            "Abbreviated example (source checkout): "
            "belgi stage r --repo . --locked-spec out/LockedSpec.json "
            "--gate-q-verdict out/GateVerdict.Q.json --evidence-manifest out/EvidenceManifest.json "
            "--evaluated-revision <sha40> --out out/verify_report.R.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p_stage_c3 = stage_subs.add_parser(
        "c3",
        help="Forward to chain.compiler_c3_docs",
        epilog=(
            f"{stage_commands.STAGE_FORWARDER_NOTE}\n\n"
            "Abbreviated example (source checkout): "
            "belgi stage c3 --repo . --locked-spec out/LockedSpec.json "
            "--gate-q-verdict out/GateVerdict.Q.json --gate-r-verdict out/GateVerdict.R.json "
            "--r-snapshot-manifest out/EvidenceManifest.R.json --out-final-manifest out/EvidenceManifest.json "
            "--out-log docs/docs_compilation_log.json --out-docs docs/chain_of_changes.md "
            "--out-bundle-dir out/bundle --out-bundle-root-sha out/bundle_root.sha256 "
            "--prompt-block-hashes out/prompt_block_hashes.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p_stage_s = stage_subs.add_parser(
        "s",
        help="Stage S subcommands (seal/verify)",
        description=stage_commands.STAGE_FORWARDER_NOTE,
        epilog="Choose `seal` or `verify` for targeted Stage S operations.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    stage_s_subs = p_stage_s.add_subparsers(dest="stage_s_command", help="S subcommand")

    p_stage_s_seal = stage_s_subs.add_parser(
        "seal",
        help="Forward to chain.seal_bundle",
        epilog=(
            f"{stage_commands.STAGE_FORWARDER_NOTE}\n\n"
            "Abbreviated example (source checkout): "
            "belgi stage s seal --repo . --locked-spec out/LockedSpec.json "
            "--gate-q-verdict out/GateVerdict.Q.json --gate-r-verdict out/GateVerdict.R.json "
            "--evidence-manifest out/EvidenceManifest.json --final-commit-sha <sha40> "
            "--sealed-at 1970-01-01T00:00:00Z --signer human:ops --out out/SealManifest.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p_stage_s_verify = stage_s_subs.add_parser(
        "verify",
        help="Forward to chain.gate_s_verify",
        epilog=(
            f"{stage_commands.STAGE_FORWARDER_NOTE}\n\n"
            "Abbreviated example (source checkout): "
            "belgi stage s verify --repo . --locked-spec out/LockedSpec.json "
            "--seal-manifest out/SealManifest.json --evidence-manifest out/EvidenceManifest.json "
            "--out out/GateVerdict.S.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    return StageRegistry(
        root=p_stage,
        c1=p_stage_c1,
        q=p_stage_q,
        r=p_stage_r,
        c3=p_stage_c3,
        s=StageSRegistry(root=p_stage_s, seal=p_stage_s_seal, verify=p_stage_s_verify),
    )
