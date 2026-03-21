from __future__ import annotations

import argparse

import belgi.cli_app.commands.bundle as bundle_commands
import belgi.cli_app.commands.pack as pack_commands
import belgi.cli_app.commands.policy as policy_commands
import belgi.cli_app.commands.run as run_commands
import belgi.cli_app.commands.stage as stage_commands
import belgi.cli_app.commands.verify as verify_commands
import belgi.cli_app.commands.waiver as waiver_commands
from belgi.cli_app import render as cli_render
from belgi.cli_app.parser.root import CliUsageError, build_cli_registry


def main(argv: list[str] | None = None) -> int:
    registry = build_cli_registry()

    try:
        args, unknown_args = registry.parser.parse_known_args(argv)
    except CliUsageError as e:
        return cli_render._emit_cli_user_error_result(
            primary_reason=e.message or "invalid CLI usage",
            parser=e.parser if isinstance(e.parser, argparse.ArgumentParser) else registry.parser,
        )
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 1
        if code == 0:
            return cli_render.RC_GO
        return cli_render._emit_cli_user_error_result(
            primary_reason=f"argument parsing failed (rc={code})",
            parser=registry.parser,
        )

    if args.command == "stage":
        stage_forward_args = [str(x) for x in unknown_args]
    elif unknown_args:
        return cli_render._emit_cli_user_error_result(
            primary_reason=f"unrecognized arguments: {' '.join(str(x) for x in unknown_args)}",
            parser=registry.parser,
        )
    else:
        stage_forward_args = []

    if args.command == "about":
        rc = run_commands.cmd_about(args)
    elif args.command == "init":
        rc = run_commands.cmd_init(args)
    elif args.command == "manifest":
        if args.manifest_command == "add":
            rc = bundle_commands.cmd_manifest_add(args)
        else:
            rc = cli_render._emit_cli_user_error_result(
                primary_reason="missing manifest subcommand",
                parser=registry.manifest.root,
                help_to_stderr=True,
            )
    elif args.command == "supplychain-scan":
        rc = policy_commands.cmd_supplychain_scan(args)
    elif args.command == "adversarial-scan":
        rc = policy_commands.cmd_adversarial_scan(args)
    elif args.command == "run":
        if args.run_command == "new":
            rc = run_commands.cmd_run_new(args)
        elif getattr(args, "tier", None):
            rc = run_commands.cmd_run(args)
        else:
            rc = cli_render._emit_cli_user_error_result(
                primary_reason="missing run mode: provide `run new` or `run --tier`",
                parser=registry.run.root,
                help_to_stderr=True,
            )
    elif args.command == "verify":
        rc = verify_commands.cmd_verify(args)
    elif args.command == "waiver":
        if args.waiver_command == "new":
            rc = waiver_commands.cmd_waiver_new(args)
        elif args.waiver_command == "apply":
            rc = waiver_commands.cmd_waiver_apply(args)
        else:
            rc = cli_render._emit_cli_user_error_result(
                primary_reason="missing waiver subcommand",
                parser=registry.waiver.root,
                help_to_stderr=True,
            )
    elif args.command == "bundle":
        if args.bundle_command == "check":
            rc = bundle_commands.cmd_bundle_check(args)
        else:
            rc = cli_render._emit_cli_user_error_result(
                primary_reason="missing bundle subcommand",
                parser=registry.bundle.root,
                help_to_stderr=True,
            )
    elif args.command == "pack":
        if args.pack_command == "build":
            if not args.input:
                rc = cli_render._emit_cli_user_error_result(
                    primary_reason="--in required for `belgi pack build`",
                    parser=registry.pack.build,
                )
            else:
                rc = pack_commands.cmd_pack_build(args)
        elif args.pack_command == "verify":
            rc = pack_commands.cmd_pack_verify(args)
        else:
            rc = cli_render._emit_cli_user_error_result(
                primary_reason="missing pack subcommand",
                parser=registry.pack.root,
                help_to_stderr=True,
            )
    elif args.command == "policy":
        if args.policy_command == "stub":
            rc = policy_commands.cmd_policy_stub(args)
        elif args.policy_command == "check-overlay":
            rc = policy_commands.cmd_policy_check_overlay(args)
        else:
            rc = cli_render._emit_cli_user_error_result(
                primary_reason="missing policy subcommand",
                parser=registry.policy.root,
                help_to_stderr=True,
            )
    elif args.command == "stage":
        if args.stage_command == "c1":
            rc = stage_commands.run_c1(parser=registry.stage.c1, forward_args=stage_forward_args)
        elif args.stage_command == "q":
            rc = stage_commands.run_q(parser=registry.stage.q, forward_args=stage_forward_args)
        elif args.stage_command == "r":
            rc = stage_commands.run_r(parser=registry.stage.r, forward_args=stage_forward_args)
        elif args.stage_command == "c3":
            rc = stage_commands.run_c3(parser=registry.stage.c3, forward_args=stage_forward_args)
        elif args.stage_command == "s":
            if args.stage_s_command == "seal":
                rc = stage_commands.run_s_seal(parser=registry.stage.s.seal, forward_args=stage_forward_args)
            elif args.stage_s_command == "verify":
                rc = stage_commands.run_s_verify(parser=registry.stage.s.verify, forward_args=stage_forward_args)
            else:
                rc = cli_render._emit_cli_user_error_result(
                    primary_reason="missing stage s subcommand",
                    parser=registry.stage.s.root,
                    help_to_stderr=True,
                )
        else:
            rc = cli_render._emit_cli_user_error_result(
                primary_reason="missing stage subcommand",
                parser=registry.stage.root,
                help_to_stderr=True,
            )
    else:
        rc = cli_render._emit_cli_user_error_result(
            primary_reason="missing command",
            parser=registry.parser,
            help_to_stderr=True,
        )

    return cli_render._normalize_cli_exit_code(int(rc))
