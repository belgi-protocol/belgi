from __future__ import annotations

import argparse
import contextlib
import importlib
import sys
from collections.abc import Iterator

from belgi.cli_app import render as cli_render

STAGE_FORWARDER_NOTE = (
    "Strict forwarder to repo-local canonical chain entrypoints (`python -m chain.*`). "
    "May be unavailable in wheel-only installs where `chain/*` is not present."
)


@contextlib.contextmanager
def _patched_argv(prog: str, argv: list[str]) -> Iterator[None]:
    original_argv = list(sys.argv)
    try:
        sys.argv = [prog, *argv]
        yield
    finally:
        sys.argv = original_argv


def _invoke_module_main(module_name: str, argv: list[str]) -> int:
    module = importlib.import_module(module_name)
    main_fn = getattr(module, "main", None)
    if not callable(main_fn):
        raise RuntimeError(f"{module_name} does not expose callable main()")

    try:
        with _patched_argv(module_name, argv):
            rc = main_fn()
    except SystemExit as e:
        if isinstance(e.code, int):
            return int(e.code)
        return 3

    if not isinstance(rc, int):
        raise RuntimeError(f"{module_name}.main() returned non-int exit code: {type(rc).__name__}")
    return int(rc)


def _run_stage_forwarder(
    *,
    stage_name: str,
    parser: argparse.ArgumentParser,
    module_name: str,
    forward_args: list[str],
) -> int:
    if not forward_args:
        return cli_render._emit_cli_user_error_result(
            primary_reason=f"missing stage arguments; see `belgi stage {stage_name} --help`",
            parser=parser,
        )

    try:
        raw_rc = _invoke_module_main(module_name, forward_args)
    except ModuleNotFoundError as e:
        missing_name = str(getattr(e, "name", "") or "").strip()
        message = str(e)
        if (
            missing_name == "chain"
            or missing_name.startswith("chain.")
            or "No module named 'chain'" in message
            or 'No module named "chain"' in message
        ):
            return cli_render._emit_cli_user_error_result(
                primary_reason=(
                    "repo-local stage module missing; run inside BELGI source checkout or "
                    "use canonical python -m chain.<...> invocation"
                ),
                parser=parser,
            )
        print(f"[belgi stage {stage_name}] ERROR: {e}", file=sys.stderr)
        print(f"[belgi stage {stage_name}] Remediation: run `belgi stage {stage_name} --help`.", file=sys.stderr)
        return cli_render.RC_INTERNAL_ERROR
    except Exception as e:
        print(f"[belgi stage {stage_name}] ERROR: {e}", file=sys.stderr)
        print(f"[belgi stage {stage_name}] Remediation: run `belgi stage {stage_name} --help`.", file=sys.stderr)
        return cli_render.RC_INTERNAL_ERROR

    normalized_rc = cli_render._normalize_cli_exit_code(raw_rc, surface="stage_forwarder")
    if raw_rc in (2, 3):
        print(f"[belgi stage {stage_name}] Remediation: run `belgi stage {stage_name} --help`.", file=sys.stderr)
    return normalized_rc


def run_c1(*, parser: argparse.ArgumentParser, forward_args: list[str]) -> int:
    return _run_stage_forwarder(
        stage_name="c1",
        parser=parser,
        module_name="chain.compiler_c1_intent",
        forward_args=forward_args,
    )


def run_q(*, parser: argparse.ArgumentParser, forward_args: list[str]) -> int:
    return _run_stage_forwarder(
        stage_name="q",
        parser=parser,
        module_name="chain.gate_q_verify",
        forward_args=forward_args,
    )


def run_r(*, parser: argparse.ArgumentParser, forward_args: list[str]) -> int:
    return _run_stage_forwarder(
        stage_name="r",
        parser=parser,
        module_name="chain.gate_r_verify",
        forward_args=forward_args,
    )


def run_c3(*, parser: argparse.ArgumentParser, forward_args: list[str]) -> int:
    return _run_stage_forwarder(
        stage_name="c3",
        parser=parser,
        module_name="chain.compiler_c3_docs",
        forward_args=forward_args,
    )


def run_s_seal(*, parser: argparse.ArgumentParser, forward_args: list[str]) -> int:
    return _run_stage_forwarder(
        stage_name="s seal",
        parser=parser,
        module_name="chain.seal_bundle",
        forward_args=forward_args,
    )


def run_s_verify(*, parser: argparse.ArgumentParser, forward_args: list[str]) -> int:
    return _run_stage_forwarder(
        stage_name="s verify",
        parser=parser,
        module_name="chain.gate_s_verify",
        forward_args=forward_args,
    )
