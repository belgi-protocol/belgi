from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Literal

RC_GO = 0
RC_NO_GO = 10
RC_USER_ERROR = 20
RC_INTERNAL_ERROR = 30
_ANSI_RESET = "\x1b[0m"
_ANSI_STATUS_COLORS: dict[str, str] = {
    "GO": "\x1b[32m",
    "NO-GO": "\x1b[31m",
    "USER_ERROR": "\x1b[33m",
    "INTERNAL_ERROR": "\x1b[35m",
}


def _emit_machine_result(
    *,
    ok: bool,
    verdict: str,
    primary_reason: str,
    tier_id: str | None,
    run_key: str | None,
    attempt_id: str | None,
    waivers_applied_count: int | None = None,
    waivers_applied_refs: list[str] | None = None,
    findings_present: bool | None = None,
    finding_count: int | None = None,
) -> None:
    payload = {
        "ok": bool(ok),
        "verdict": verdict,
        "primary_reason": str(primary_reason),
        "tier_id": tier_id,
        "run_key": run_key,
        "attempt_id": attempt_id,
    }
    if waivers_applied_count is not None:
        payload["waivers_applied_count"] = int(waivers_applied_count)
    if waivers_applied_refs is not None:
        payload["waivers_applied_refs"] = list(waivers_applied_refs)
    if findings_present is not None:
        payload["findings_present"] = bool(findings_present)
    if finding_count is not None:
        payload["finding_count"] = int(finding_count)
    print(json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")))


def _stderr_supports_color() -> bool:
    if os.environ.get("NO_COLOR") is not None or os.environ.get("BELGI_NO_COLOR") is not None:
        return False
    isatty = getattr(sys.stderr, "isatty", None)
    if not callable(isatty):
        return False
    try:
        return bool(isatty())
    except Exception:
        return False


def _colorize_status_token(token: str, *, enabled: bool) -> str:
    if not enabled:
        return token
    color = _ANSI_STATUS_COLORS.get(token)
    if not color:
        return token
    return f"{color}{token}{_ANSI_RESET}"


def _emit_human_status(*, prefix: str, level: str, lines: list[str]) -> None:
    normalized_lines = ["" if line is None else str(line) for line in lines]
    if not normalized_lines:
        normalized_lines = [""]
    status_token = str(level or "INFO").upper()
    colored_token = _colorize_status_token(status_token, enabled=_stderr_supports_color())
    first_line = normalized_lines[0]
    if first_line:
        print(f"{prefix} {colored_token}: {first_line}", file=sys.stderr)
    else:
        print(f"{prefix} {colored_token}", file=sys.stderr)
    for extra in normalized_lines[1:]:
        if extra == "":
            print("", file=sys.stderr)
            continue
        print(f"{prefix} {extra}", file=sys.stderr)


def _emit_cli_user_error_result(
    *,
    primary_reason: str,
    parser: argparse.ArgumentParser | None = None,
    help_to_stderr: bool = False,
) -> int:
    _emit_machine_result(
        ok=False,
        verdict="NO-GO",
        primary_reason=primary_reason,
        tier_id=None,
        run_key=None,
        attempt_id=None,
    )
    if parser is not None:
        usage = parser.format_usage()
        if usage:
            print(usage, file=sys.stderr, end="")
        if help_to_stderr:
            print(parser.format_help(), file=sys.stderr, end="")
        prog = str(getattr(parser, "prog", "belgi") or "belgi")
    else:
        prog = "belgi"
    _emit_human_status(prefix=prog, level="USER_ERROR", lines=[primary_reason])
    return RC_USER_ERROR


def _normalize_cli_exit_code(
    raw_rc: int,
    *,
    surface: Literal["default", "stage_forwarder"] = "default",
) -> int:
    if raw_rc == RC_GO:
        return RC_GO
    if raw_rc == RC_NO_GO:
        return RC_NO_GO
    if raw_rc == RC_USER_ERROR:
        return RC_USER_ERROR
    if raw_rc == RC_INTERNAL_ERROR:
        return RC_INTERNAL_ERROR
    if surface == "default":
        if raw_rc in (1, 2):
            return RC_NO_GO
        if raw_rc == 3:
            return RC_USER_ERROR
        return RC_INTERNAL_ERROR
    if surface == "stage_forwarder":
        if raw_rc == 2:
            return RC_NO_GO
        if raw_rc == 3:
            return RC_USER_ERROR
        return RC_INTERNAL_ERROR
    raise ValueError(f"unsupported CLI exit normalization surface: {surface}")
