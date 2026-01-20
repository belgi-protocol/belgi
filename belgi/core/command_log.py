from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from belgi.core.schema import parse_rfc3339


@dataclass(frozen=True)
class CommandRecord:
    """Structured command record matching EvidenceManifest.schema.json CommandRecord def."""

    argv: list[str]
    exit_code: int
    started_at: str  # RFC3339
    finished_at: str  # RFC3339


def format_command_string(argv: list[str]) -> str:
    """Format argv list as a deterministic command string for strings mode.

    Returns the exact string that will be matched by chain.logic.base.command_satisfied() in strings mode.
    Format: "belgi <subcommand>" for belgi commands, or space-joined argv otherwise.

    Note: This is a simple join. For Gate R matching, only "belgi <subcommand>" format
    is recognized. More complex argv is serialized but may not match any required command.
    """

    if not argv:
        return ""
    return " ".join(argv)


def make_command_record(
    argv: list[str],
    exit_code: int,
    *,
    timestamp: str = "1970-01-01T00:00:00Z",
) -> CommandRecord:
    """Create a CommandRecord with deterministic timestamps.

    For deterministic runs, use the default fixed timestamp.
    For real runs, pass actual timestamps.
    """

    parse_rfc3339(timestamp)
    return CommandRecord(
        argv=list(argv),
        exit_code=exit_code,
        started_at=timestamp,
        finished_at=timestamp,
    )


def command_record_to_dict(record: CommandRecord) -> dict[str, Any]:
    """Convert CommandRecord to dict for JSON serialization."""

    return {
        "argv": list(record.argv),
        "exit_code": record.exit_code,
        "started_at": record.started_at,
        "finished_at": record.finished_at,
    }


def append_command_to_manifest(
    commands_executed: list[Any],
    *,
    mode: str,
    argv: list[str],
    exit_code: int,
    timestamp: str = "1970-01-01T00:00:00Z",
) -> list[Any]:
    """Append a command record to commands_executed list (returns new list).

    Raises ValueError if mode is invalid or list type doesn't match mode.
    """

    if mode not in ("strings", "structured"):
        raise ValueError(f"Invalid command_log_mode: {mode}")

    result = list(commands_executed)

    if mode == "strings":
        for entry in result:
            if not isinstance(entry, str):
                raise ValueError("commands_executed contains non-string in strings mode")
        result.append(format_command_string(argv))
    else:  # structured
        for entry in result:
            if not isinstance(entry, dict):
                raise ValueError("commands_executed contains non-dict in structured mode")
        record = make_command_record(argv, exit_code, timestamp=timestamp)
        result.append(command_record_to_dict(record))

    return result


def detect_command_log_mode(commands_executed: Any) -> str | None:
    """Detect the command_log_mode from commands_executed list.

    Returns "strings", "structured", or None if invalid/empty.
    """

    if not isinstance(commands_executed, list) or len(commands_executed) == 0:
        return None

    first = commands_executed[0]
    if isinstance(first, str):
        if all(isinstance(x, str) for x in commands_executed):
            return "strings"
        return None

    if isinstance(first, dict):
        for entry in commands_executed:
            if not isinstance(entry, dict):
                return None
            if not all(k in entry for k in ("argv", "exit_code", "started_at", "finished_at")):
                return None
        return "structured"

    return None
