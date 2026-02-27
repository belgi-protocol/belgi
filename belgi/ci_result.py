from __future__ import annotations

import json
from pathlib import Path
from typing import Any


BELGI_RESULT_PREFIX = "BELGI_RESULT"


def parse_belgi_result_lines(lines: list[str], *, source: str) -> dict[str, Any]:
    payload: str | None = None
    for line in reversed(lines):
        stripped = line.strip()
        if stripped.startswith(BELGI_RESULT_PREFIX):
            payload = stripped[len(BELGI_RESULT_PREFIX) :].strip()
            break

    if payload is None:
        raise ValueError(f"missing BELGI_RESULT line in {source}")

    try:
        obj = json.loads(payload)
    except Exception as e:
        raise ValueError(f"invalid BELGI_RESULT JSON in {source}: {e}") from e
    if not isinstance(obj, dict):
        raise ValueError(f"BELGI_RESULT payload must be a JSON object in {source}")
    return obj


def parse_belgi_result_file(path: Path) -> dict[str, Any]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return parse_belgi_result_lines(lines, source=path.as_posix())


def ensure_belgi_result_line(path: Path) -> dict[str, Any]:
    current_text = path.read_text(encoding="utf-8", errors="replace")
    lines = current_text.splitlines()
    try:
        return parse_belgi_result_lines(lines, source=path.as_posix())
    except ValueError as e:
        if not str(e).startswith("missing BELGI_RESULT line in "):
            raise

    machine_obj: dict[str, Any] | None = None
    for line in reversed(lines):
        stripped = line.strip()
        if not stripped.startswith("{"):
            continue
        try:
            parsed = json.loads(stripped)
        except Exception:
            continue
        if (
            isinstance(parsed, dict)
            and isinstance(parsed.get("run_key"), str)
            and isinstance(parsed.get("attempt_id"), str)
            and isinstance(parsed.get("verdict"), str)
            and isinstance(parsed.get("ok"), bool)
        ):
            machine_obj = parsed
            break

    if machine_obj is None:
        raise ValueError(f"missing BELGI_RESULT line in {path.as_posix()}")

    marker_payload = json.dumps(machine_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    suffix = "" if current_text.endswith("\n") or current_text == "" else "\n"
    path.write_text(
        current_text + suffix + f"{BELGI_RESULT_PREFIX} {marker_payload}\n",
        encoding="utf-8",
        errors="strict",
    )
    return machine_obj
