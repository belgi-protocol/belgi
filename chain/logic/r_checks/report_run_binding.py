from __future__ import annotations

from typing import Any


def required_report_run_binding_error(
    *,
    payload: dict[str, Any],
    locked_run_id: Any,
    where: str,
) -> str:
    if not isinstance(locked_run_id, str) or not locked_run_id.strip():
        return "LockedSpec.run_id missing/invalid."

    payload_run_id = payload.get("run_id")
    if payload_run_id != locked_run_id:
        return (
            f"{where}: payload run_id={payload_run_id!r} belongs to a different run; "
            f"expected LockedSpec.run_id={locked_run_id!r}."
        )

    return ""


def required_report_run_binding_remediation() -> str:
    return "Do regenerate the required report for the current LockedSpec.run_id then re-run R."
