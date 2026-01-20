from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


Status = str  # "PASS" | "FAIL"


@dataclass(frozen=True)
class CheckResult:
    check_id: str
    status: Status
    message: str
    pointers: list[str]
    category: str | None = None
    remediation_next_instruction: str | None = None


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="strict"))


def command_satisfied(commands_executed: Any, *, mode: str, subcommand: str) -> bool:
    """Return True iff EvidenceManifest.commands_executed satisfies the required belgi subcommand."""

    if mode == "strings":
        if not isinstance(commands_executed, list):
            return False
        target = f"belgi {subcommand}"
        return any(isinstance(entry, str) and entry == target for entry in commands_executed)

    if mode == "structured":
        if not isinstance(commands_executed, list):
            return False
        for entry in commands_executed:
            if not isinstance(entry, dict):
                continue
            argv = entry.get("argv")
            if not isinstance(argv, list) or len(argv) < 2 or not all(isinstance(x, str) and x for x in argv):
                continue
            if argv[0] != "belgi" or argv[1] != subcommand:
                continue
            exit_code = entry.get("exit_code")
            if isinstance(exit_code, int) and not isinstance(exit_code, bool) and exit_code == 0:
                return True
        return False

    return False


def find_artifacts_by_kind(artifacts: Any, kind: str) -> list[dict[str, Any]]:
    if not isinstance(artifacts, list):
        return []
    out: list[dict[str, Any]] = []
    for a in artifacts:
        if not isinstance(a, dict):
            continue
        if a.get("kind") == kind:
            out.append(a)
    return out


def find_artifacts_by_kind_id(artifacts: Any, kind: str, artifact_id: str) -> list[dict[str, Any]]:
    if not isinstance(artifacts, list):
        return []

    matches: list[dict[str, Any]] = []
    for a in artifacts:
        if not isinstance(a, dict):
            continue
        if a.get("kind") == kind and a.get("id") == artifact_id:
            matches.append(a)

    return matches


def stable_unique(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def verify_protocol_identity(
    *,
    locked_spec: dict[str, Any] | None,
    active_pack_id: str,
    active_manifest_sha256: str,
    active_pack_name: str,
    active_source: str,
    gate_id: str,
) -> CheckResult | None:
    """Verify LockedSpec.protocol_pack matches active protocol context.

    Returns None if match, CheckResult with FAIL if mismatch or missing.
    Fail-closed: any mismatch (pack_id, manifest_sha256, pack_name) is a hard failure.

    Note: source is NOT checked for identity. Source can legitimately differ between
    compilation (e.g. builtin) and verification (e.g. override with same pack_id).
    If source differs but pack_id and manifest_sha256 match, verification passes.

    gate_id must be one of: Q, R, S
    """
    # Category and remediation are gate-specific for taxonomy compliance.
    category = f"F{gate_id}-PROTOCOL-IDENTITY-MISMATCH"
    gate_suffix = f"then re-run {gate_id}."

    if locked_spec is None:
        return CheckResult(
            check_id="PROTOCOL-IDENTITY-001",
            status="FAIL",
            message="LockedSpec is missing; cannot verify protocol identity.",
            pointers=["LockedSpec.protocol_pack"],
            category=category,
            remediation_next_instruction=f"Do re-compile LockedSpec with C1 using the active protocol pack {gate_suffix}",
        )

    pp = locked_spec.get("protocol_pack")
    if not isinstance(pp, dict):
        return CheckResult(
            check_id="PROTOCOL-IDENTITY-001",
            status="FAIL",
            message="LockedSpec.protocol_pack is missing or invalid.",
            pointers=["LockedSpec.protocol_pack"],
            category=category,
            remediation_next_instruction=f"Do re-compile LockedSpec with C1 using the active protocol pack {gate_suffix}",
        )

    declared_pack_id = pp.get("pack_id")
    declared_manifest_sha = pp.get("manifest_sha256")
    declared_pack_name = pp.get("pack_name")

    # Source is explicitly NOT checked for identity match (see docstring).
    # pack_id and manifest_sha256 are the cryptographic binding; source is metadata.

    mismatches: list[str] = []
    if declared_pack_id != active_pack_id:
        mismatches.append(f"pack_id: declared={declared_pack_id!r} active={active_pack_id!r}")
    if declared_manifest_sha != active_manifest_sha256:
        mismatches.append(f"manifest_sha256: declared={declared_manifest_sha!r} active={active_manifest_sha256!r}")
    if declared_pack_name != active_pack_name:
        mismatches.append(f"pack_name: declared={declared_pack_name!r} active={active_pack_name!r}")

    if mismatches:
        return CheckResult(
            check_id="PROTOCOL-IDENTITY-001",
            status="FAIL",
            message="Protocol identity mismatch between LockedSpec and active protocol pack: " + "; ".join(mismatches),
            pointers=["LockedSpec.protocol_pack"],
            category=category,
            remediation_next_instruction=f"Do ensure the same protocol pack is used for C1 compilation and gate verification {gate_suffix}",
        )

    return None
