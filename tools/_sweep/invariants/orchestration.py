from __future__ import annotations

from tools._shared import common as _common
from tools._sweep.inputs import (
    _canonical_inputs,
    _governed_sweep_owner_files,
    _iter_schema_files,
)
from tools._sweep.managed_surfaces import _sweep_managed_surface_files
from tools._sweep.model import InvariantResult, inventory_witness_details

_PROTOCOL_IDENTITY_SOURCE_GUARD_FILES: tuple[str, ...] = (
    "CANONICALS.md",
    "gates/GATE_Q.md",
    "gates/GATE_R.md",
    "gates/GATE_S.md",
    "gates/failure-taxonomy.md",
    "belgi/canonicals/CANONICALS.md",
    "belgi/_protocol_packs/v1/gates/GATE_Q.md",
    "belgi/_protocol_packs/v1/gates/GATE_R.md",
    "belgi/_protocol_packs/v1/gates/GATE_S.md",
    "belgi/_protocol_packs/v1/gates/failure-taxonomy.md",
)

_PROTOCOL_IDENTITY_SOURCE_FORBIDDEN_PATTERNS: tuple[tuple[str, _common.re.Pattern[str]], ...] = (
    (
        "identity tuple includes source",
        _common.re.compile(r"\bpack_id\s*,\s*manifest_sha256\s*,\s*pack_name\s*,\s*source\b", flags=_common.re.IGNORECASE),
    ),
    (
        "active identity includes source",
        _common.re.compile(r"active protocol context identity.*\bsource\b", flags=_common.re.IGNORECASE),
    ),
    (
        "source compared for identity",
        _common.re.compile(r"lockedspec\.protocol_pack\.source.*active\s+`?source`?", flags=_common.re.IGNORECASE),
    ),
    (
        "source mismatch wording",
        _common.re.compile(r"\bsource mismatch\b", flags=_common.re.IGNORECASE),
    ),
)

_FIXTURE_ZERO_GOVERNED_PUBLIC_PATHS: tuple[str, ...] = (
    "policy/fixtures/public/gate_q/cases.json",
    "policy/fixtures/public/gate_r/cases.json",
    "policy/fixtures/public/gate_s/cases.json",
    "policy/fixtures/public/seal/cases.json",
)

def check_cs_byte_001(root: _common.Path) -> InvariantResult:
    """CS-BYTE-001 — Byte Integrity: tools/normalize.py --check must pass."""

    # CS-BYTE-001 MUST use the exact Byte Guard enumeration + detector to avoid drift.
    from tools.normalize import scan_byte_guard

    # Exclude sweep outputs so CS-BYTE-001 cannot self-invalidate the current sweep artifact write.
    report = scan_byte_guard(
        root,
        tracked_only=True,
        exclude_roots=None,
        exclude_paths=[_common.CANONICAL_SWEEP_OUT, _common.CANONICAL_SWEEP_SUMMARY],
        allow_empty=False,
        mode="check",
    )
    details = {
        "scope": "tracked-only",
        "surface": report.get("surface"),
        "counts": report.get("counts"),
        "drift_files": report.get("drift_files"),
    }
    status = str(report.get("status") or "FAIL")
    if status != "PASS":
        return InvariantResult(
            "CS-BYTE-001",
            "FAIL",
            ["tools/normalize.py"],
            "Run python -m tools.normalize --fix --tracked-only to eliminate CRLF drift, then rerun the sweep.",
            details,
        )
    return InvariantResult("CS-BYTE-001", "PASS", ["tools/normalize.py"], "", details)

def check_cs_protocol_identity_001(
    root: _common.Path,
    *,
    guard_files: tuple[str, ...] = _PROTOCOL_IDENTITY_SOURCE_GUARD_FILES,
    forbidden_patterns: tuple[tuple[str, _common.re.Pattern[str]], ...] = _PROTOCOL_IDENTITY_SOURCE_FORBIDDEN_PATTERNS,
) -> InvariantResult:
    """CS-PROTOCOL-IDENTITY-001 — Protocol identity language excludes source from identity tuple."""

    missing_files: list[str] = []
    violations: list[str] = []
    for rel in sorted(guard_files):
        try:
            p = _common._resolve_repo_path(root, rel, must_exist=True, must_be_file=True)
        except _common._UserInputError:
            missing_files.append(rel)
            continue
        for line_no, line in enumerate(_common.read_text(p).splitlines(), start=1):
            for reason, pattern in forbidden_patterns:
                if pattern.search(line):
                    violations.append(f"{rel}:{line_no} ({reason})")
                    break

    if missing_files:
        joined = ", ".join(sorted(missing_files))
        return InvariantResult(
            "CS-PROTOCOL-IDENTITY-001",
            "FAIL",
            [_common.CONSISTENCY_SPEC_DOC, "CANONICALS.md#protocol-pack-identity"],
            (
                "Missing protocol-identity guard file(s): "
                f"{joined}. Restore/add these files, then rerun sweep."
            ),
        )

    if violations:
        sample = ", ".join(violations[:8])
        suffix = "" if len(violations) <= 8 else f" (+{len(violations) - 8} more)"
        return InvariantResult(
            "CS-PROTOCOL-IDENTITY-001",
            "FAIL",
            [
                f"{_common.CONSISTENCY_SPEC_DOC}#cs-protocol-identity-001--protocol-identity-language-excludes-source-from-identity-tuple",
                "CANONICALS.md#protocol-pack-identity",
            ],
            (
                "Protocol identity wording must treat source as operational context only. "
                "Remove source-based identity semantics from: "
                f"{sample}{suffix}."
            ),
            {"violations": violations},
        )

    return InvariantResult(
        "CS-PROTOCOL-IDENTITY-001",
        "PASS",
        [
            f"{_common.CONSISTENCY_SPEC_DOC}#cs-protocol-identity-001--protocol-identity-language-excludes-source-from-identity-tuple",
            "CANONICALS.md#protocol-pack-identity",
        ],
        "",
    )

def check_cs_fixture_zero_001(root: _common.Path) -> InvariantResult:
    """CS-FIXTURE-ZERO-001 — governed public fixture surface stays absent."""

    reintroduced = [
        rel
        for rel in _FIXTURE_ZERO_GOVERNED_PUBLIC_PATHS
        if (root / _common.Path(*rel.split("/"))).exists()
    ]
    evidence = [f"{_common.CONSISTENCY_SPEC_DOC}#cs-fixture-zero-001--governed-public-fixture-surface-absent-in-belgi-main-repo"]
    if reintroduced:
        sample = ", ".join(reintroduced)
        return InvariantResult(
            "CS-FIXTURE-ZERO-001",
            "FAIL",
            evidence,
            f"Remove reintroduced governed public fixture surface path(s): {sample}.",
            {"reintroduced_paths": reintroduced},
        )
    return InvariantResult(
        "CS-FIXTURE-ZERO-001",
        "PASS",
        evidence,
        "",
        {"checked_paths": list(_FIXTURE_ZERO_GOVERNED_PUBLIC_PATHS)},
    )

def check_cs_sweep_001(
    root: _common.Path,
    *,
    canonical_inputs_fn: _common.Callable[[_common.Path], list[str]] = _canonical_inputs,
    iter_schema_files_fn: _common.Callable[[_common.Path], list[str]] = _iter_schema_files,
) -> InvariantResult:
    """CS-SWEEP-001 — Input Authority: canonical inputs reflect current schemas/tools."""

    derived_from = (
        "tools/_sweep/inputs.py::_canonical_inputs",
        "tools/_sweep/inputs.py::_iter_builtin_protocol_pack_files",
        "tools/_sweep/inputs.py::_iter_schema_files",
    )
    try:
        canon = sorted(set(canonical_inputs_fn(root)))
        schema_files = sorted(set(iter_schema_files_fn(root)))
    except Exception as e:
        return InvariantResult(
            "CS-SWEEP-001",
            "FAIL",
            ["schemas/README.md", "tools/_sweep/inputs.py"],
            f"Fix tools/_sweep/inputs.py canonical input enumeration error ({e}), then rerun sweep.",
            inventory_witness_details(
                checked_set=(),
                mismatched=(f"enumeration_error: {e}",),
                derived_from=derived_from,
            ),
        )

    required = sorted(
        {
            *schema_files,
            "tools/normalize.py",
            "tools/rehash.py",
            "tools/canonicals_report.py",
            *_governed_sweep_owner_files(),
        }
    )
    missing = sorted(set(required) - set(canon))
    details = inventory_witness_details(
        checked_set=canon,
        missing=missing,
        derived_from=derived_from,
    )
    if missing:
        joined = ", ".join(missing)
        return InvariantResult(
            "CS-SWEEP-001",
            "FAIL",
            [
                "schemas/README.md",
                "tools/_sweep/inputs.py",
                "tools/_sweep/managed_surfaces.py",
                "tools/_sweep/registry.py",
            ],
            (
                "Ensure sweep inputs include the full schema/tooling owner surface from tools/_sweep/inputs.py, "
                "tools/_sweep/managed_surfaces.py, and tools/_sweep/registry.py. Missing: "
                f"{joined}."
            ),
            details,
        )

    return InvariantResult(
        "CS-SWEEP-001",
        "PASS",
        [
            "schemas/README.md",
            "tools/_sweep/inputs.py",
            "tools/_sweep/managed_surfaces.py",
            "tools/_sweep/registry.py",
        ],
        "",
        details,
    )

def check_cs_sweep_002(
    root: _common.Path,
    *,
    canonical_inputs_fn: _common.Callable[[_common.Path], list[str]] = _canonical_inputs,
    sweep_managed_surface_files_fn: _common.Callable[[_common.Path], list[str]] = _sweep_managed_surface_files,
) -> InvariantResult:
    """CS-SWEEP-002 — Managed surfaces are explicitly listed by the managed-surface owner and sweep inputs."""

    derived_from = (
        "tools/_sweep/inputs.py::_canonical_inputs",
        "tools/_sweep/managed_surfaces.py::_sweep_managed_surface_files",
    )
    try:
        canon = set(canonical_inputs_fn(root))
        required = sorted(set(sweep_managed_surface_files_fn(root)))
    except Exception as e:
        return InvariantResult(
            "CS-SWEEP-002",
            "FAIL",
            [f"{_common.CONSISTENCY_SPEC_DOC}#cs-sweep-002--managed-surface-coverage"],
            f"Failed to enumerate managed sweep surfaces from tools/_sweep/managed_surfaces.py ({e}).",
            inventory_witness_details(
                checked_set=(),
                mismatched=(f"enumeration_error: {e}",),
                derived_from=derived_from,
            ),
        )

    missing = sorted([rel for rel in required if rel not in canon])
    details = inventory_witness_details(
        checked_set=required,
        missing=missing,
        derived_from=derived_from,
    )
    if missing:
        joined = ", ".join(missing)
        return InvariantResult(
            "CS-SWEEP-002",
            "FAIL",
            [
                f"{_common.CONSISTENCY_SPEC_DOC}#cs-sweep-002--managed-surface-coverage",
                "tools/_sweep/inputs.py",
                "tools/_sweep/managed_surfaces.py",
                "tools/_sweep/registry.py",
            ],
            (
                "Add missing managed surface path(s) to tools/_sweep/managed_surfaces.py and "
                "tools/_sweep/inputs.py canonical inputs "
                "and synchronize docs/operations/consistency-sweep.md Inputs list. Missing: "
                f"{joined}."
            ),
            details,
        )

    return InvariantResult(
        "CS-SWEEP-002",
        "PASS",
        [
            f"{_common.CONSISTENCY_SPEC_DOC}#cs-sweep-002--managed-surface-coverage",
            "tools/_sweep/managed_surfaces.py",
            "tools/_sweep/inputs.py",
        ],
        "",
        details,
    )

def check_cs_r0_enforcement_wired_001(root: _common.Path) -> InvariantResult:
    """CS-R0-ENFORCEMENT-WIRED-001 — R0 evidence sufficiency check is wired into registry."""

    p = _common.repo_path(root, "chain/logic/r_checks/registry.py")
    if not p.exists():
        return InvariantResult("CS-R0-ENFORCEMENT-WIRED-001", "FAIL", [], "Missing chain/logic/r_checks/registry.py.")

    txt = _common.read_text(p)
    required = [
        "r0_evidence_sufficiency",
        "r0_evidence_sufficiency.run",
    ]
    if not all(s in txt for s in required):
        return InvariantResult(
            "CS-R0-ENFORCEMENT-WIRED-001",
            "FAIL",
            ["chain/logic/r_checks/registry.py"],
            "Wire chain/logic/r_checks/r0_evidence_sufficiency.py into chain/logic/r_checks/registry.py deterministic check order.",
        )

    return InvariantResult(
        "CS-R0-ENFORCEMENT-WIRED-001",
        "PASS",
        ["chain/logic/r_checks/registry.py"],
        "",
    )
