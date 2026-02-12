from __future__ import annotations

import json
from pathlib import Path

from belgi.core.schema import parse_rfc3339, validate_schema
from belgi.protocol.pack import get_builtin_protocol_context


DEFAULT_GENERATED_AT = "1970-01-01T00:00:00Z"
DEFAULT_SCHEMA_VERSION = "1.0.0"


def _normalize_check_ids(raw_check_ids: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for i, raw in enumerate(raw_check_ids):
        cid = str(raw or "").strip()
        if not cid:
            raise ValueError(f"--check-id[{i}] missing/invalid")
        if cid in seen:
            continue
        seen.add(cid)
        out.append(cid)
    out.sort()
    if not out:
        raise ValueError("at least one --check-id is required")
    return out


def build_policy_stub_payload(
    *,
    run_id: str,
    check_ids: list[str],
    generated_at: str,
    schema_version: str = DEFAULT_SCHEMA_VERSION,
) -> dict[str, object]:
    rid = str(run_id or "").strip()
    if not rid:
        raise ValueError("--run-id missing/invalid")
    gav = str(generated_at or "").strip()
    if not gav:
        raise ValueError("--generated-at missing/invalid")
    parse_rfc3339(gav)
    ver = str(schema_version or "").strip()
    if not ver:
        raise ValueError("schema_version missing/invalid")

    normalized_check_ids = _normalize_check_ids(check_ids)
    checks = [{"check_id": cid, "passed": True} for cid in normalized_check_ids]
    payload: dict[str, object] = {
        "schema_version": ver,
        "run_id": rid,
        "generated_at": gav,
        "summary": {
            "total_checks": len(checks),
            "passed": len(checks),
            "failed": 0,
        },
        "checks": checks,
    }

    protocol = get_builtin_protocol_context()
    schema = protocol.read_json("schemas/PolicyReportPayload.schema.json")
    if not isinstance(schema, dict):
        raise ValueError("PolicyReportPayload schema must be a JSON object")
    errs = validate_schema(payload, schema, root_schema=schema, path="policy_report")
    if errs:
        first = errs[0]
        raise ValueError(f"PolicyReportPayload invalid at {first.path}: {first.message}")
    return payload


def render_policy_stub_bytes(
    *,
    run_id: str,
    check_ids: list[str],
    generated_at: str = DEFAULT_GENERATED_AT,
    schema_version: str = DEFAULT_SCHEMA_VERSION,
) -> bytes:
    payload = build_policy_stub_payload(
        run_id=run_id,
        check_ids=check_ids,
        generated_at=generated_at,
        schema_version=schema_version,
    )
    return (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode(
        "utf-8", errors="strict"
    )


def write_policy_stub(
    *,
    out_path: Path,
    run_id: str,
    check_ids: list[str],
    generated_at: str = DEFAULT_GENERATED_AT,
    schema_version: str = DEFAULT_SCHEMA_VERSION,
) -> bytes:
    if not isinstance(out_path, Path):
        raise TypeError("out_path must be pathlib.Path")
    if out_path.exists():
        if out_path.is_symlink() or not out_path.is_file():
            raise ValueError(f"invalid output path: {out_path}")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    data = render_policy_stub_bytes(
        run_id=run_id,
        check_ids=check_ids,
        generated_at=generated_at,
        schema_version=schema_version,
    )
    out_path.write_bytes(data)
    return data
