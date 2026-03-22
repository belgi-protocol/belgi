from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from belgi.core.hash import sha256_bytes
from belgi.core.jail import resolve_storage_ref
from belgi.core.schema import validate_schema
from belgi.protocol.pack import ProtocolContext, get_builtin_protocol_context


def _format_schema_errors(errors: list[object]) -> str:
    parts: list[str] = []
    for err in errors:
        path = getattr(err, "path", "<unknown>")
        message = getattr(err, "message", "schema error")
        parts.append(f"{path}: {message}")
    return "; ".join(parts)


def load_locked_schema_object(
    *,
    repo_root: Path,
    storage_ref: str,
    declared_hash: str,
    schema_rel: str,
    label: str,
    protocol: ProtocolContext | None = None,
    schema: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], Path]:
    try:
        object_path = resolve_storage_ref(repo_root, storage_ref)
    except ValueError as e:
        raise ValueError(f"{label} storage_ref invalid: {e}") from e
    if object_path.is_symlink() or not object_path.is_file():
        raise ValueError(f"{label} missing/invalid at storage_ref")

    raw_bytes = object_path.read_bytes()
    if sha256_bytes(raw_bytes) != declared_hash.lower():
        raise ValueError(f"{label} hash mismatch")

    try:
        payload = json.loads(raw_bytes.decode("utf-8", errors="strict"))
    except Exception as e:
        raise ValueError(f"{label} is not valid UTF-8 JSON: {e}") from e
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON object")

    if schema is None:
        if protocol is None:
            protocol = get_builtin_protocol_context()
        schema = protocol.read_json(schema_rel)
    schema_errors = validate_schema(payload, schema, root_schema=schema, path=label)
    if schema_errors:
        raise ValueError(f"{label} schema validation failed: {_format_schema_errors(schema_errors)}")

    return payload, object_path
