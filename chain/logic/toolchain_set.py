from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from belgi.core.jail import resolve_storage_ref
from belgi.protocol.pack import ProtocolContext

from .locked_object_schema import load_locked_schema_object

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass(frozen=True)
class ToolchainSetRef:
    object_id: str
    path: str


@dataclass(frozen=True)
class LockedToolchainSet:
    object_id: str
    storage_ref: str
    path: Path
    toolchain_set_id: str
    refs: list[ToolchainSetRef]


def load_locked_toolchain_set(
    *,
    repo_root: Path,
    locked_spec: dict[str, Any],
    protocol: ProtocolContext | None = None,
    schema: dict[str, Any] | None = None,
) -> LockedToolchainSet:
    env_obj = locked_spec.get("environment_envelope")
    if not isinstance(env_obj, dict):
        raise ValueError("LockedSpec.environment_envelope missing/invalid")

    toolchain_set_ref = env_obj.get("toolchain_set_ref")
    if not isinstance(toolchain_set_ref, dict):
        raise ValueError("LockedSpec.environment_envelope.toolchain_set_ref missing/invalid")

    object_id = toolchain_set_ref.get("id")
    declared_hash = toolchain_set_ref.get("hash")
    storage_ref = toolchain_set_ref.get("storage_ref")
    if not isinstance(object_id, str) or not object_id.strip():
        raise ValueError("LockedSpec.environment_envelope.toolchain_set_ref.id missing/invalid")
    if not isinstance(storage_ref, str) or not storage_ref.strip():
        raise ValueError("LockedSpec.environment_envelope.toolchain_set_ref.storage_ref missing/invalid")
    if not isinstance(declared_hash, str) or not _SHA256_RE.fullmatch(declared_hash):
        raise ValueError("LockedSpec.environment_envelope.toolchain_set_ref.hash missing/invalid")

    toolchain_set_obj, toolchain_set_path = load_locked_schema_object(
        repo_root=repo_root,
        storage_ref=storage_ref.strip(),
        declared_hash=declared_hash,
        schema_rel="schemas/ToolchainSet.schema.json",
        label="ToolchainSet",
        protocol=protocol,
        schema=schema,
    )
    toolchain_set_id = str(toolchain_set_obj["toolchain_set_id"]).strip()
    refs_obj = toolchain_set_obj["refs"]

    refs: list[ToolchainSetRef] = []
    seen_ids: set[str] = set()
    for idx, entry in enumerate(refs_obj):
        if not isinstance(entry, dict):
            raise ValueError(f"ToolchainSet.refs[{idx}] missing/invalid")
        ref_id = entry.get("id")
        ref_path = entry.get("path")
        if not isinstance(ref_id, str) or not ref_id.strip():
            raise ValueError(f"ToolchainSet.refs[{idx}].id missing/invalid")
        if ref_id == "toolchain.main":
            raise ValueError("ToolchainSet.refs must not declare reserved id toolchain.main")
        if ref_id in seen_ids:
            raise ValueError(f"duplicate ToolchainSet ref id: {ref_id}")
        seen_ids.add(ref_id)
        if not isinstance(ref_path, str) or not ref_path.strip():
            raise ValueError(f"ToolchainSet.refs[{idx}].path missing/invalid")
        try:
            ref_path_obj = resolve_storage_ref(repo_root, ref_path)
        except ValueError as e:
            raise ValueError(f"ToolchainSet.refs[{idx}].path invalid: {e}") from e
        if ref_path_obj.is_symlink() or not ref_path_obj.is_file():
            raise ValueError(f"ToolchainSet.refs[{idx}].path missing/invalid at storage_ref: {ref_path}")
        refs.append(ToolchainSetRef(object_id=ref_id.strip(), path=ref_path.strip()))

    return LockedToolchainSet(
        object_id=object_id.strip(),
        storage_ref=storage_ref.strip(),
        path=toolchain_set_path,
        toolchain_set_id=toolchain_set_id.strip(),
        refs=refs,
    )
