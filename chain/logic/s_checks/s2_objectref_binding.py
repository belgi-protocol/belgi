from __future__ import annotations

import base64
import json
from typing import Any

from belgi.core.hash import sha256_bytes
from belgi.core.jail import safe_relpath
from belgi.core.jail import resolve_storage_ref
from belgi.core.schema import validate_schema
from chain.logic.base import CheckResult
from chain.logic.s_checks.context import SCheckContext


class _ReplayInstructionsRefError(Exception):
    def __init__(self, message: str, pointer: str) -> None:
        self.message = message
        self.pointer = pointer
        super().__init__(message)


class _ReplayInstructionsPayloadError(Exception):
    def __init__(self, message: str, pointer: str) -> None:
        self.message = message
        self.pointer = pointer
        super().__init__(message)


def _require_object_ref(obj: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise ValueError(f"{field} must be an object")
    for k in ("id", "hash", "storage_ref"):
        if k not in obj:
            raise ValueError(f"{field} missing required '{k}'")
    if not isinstance(obj.get("hash"), str) or not obj.get("hash"):
        raise ValueError(f"{field}.hash missing/invalid")
    if not isinstance(obj.get("storage_ref"), str) or not obj.get("storage_ref"):
        raise ValueError(f"{field}.storage_ref missing/invalid")
    return obj


def _resolve_objectref_bytes(repo_root, obj_ref: dict[str, Any], *, field: str) -> bytes:
    storage_ref = str(obj_ref["storage_ref"])
    declared_hash = str(obj_ref["hash"]).lower()

    p = resolve_storage_ref(repo_root, storage_ref)
    blob = p.read_bytes()
    digest = sha256_bytes(blob).lower()
    if digest != declared_hash:
        raise ValueError(f"{field} hash mismatch: declared {declared_hash}, computed {digest}")
    return blob


def _replay_ptr(storage_ref: str, suffix: str) -> str:
    return f"{storage_ref}#{suffix}"


def run(ctx: SCheckContext) -> list[CheckResult]:
    repo_root = ctx.repo_root
    sm = ctx.seal_manifest

    try:
        refs: list[tuple[str, dict[str, Any]]] = []
        for key in (
            "locked_spec_ref",
            "gate_q_verdict_ref",
            "gate_r_verdict_ref",
            "evidence_manifest_ref",
        ):
            refs.append((f"SealManifest.{key}", _require_object_ref(sm.get(key), field=f"SealManifest.{key}")))

        waivers = sm.get("waivers")
        if isinstance(waivers, list):
            for i, w in enumerate(waivers):
                refs.append((f"SealManifest.waivers[{i}]", _require_object_ref(w, field=f"SealManifest.waivers[{i}]")))

        replay_ref = None
        if "replay_instructions_ref" in sm:
            try:
                replay_ref = _require_object_ref(sm.get("replay_instructions_ref"), field="SealManifest.replay_instructions_ref")
            except ValueError as e:
                ptr = safe_relpath(repo_root, ctx.seal_manifest_path) + "#/replay_instructions_ref"
                raise _ReplayInstructionsRefError(str(e), ptr) from e
            refs.append(("SealManifest.replay_instructions_ref", replay_ref))

        # Pinned seal public key (may be required by tier).
        env = ctx.locked_spec.get("environment_envelope")
        if isinstance(env, dict) and "seal_pubkey_ref" in env:
            refs.append(
                (
                    "LockedSpec.environment_envelope.seal_pubkey_ref",
                    _require_object_ref(env.get("seal_pubkey_ref"), field="LockedSpec.environment_envelope.seal_pubkey_ref"),
                )
            )

        for field, obj_ref in refs:
            try:
                _resolve_objectref_bytes(repo_root, obj_ref, field=field)
            except ValueError as e:
                if field == "SealManifest.replay_instructions_ref":
                    ptr = safe_relpath(repo_root, ctx.seal_manifest_path) + "#/replay_instructions_ref"
                    raise _ReplayInstructionsRefError(str(e), ptr) from e
                raise

        if replay_ref is not None:
            storage_ref = str(replay_ref.get("storage_ref") or "").strip()
            ptr = _replay_ptr(storage_ref, "/source_archive_ref")
            if ctx.replay_instructions_schema is None:
                return [
                    CheckResult(
                        check_id="S2",
                        status="FAIL",
                        category="FS-OBJECTREF-HASH-MISMATCH",
                        message="ReplayInstructionsPayload schema missing or invalid",
                        pointers=[
                            safe_relpath(repo_root, ctx.seal_manifest_path) + "#/replay_instructions_ref",
                            "schemas/ReplayInstructionsPayload.schema.json",
                        ],
                        remediation_next_instruction=(
                            "Do restore ReplayInstructionsPayload.schema.json in protocol pack then re-run S."
                        ),
                    )
                ]
            try:
                replay_bytes = _resolve_objectref_bytes(repo_root, replay_ref, field="SealManifest.replay_instructions_ref")
            except ValueError as e:
                raise _ReplayInstructionsRefError(str(e), safe_relpath(repo_root, ctx.seal_manifest_path) + "#/replay_instructions_ref") from e

            try:
                replay_text = replay_bytes.decode("utf-8", errors="strict")
            except UnicodeDecodeError as e:
                raise _ReplayInstructionsPayloadError("Replay instructions must be valid UTF-8", ptr) from e

            try:
                replay_doc = json.loads(replay_text)
            except json.JSONDecodeError as e:
                raise _ReplayInstructionsPayloadError("Replay instructions JSON invalid", ptr) from e

            if not isinstance(replay_doc, dict):
                raise _ReplayInstructionsPayloadError("Replay instructions JSON must be an object", ptr)

            errs = validate_schema(
                replay_doc,
                ctx.replay_instructions_schema,
                root_schema=ctx.replay_instructions_schema,
                path="ReplayInstructionsPayload",
            )
            if errs:
                raise _ReplayInstructionsPayloadError("Replay instructions schema validation failed", ptr)

            source_ref = replay_doc.get("source_archive_ref")
            try:
                source_ref = _require_object_ref(source_ref, field="ReplayInstructionsPayload.source_archive_ref")
            except ValueError as e:
                raise _ReplayInstructionsPayloadError(str(e), ptr) from e

            try:
                _resolve_objectref_bytes(repo_root, source_ref, field="ReplayInstructionsPayload.source_archive_ref")
            except ValueError as e:
                raise _ReplayInstructionsPayloadError(str(e), ptr) from e

    except _ReplayInstructionsRefError as e:
        return [
            CheckResult(
                check_id="S2",
                status="FAIL",
                category="FS-OBJECTREF-HASH-MISMATCH",
                message=e.message,
                pointers=[e.pointer],
                remediation_next_instruction="Do restore the correct replay instructions reference bytes (hash binding) then re-run S.",
            )
        ]

    except _ReplayInstructionsPayloadError as e:
        return [
            CheckResult(
                check_id="S2",
                status="FAIL",
                category="FS-OBJECTREF-HASH-MISMATCH",
                message=e.message,
                pointers=[e.pointer],
                remediation_next_instruction="Do fix the replay instructions payload and source_archive_ref binding then re-run S.",
            )
        ]

    except ValueError as e:
        return [
            CheckResult(
                check_id="S2",
                status="FAIL",
                category="FS-OBJECTREF-HASH-MISMATCH",
                message=str(e),
                pointers=[safe_relpath(repo_root, ctx.seal_manifest_path)],
                remediation_next_instruction="Do restore the correct referenced artifact bytes (hash binding) then re-run S.",
            )
        ]

    return [CheckResult(check_id="S2", status="PASS", message="All SealManifest ObjectRefs hash-bind correctly.", pointers=[])]
