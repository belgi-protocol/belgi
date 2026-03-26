from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from chain.logic.s_checks.context import SCheckContext
from chain.logic.s_checks import s2_objectref_binding
from tests.gates.gate_test_support import REPO_ROOT, _read_json, _sha256_hex

pytestmark = pytest.mark.repo_local


def _write_bytes_rel(root: Path, rel: str, data: bytes) -> dict[str, str]:
    path = root / Path(*rel.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {"storage_ref": rel, "hash": _sha256_hex(data)}


def _make_obj_ref(storage_ref: str, data: bytes, obj_id: str) -> dict[str, str]:
    return {"id": obj_id, "hash": _sha256_hex(data), "storage_ref": storage_ref}


def _build_s2_ctx(
    tmp_path: Path,
    *,
    replay_ref: dict[str, str] | None,
    replay_schema: dict[str, Any] | None = None,
) -> SCheckContext:
    locked_bytes = b"{\"run_id\":\"run\",\"tier\":{\"tier_id\":\"tier-1\"}}\n"
    q_bytes = b"{}\n"
    r_bytes = b"{}\n"
    evidence_bytes = b"{}\n"

    locked = _write_bytes_rel(tmp_path, "inputs/LockedSpec.json", locked_bytes)
    gate_q = _write_bytes_rel(tmp_path, "inputs/GateVerdict.Q.json", q_bytes)
    gate_r = _write_bytes_rel(tmp_path, "inputs/GateVerdict.R.json", r_bytes)
    evidence = _write_bytes_rel(tmp_path, "inputs/EvidenceManifest.json", evidence_bytes)

    seal_manifest = {
        "locked_spec_ref": _make_obj_ref(locked["storage_ref"], locked_bytes, "locked"),
        "gate_q_verdict_ref": _make_obj_ref(gate_q["storage_ref"], q_bytes, "q"),
        "gate_r_verdict_ref": _make_obj_ref(gate_r["storage_ref"], r_bytes, "r"),
        "evidence_manifest_ref": _make_obj_ref(evidence["storage_ref"], evidence_bytes, "e"),
        "waivers": [],
    }
    if replay_ref is not None:
        seal_manifest["replay_instructions_ref"] = replay_ref

    seal_path = tmp_path / "SealManifest.json"
    seal_path.write_text(json.dumps(seal_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", errors="strict")

    schemas_root = REPO_ROOT / "schemas"
    if replay_schema is None:
        replay_schema = _read_json(schemas_root / "ReplayInstructionsPayload.schema.json")
    return SCheckContext(
        repo_root=tmp_path,
        locked_spec_path=tmp_path / "inputs" / "LockedSpec.json",
        seal_manifest_path=seal_path,
        evidence_manifest_path=tmp_path / "inputs" / "EvidenceManifest.json",
        locked_spec=_read_json(tmp_path / "inputs" / "LockedSpec.json"),
        seal_manifest=seal_manifest,
        evidence_manifest=_read_json(tmp_path / "inputs" / "EvidenceManifest.json"),
        locked_spec_schema=_read_json(schemas_root / "LockedSpec.schema.json"),
        seal_manifest_schema=_read_json(schemas_root / "SealManifest.schema.json"),
        evidence_manifest_schema=_read_json(schemas_root / "EvidenceManifest.schema.json"),
        gate_verdict_schema=_read_json(schemas_root / "GateVerdict.schema.json"),
        waiver_schema=_read_json(schemas_root / "Waiver.schema.json"),
        replay_instructions_schema=replay_schema,
        tier_id="tier-1",
        run_id="run",
    )


def test_s2_replay_instructions_missing_source_archive_ref_fails(tmp_path: Path) -> None:
    replay_doc = {"note": "missing source"}
    replay_bytes = json.dumps(replay_doc, sort_keys=True).encode("utf-8")
    replay_ref = {
        "id": "replay-1",
        "hash": _sha256_hex(replay_bytes),
        "storage_ref": "temp/replay/replay.json",
    }
    _write_bytes_rel(tmp_path, replay_ref["storage_ref"], replay_bytes)

    ctx = _build_s2_ctx(tmp_path, replay_ref=replay_ref)
    results = s2_objectref_binding.run(ctx)
    assert len(results) == 1
    assert results[0].status == "FAIL"
    assert results[0].pointers == ["temp/replay/replay.json#/source_archive_ref"]


def test_s2_replay_instructions_ref_hash_mismatch_fails(tmp_path: Path) -> None:
    replay_doc = {"source_archive_ref": {"id": "src", "hash": "0" * 64, "storage_ref": "temp/src.tar"}}
    replay_bytes = json.dumps(replay_doc, sort_keys=True).encode("utf-8")
    replay_ref = {
        "id": "replay-1",
        "hash": "f" * 64,
        "storage_ref": "temp/replay/replay.json",
    }
    _write_bytes_rel(tmp_path, replay_ref["storage_ref"], replay_bytes)

    ctx = _build_s2_ctx(tmp_path, replay_ref=replay_ref)
    results = s2_objectref_binding.run(ctx)
    assert len(results) == 1
    assert results[0].status == "FAIL"
    assert results[0].pointers == ["SealManifest.json#/replay_instructions_ref"]


def test_s2_replay_instructions_source_archive_hash_mismatch_fails(tmp_path: Path) -> None:
    src_bytes = b"archive-bytes"
    src_ref = {
        "id": "src",
        "hash": "0" * 64,
        "storage_ref": "temp/src.tar",
    }
    _write_bytes_rel(tmp_path, src_ref["storage_ref"], src_bytes)

    replay_doc = {"source_archive_ref": src_ref}
    replay_bytes = json.dumps(replay_doc, sort_keys=True).encode("utf-8")
    replay_ref = {
        "id": "replay-1",
        "hash": _sha256_hex(replay_bytes),
        "storage_ref": "temp/replay/replay.json",
    }
    _write_bytes_rel(tmp_path, replay_ref["storage_ref"], replay_bytes)

    ctx = _build_s2_ctx(tmp_path, replay_ref=replay_ref)
    results = s2_objectref_binding.run(ctx)
    assert len(results) == 1
    assert results[0].status == "FAIL"
    assert results[0].pointers == ["temp/replay/replay.json#/source_archive_ref"]


def test_s2_replay_instructions_invalid_json_fails(tmp_path: Path) -> None:
    replay_bytes = b"{not-json"
    replay_ref = {
        "id": "replay-1",
        "hash": _sha256_hex(replay_bytes),
        "storage_ref": "temp/replay/replay.json",
    }
    _write_bytes_rel(tmp_path, replay_ref["storage_ref"], replay_bytes)

    ctx = _build_s2_ctx(tmp_path, replay_ref=replay_ref)
    results = s2_objectref_binding.run(ctx)
    assert len(results) == 1
    assert results[0].status == "FAIL"
    assert results[0].pointers == ["temp/replay/replay.json#/source_archive_ref"]


def test_s2_no_replay_ref_does_not_require_schema(tmp_path: Path) -> None:
    ctx = _build_s2_ctx(tmp_path, replay_ref=None, replay_schema=None)
    results = s2_objectref_binding.run(ctx)
    assert len(results) == 1
    assert results[0].status == "PASS"
