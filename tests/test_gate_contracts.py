from __future__ import annotations

import base64
import hashlib
import importlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.repo_local

REPO_ROOT = Path(__file__).resolve().parents[1]
for _k in list(sys.modules.keys()):
    if _k == "belgi" or _k.startswith("belgi."):
        del sys.modules[_k]

import builders
from belgi.protocol.pack import MANIFEST_FILENAME, build_manifest_bytes
from chain.logic.s_checks import s2_objectref_binding
from chain.logic.s_checks.context import SCheckContext


def _taxonomy_ids(root: Path) -> set[str]:
    text = (root / "gates" / "failure-taxonomy.md").read_text(encoding="utf-8", errors="strict")
    ids = set(re.findall(r"category_id:\s*`([^`]+)`", text))
    assert ids, "taxonomy category_id tokens not parsed"
    return ids


def _run_module(module: str, args: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", module, *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
    )


def _read_json(path: Path) -> dict:
    obj = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    assert isinstance(obj, dict)
    return obj


def _clean_dir(path: Path) -> None:
    if path.exists():
        _rmtree_retry(path)
    path.mkdir(parents=True, exist_ok=True)


def _rmtree_retry(path: Path, *, attempts: int = 12, base_delay_s: float = 0.03) -> None:
    def _onerror(func, p, exc_info):
        try:
            os.chmod(p, stat.S_IWRITE)
        except Exception:
            pass
        func(p)

    last_exc: BaseException | None = None
    for i in range(attempts):
        try:
            shutil.rmtree(path, onerror=_onerror)
            return
        except (PermissionError, OSError) as e:
            last_exc = e
            if i == attempts - 1:
                raise
            time.sleep(base_delay_s * (i + 1))

    if last_exc is not None:
        raise last_exc


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _ed25519_pubkey_hex_from_seed(seed_hex: str) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return public_key.hex()


def _write_bytes_rel(root: Path, rel: str, data: bytes) -> dict[str, str]:
    p = root / Path(*rel.split("/"))
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
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
    ctx = SCheckContext(
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
    return ctx


def _walk_files_sorted(root: Path) -> list[Path]:
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        filenames.sort()
        for name in filenames:
            out.append(Path(dirpath) / name)
    return sorted(out, key=lambda p: p.relative_to(root).as_posix())


def _compute_bundle_sha256(bundle_dir: Path) -> str:
    files = []
    for p in _walk_files_sorted(bundle_dir):
        rel = p.relative_to(bundle_dir).as_posix()
        if rel == "docs_bundle_manifest.json":
            continue
        files.append((rel, _sha256_hex(p.read_bytes())))
    payload = "".join([f"{rel}\n{h}\n" for (rel, h) in files]).encode("utf-8", errors="strict")
    return _sha256_hex(payload)


def _compute_bundle_root_sha256(*, docs_bundle_manifest_sha256: str, bundle_sha256: str) -> str:
    payload = f"manifest\n{docs_bundle_manifest_sha256}\nbundle\n{bundle_sha256}\n".encode("utf-8", errors="strict")
    return _sha256_hex(payload)


def _selected_prompt_block_hashes_for_locked(locked_spec: dict[str, Any]) -> dict[str, str]:
    c1 = importlib.import_module("chain.compiler_c1_intent")
    selector = c1._prompt_block_ids_for_tier
    render = c1._render_prompt_block

    tier_obj = locked_spec.get("tier")
    assert isinstance(tier_obj, dict)
    tier_id = tier_obj.get("tier_id")
    assert isinstance(tier_id, str) and tier_id

    selected_ids = selector(tier_id)
    assert isinstance(selected_ids, list) and selected_ids

    locked_preimage = dict(locked_spec)
    locked_preimage.pop("prompt_bundle_ref", None)

    out: dict[str, str] = {}
    for block_id in selected_ids:
        rendered = render(block_id=block_id, locked_spec_preimage=locked_preimage)
        assert isinstance(rendered, (bytes, bytearray))
        out[str(block_id)] = _sha256_hex(bytes(rendered))
    return out


def test_gate_q_evidence_002_remediation_substitutes_missing_kind(tmp_path: Path) -> None:
    taxo = _taxonomy_ids(REPO_ROOT)
    paths = builders.build_q_repo(tmp_path, rel_root="gate_q/q_pass_tier0", run_id="q-evidence-002")
    intent_rel = paths["intent"]
    locked_rel = paths["locked"]
    em = _read_json(tmp_path / paths["evidence"])
    artifacts = em.get("artifacts")
    assert isinstance(artifacts, list)
    em["artifacts"] = [a for a in artifacts if isinstance(a, dict) and a.get("kind") != "command_log"]
    em_rel = "out/EvidenceManifest.missing_command_log.json"
    em_path = tmp_path / Path(*em_rel.split("/"))
    em_path.parent.mkdir(parents=True, exist_ok=True)
    em_path.write_text(json.dumps(em, indent=2, sort_keys=True) + "\n", encoding="utf-8", errors="strict")
    out_rel = "out/GateVerdict.Q.missing_command_log.json"
    out_path = tmp_path / Path(*out_rel.split("/"))

    cp = _run_module(
        "chain.gate_q_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--intent-spec",
            intent_rel,
            "--locked-spec",
            locked_rel,
            "--evidence-manifest",
            em_rel,
            "--out",
            out_rel,
        ],
        cwd=REPO_ROOT,
    )

    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
    gv = _read_json(out_path)

    assert gv.get("failure_category") == "FQ-EVIDENCE-MISSING"
    assert gv.get("failure_category") in taxo

    remediation = ((gv.get("remediation") or {}).get("next_instruction"))
    assert isinstance(remediation, str)
    assert "command_log" in remediation
    assert "missing_kind" not in remediation


def test_gate_q_taxonomy_mismatch_is_internal_error_and_no_output(tmp_path: Path) -> None:
    # Create a fake repo root with an incomplete taxonomy, proving verifiers fail-closed
    # (exit code 3) and do not emit a GateVerdict.
    fake_root = tmp_path / "fake_repo"
    _clean_dir(fake_root)

    # Under pack-truth, Gate Q loads taxonomy/schemas/tiers from the active protocol pack.
    # Build a minimal valid protocol pack with an incomplete taxonomy so category validation fails.
    pack_root = fake_root / "protocol_pack"
    pack_root.mkdir(parents=True, exist_ok=True)

    def _copy_into_pack(rel: str) -> None:
        src = REPO_ROOT / Path(*rel.split("/"))
        dst = pack_root / Path(*rel.split("/"))
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(src.read_bytes())

    _copy_into_pack("tiers/tier-packs.md")
    _copy_into_pack("tiers/tier-packs.json")
    for rel in [
        "schemas/IntentSpec.schema.json",
        "schemas/LockedSpec.schema.json",
        "schemas/EvidenceManifest.schema.json",
        "schemas/Waiver.schema.json",
        "schemas/HOTLApproval.schema.json",
        "schemas/ToolchainSet.schema.json",
        "schemas/Tolerances.schema.json",
        "schemas/GateVerdict.schema.json",
    ]:
        _copy_into_pack(rel)

    (pack_root / "gates").mkdir(parents=True, exist_ok=True)
    (pack_root / "gates" / "failure-taxonomy.md").write_text(
        "# Fake taxonomy\n\n- category_id: `FQ-NOT-THE-ONE`\n",
        encoding="utf-8",
        errors="strict",
    )
    (pack_root / MANIFEST_FILENAME).write_bytes(build_manifest_bytes(pack_root=pack_root, pack_name="test-pack"))

    paths = builders.build_q_repo(
        fake_root,
        rel_root="gate_q/q_intent_001_no_yaml_block",
        run_id="q-taxonomy-mismatch",
    )
    (fake_root / paths["intent"]).write_text("# Intent\nNo YAML block here.\n", encoding="utf-8", errors="strict")

    # Note: out is repo-relative *to fake_root*, not REPO_ROOT.
    out_path = fake_root / "out" / "GateVerdict.json"

    cp = _run_module(
        "chain.gate_q_verify",
        [
            "--repo",
            str(fake_root),
            "--protocol-pack",
            "protocol_pack",
            "--intent-spec",
            paths["intent"],
            "--locked-spec",
            paths["locked"],
            "--evidence-manifest",
            paths["evidence"],
            "--out",
            "out/GateVerdict.json",
        ],
        cwd=REPO_ROOT,
    )

    assert cp.returncode == 3, (cp.returncode, cp.stdout, cp.stderr)
    assert "category_id not in taxonomy" in cp.stderr
    assert not out_path.exists()


def test_c3_docs_bundle_is_deterministic_and_profile_scoped(tmp_path: Path) -> None:
    fake_root = tmp_path / "c3_bundle_repo"
    _clean_dir(fake_root)

    def _copy_rel(rel: str) -> None:
        src = REPO_ROOT / Path(*rel.split("/"))
        dst = fake_root / Path(*rel.split("/"))
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(src, dst, dirs_exist_ok=True)
        else:
            dst.write_bytes(src.read_bytes())

    # Minimal repo surface needed by C3 bundle enumeration and schema validation.
    for rel in [
        "CANONICALS.md",
        "terminology.md",
        "trust-model.md",
        "gates",
        "tiers",
        "schemas",
        "docs/operations",
        "belgi/templates",
        "docs/research",
    ]:
        _copy_rel(rel)
    assert not (fake_root / ".belgi" / "engine" / "c3_canonicals").exists()

    # Inputs (in fake repo): LockedSpec, GateVerdicts, and snapshot EvidenceManifests.
    synthetic_r = builders.build_r_repo(fake_root, rel_root="inputs/r_pass_tier1", run_id="c3-bundle")
    locked_rel = synthetic_r["locked"]
    q_rel = "inputs/GateVerdict.Q.json"
    r_rel = "inputs/GateVerdict.R.json"
    qsnap_rel = "inputs/EvidenceManifest.Q.json"
    rsnap_rel = "inputs/EvidenceManifest.R.json"

    run_id = _read_json(fake_root / Path(*locked_rel.split("/"))).get("run_id")
    assert isinstance(run_id, str) and run_id

    # Prompt block hashes mapping follows selected-only contract for the locked tier.
    locked_obj = _read_json(fake_root / Path(*locked_rel.split("/")))
    pb_hashes = _selected_prompt_block_hashes_for_locked(locked_obj)
    pb_rel = "inputs/prompt_block_hashes.json"
    (fake_root / Path(*pb_rel.split("/"))).write_text(
        json.dumps(pb_hashes, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
    )

    def _write_json(root: Path, rel: str, obj: dict) -> None:
        p = root / Path(*rel.split("/"))
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8", errors="strict")

    def _object_ref(*, obj_id: str, storage_ref: str, file_bytes: bytes) -> dict:
        return {"id": obj_id, "storage_ref": storage_ref, "hash": _sha256_hex(file_bytes)}

    # Q-snapshot EvidenceManifest (must exist for GateVerdict.Q.evidence_manifest_ref).
    qsnap_obj = {
        "schema_version": "1.0.0",
        "run_id": run_id,
        "artifacts": [
            {
                "kind": "schema_validation",
                "id": "locked_spec",
                "hash": _sha256_hex((fake_root / Path(*locked_rel.split("/"))).read_bytes()),
                "media_type": "application/json",
                "storage_ref": locked_rel,
                "produced_by": "R",
            }
        ],
        "commands_executed": ["fixture"],
        "envelope_attestation": None,
    }
    _write_json(fake_root, qsnap_rel, qsnap_obj)
    qsnap_bytes = (fake_root / Path(*qsnap_rel.split("/"))).read_bytes()

    qv_obj = {
        "schema_version": "1.0.0",
        "run_id": run_id,
        "gate_id": "Q",
        "verdict": "GO",
        "failure_category": None,
        "failures": [],
        "evidence_manifest_ref": _object_ref(obj_id="evidence.q_snapshot", storage_ref=qsnap_rel, file_bytes=qsnap_bytes),
        "evaluated_at": "1970-01-01T00:00:00Z",
        "evaluator": "fixture",
    }
    _write_json(fake_root, q_rel, qv_obj)
    qv_bytes = (fake_root / Path(*q_rel.split("/"))).read_bytes()

    # R-snapshot EvidenceManifest must index LockedSpec + GateVerdict.Q by (storage_ref, sha256).
    rsnap_obj = {
        "schema_version": "1.0.0",
        "run_id": run_id,
        "artifacts": [
            {
                "kind": "schema_validation",
                "id": "locked_spec",
                "hash": _sha256_hex((fake_root / Path(*locked_rel.split("/"))).read_bytes()),
                "media_type": "application/json",
                "storage_ref": locked_rel,
                "produced_by": "R",
            },
            {
                "kind": "schema_validation",
                "id": "gate_q_verdict",
                "hash": _sha256_hex(qv_bytes),
                "media_type": "application/json",
                "storage_ref": q_rel,
                "produced_by": "R",
            },
        ],
        "commands_executed": ["fixture"],
        "envelope_attestation": None,
    }
    _write_json(fake_root, rsnap_rel, rsnap_obj)
    rsnap_bytes = (fake_root / Path(*rsnap_rel.split("/"))).read_bytes()

    rv_obj = {
        "schema_version": "1.0.0",
        "run_id": run_id,
        "gate_id": "R",
        "verdict": "GO",
        "failure_category": None,
        "failures": [],
        "evidence_manifest_ref": _object_ref(obj_id="evidence.r_snapshot", storage_ref=rsnap_rel, file_bytes=rsnap_bytes),
        "evaluated_at": "1970-01-01T00:00:00Z",
        "evaluator": "fixture",
    }
    _write_json(fake_root, r_rel, rv_obj)

    # Outputs (in fake repo). Note: --out-log is canonical and fixed.
    out_log_rel = "docs/docs_compilation_log.json"

    def _run_c3(
        profile: str,
        *,
        out_final_rel: str,
        out_docs_rel: str,
        out_bundle_dir_rel: str,
        out_root_sha_rel: str,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "chain.compiler_c3_docs",
                "--repo",
                str(fake_root),
                "--locked-spec",
                locked_rel,
                "--gate-q-verdict",
                q_rel,
                "--gate-r-verdict",
                r_rel,
                "--r-snapshot-manifest",
                rsnap_rel,
                "--out-final-manifest",
                out_final_rel,
                "--out-log",
                out_log_rel,
                "--out-docs",
                out_docs_rel,
                "--out-bundle-dir",
                out_bundle_dir_rel,
                "--out-bundle-root-sha",
                out_root_sha_rel,
                "--profile",
                profile,
                "--prompt-block-hashes",
                pb_rel,
                "--generated-at",
                "1970-01-01T00:00:00Z",
            ],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
        )

    def _outs(prefix: str) -> dict[str, str]:
        base = prefix.rstrip("/")
        return {
            "out_final_rel": f"{base}/EvidenceManifest.final.json",
            "out_docs_rel": f"{base}/docs.md",
            "out_bundle_dir_rel": f"{base}/bundle",
            "out_root_sha_rel": f"{base}/bundle_root.sha256",
        }

    def _clean_outputs() -> None:
        for rel in ["out", "docs/docs_compilation_log.json"]:
            p = fake_root / Path(*rel.split("/"))
            if p.is_dir():
                _rmtree_retry(p)
            elif p.exists():
                p.unlink()

    # Run twice and compare deterministic outputs.
    outs1 = {
        "out_final_rel": "out/EvidenceManifest.final.json",
        "out_docs_rel": "out/docs.md",
        "out_bundle_dir_rel": "out/bundle",
        "out_root_sha_rel": "out/bundle_root.sha256",
    }

    cp1 = _run_c3("public", **outs1)
    assert cp1.returncode == 0, (cp1.returncode, cp1.stdout, cp1.stderr)

    pb_path = fake_root / Path(*pb_rel.split("/"))
    selected_ids = list(pb_hashes.keys())
    assert selected_ids
    selected_first = selected_ids[0]

    # Selected-only contract: missing selected hash must fail closed.
    pb_missing = dict(pb_hashes)
    pb_missing.pop(selected_first)
    pb_path.write_text(json.dumps(pb_missing, indent=2, sort_keys=True) + "\n", encoding="utf-8", errors="strict")
    cp_missing_selected = _run_c3(
        "public",
        out_final_rel="out/missing_selected/EvidenceManifest.final.json",
        out_docs_rel="out/missing_selected/docs.md",
        out_bundle_dir_rel="out/missing_selected/bundle",
        out_root_sha_rel="out/missing_selected/bundle_root.sha256",
    )
    assert cp_missing_selected.returncode == 2, (
        cp_missing_selected.returncode,
        cp_missing_selected.stdout,
        cp_missing_selected.stderr,
    )
    assert "missing/invalid selected block hashes" in cp_missing_selected.stderr
    assert selected_first in cp_missing_selected.stderr

    # Selected-only contract: mismatched selected hash must fail closed.
    pb_mismatch = dict(pb_hashes)
    pb_mismatch[selected_first] = "f" * 64
    pb_path.write_text(json.dumps(pb_mismatch, indent=2, sort_keys=True) + "\n", encoding="utf-8", errors="strict")
    cp_mismatch_selected = _run_c3(
        "public",
        out_final_rel="out/mismatch_selected/EvidenceManifest.final.json",
        out_docs_rel="out/mismatch_selected/docs.md",
        out_bundle_dir_rel="out/mismatch_selected/bundle",
        out_root_sha_rel="out/mismatch_selected/bundle_root.sha256",
    )
    assert cp_mismatch_selected.returncode == 2, (
        cp_mismatch_selected.returncode,
        cp_mismatch_selected.stdout,
        cp_mismatch_selected.stderr,
    )
    assert "mismatch for selected block" in cp_mismatch_selected.stderr
    assert selected_first in cp_mismatch_selected.stderr

    # Extra non-selected keys are allowed and ignored.
    pb_with_extra = dict(pb_hashes)
    pb_with_extra["PB-999"] = "0" * 64
    pb_path.write_text(json.dumps(pb_with_extra, indent=2, sort_keys=True) + "\n", encoding="utf-8", errors="strict")
    cp_extra_selected = _run_c3(
        "public",
        out_final_rel="out/extra_selected/EvidenceManifest.final.json",
        out_docs_rel="out/extra_selected/docs.md",
        out_bundle_dir_rel="out/extra_selected/bundle",
        out_root_sha_rel="out/extra_selected/bundle_root.sha256",
    )
    assert cp_extra_selected.returncode == 0, (
        cp_extra_selected.returncode,
        cp_extra_selected.stdout,
        cp_extra_selected.stderr,
    )

    # Restore baseline selected-only hashes.
    pb_path.write_text(json.dumps(pb_hashes, indent=2, sort_keys=True) + "\n", encoding="utf-8", errors="strict")

    # C3 protocol identity enforcement: mismatch must fail closed with stable failure id.
    locked_path = fake_root / Path(*locked_rel.split("/"))
    locked_original_bytes = locked_path.read_bytes()
    locked_obj = _read_json(locked_path)
    protocol_pack_obj = locked_obj.get("protocol_pack")
    assert isinstance(protocol_pack_obj, dict)
    protocol_pack_obj["pack_id"] = "0" * 64
    locked_path.write_text(
        json.dumps(locked_obj, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
    )
    cp_identity_fail = _run_c3(
        "public",
        out_final_rel="out/identity_mismatch/EvidenceManifest.final.json",
        out_docs_rel="out/identity_mismatch/docs.md",
        out_bundle_dir_rel="out/identity_mismatch/bundle",
        out_root_sha_rel="out/identity_mismatch/bundle_root.sha256",
    )
    assert cp_identity_fail.returncode == 2, (
        cp_identity_fail.returncode,
        cp_identity_fail.stdout,
        cp_identity_fail.stderr,
    )
    assert "C3-PROTOCOL-IDENTITY-MISMATCH" in cp_identity_fail.stderr
    assert "CANONICALS.md#protocol-pack-identity" in cp_identity_fail.stderr
    locked_path.write_bytes(locked_original_bytes)

    # Re-run baseline outputs so docs_compilation_log reflects outs1 paths after
    # selected-hash negative cases.
    cp1_rebaseline = _run_c3("public", **outs1)
    assert cp1_rebaseline.returncode == 0, (
        cp1_rebaseline.returncode,
        cp1_rebaseline.stdout,
        cp1_rebaseline.stderr,
    )

    bundle_dir1 = fake_root / Path(*outs1["out_bundle_dir_rel"].split("/"))
    m1 = (bundle_dir1 / "docs_bundle_manifest.json").read_bytes()
    root1 = (fake_root / Path(*outs1["out_root_sha_rel"].split("/"))).read_text(encoding="utf-8", errors="strict")

    # Public profile must not include internal-only roots.
    assert not (bundle_dir1 / "belgi" / "research").exists()

    # Final manifest must append exactly one artifact beyond the R-snapshot.
    rsnap_loaded = _read_json(fake_root / Path(*rsnap_rel.split("/")))
    final_loaded = _read_json(fake_root / Path(*outs1["out_final_rel"].split("/")))
    rsnap_arts = rsnap_loaded.get("artifacts")
    final_arts = final_loaded.get("artifacts")
    assert isinstance(rsnap_arts, list) and isinstance(final_arts, list)
    assert len(final_arts) == len(rsnap_arts) + 1
    new_art = [a for a in final_arts if isinstance(a, dict) and a.get("id") == "docs.compilation_log"]
    assert len(new_art) == 1
    assert new_art[0].get("kind") == "docs_compilation_log"
    assert new_art[0].get("storage_ref") == "docs/docs_compilation_log.json"
    assert new_art[0].get("produced_by") == "C3"

    # docs_compilation_log must bind output paths + hashes in payload.outputs.
    log_obj = _read_json(fake_root / Path(*out_log_rel.split("/")))
    outputs = log_obj.get("outputs")
    assert isinstance(outputs, dict)
    for k in [
        "bundle_sha256",
        "docs_bundle_manifest_sha256",
        "bundle_root_sha256",
        "docs_markdown",
        "bundle_manifest",
        "bundle_toc",
        "bundle_root_sha_file",
        "bundle_dir",
    ]:
        assert k in outputs
    assert outputs["bundle_dir"] == outs1["out_bundle_dir_rel"]
    assert outputs["bundle_manifest"]["path"] == f"{outs1['out_bundle_dir_rel']}/docs_bundle_manifest.json"
    assert outputs["bundle_toc"]["path"] == f"{outs1['out_bundle_dir_rel']}/TOC.md"
    assert outputs["docs_markdown"]["path"] == outs1["out_docs_rel"]
    assert outputs["bundle_root_sha_file"]["path"] == outs1["out_root_sha_rel"]

    # Cleanup may fail on Windows due to transient file locks. If so, fall back to unique output dirs.
    outs2 = outs1
    try:
        _clean_outputs()
    except (PermissionError, OSError):
        outs2 = _outs("out/run2")

    cp2 = _run_c3("public", **outs2)
    assert cp2.returncode == 0, (cp2.returncode, cp2.stdout, cp2.stderr)

    bundle_dir2 = fake_root / Path(*outs2["out_bundle_dir_rel"].split("/"))
    m2 = (bundle_dir2 / "docs_bundle_manifest.json").read_bytes()
    root2 = (fake_root / Path(*outs2["out_root_sha_rel"].split("/"))).read_text(encoding="utf-8", errors="strict")
    assert m2 == m1
    assert root2 == root1

    # Non-circular hashing: bundle_sha excludes manifest bytes.
    manifest_obj = json.loads(m2.decode("utf-8"))
    bundle_sha = _compute_bundle_sha256(bundle_dir2)
    assert manifest_obj["bundle_sha256"] == bundle_sha

    # Reformat only the manifest file and confirm bundle_sha unchanged but root changes.
    (bundle_dir2 / "docs_bundle_manifest.json").write_text(
        json.dumps(manifest_obj, indent=4, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
    )
    bundle_sha2 = _compute_bundle_sha256(bundle_dir2)
    assert bundle_sha2 == bundle_sha
    manifest_sha2 = _sha256_hex((bundle_dir2 / "docs_bundle_manifest.json").read_bytes())
    root2_calc = _compute_bundle_root_sha256(docs_bundle_manifest_sha256=manifest_sha2, bundle_sha256=bundle_sha)
    assert root2_calc.strip() != root1.strip()

    # Tampering: changing any bundled file changes bundle_sha deterministically.
    target = bundle_dir2 / "CANONICALS.md"
    target.write_text(
        target.read_text(encoding="utf-8", errors="strict") + "tamper\n",
        encoding="utf-8",
        errors="strict",
    )
    assert _compute_bundle_sha256(bundle_dir2) != bundle_sha

    # Internal profile includes docs/research/** as allowed by template.
    outs3 = _outs("out/internal")
    cp3 = _run_c3("internal", **outs3)
    assert cp3.returncode == 0, (cp3.returncode, cp3.stdout, cp3.stderr)

    # Contract guard: C3 must fail if the R-snapshot manifest does not index GateVerdict(Q).
    rsnap_obj_missing_q = {
        "schema_version": "1.0.0",
        "run_id": run_id,
        "artifacts": [
            {
                "kind": "schema_validation",
                "id": "locked_spec",
                "hash": _sha256_hex((fake_root / Path(*locked_rel.split("/"))).read_bytes()),
                "media_type": "application/json",
                "storage_ref": locked_rel,
                "produced_by": "R",
            }
        ],
        "commands_executed": ["fixture"],
        "envelope_attestation": None,
    }
    _write_json(fake_root, rsnap_rel, rsnap_obj_missing_q)
    rsnap_bytes2 = (fake_root / Path(*rsnap_rel.split("/"))).read_bytes()
    rv_obj2 = dict(rv_obj)
    rv_obj2["evidence_manifest_ref"] = _object_ref(
        obj_id="evidence.r_snapshot",
        storage_ref=rsnap_rel,
        file_bytes=rsnap_bytes2,
    )
    _write_json(fake_root, r_rel, rv_obj2)

    cp_bad = _run_c3(
        "public",
        out_final_rel="docs/out_final_manifest.bad.json",
        out_docs_rel="docs/out_docs.bad.md",
        out_bundle_dir_rel="docs/out_bundle.bad",
        out_root_sha_rel="docs/out_bundle_root_sha.bad.txt",
    )
    assert cp_bad.returncode == 2, (cp_bad.returncode, cp_bad.stdout, cp_bad.stderr)
    assert (
        ("GateVerdict.Q.json" in cp_bad.stderr and "storage_ref" in cp_bad.stderr)
        or ("gate_q_verdict" in cp_bad.stderr)
        or ("GateVerdict(Q)" in cp_bad.stderr)
    )


def test_gate_r_snapshot_index_hash_mismatch_is_no_go(tmp_path: Path) -> None:
    """Gate R must fail-closed if a required snapshot index entry exists but hash mismatches bytes."""

    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)

    fixture_dir = "gate_r/r_pass_tier1"
    paths = _copy_fixture_inputs(REPO_ROOT, tmp_path, fixture_dir)
    _sync_locked_spec_protocol_identity(
        tmp_path / paths["locked"],
        tmp_path / "protocol_pack" / MANIFEST_FILENAME,
    )

    (tmp_path / "inputs").mkdir(parents=True, exist_ok=True)
    gate_q_rel = "inputs/GateVerdict.Q.json"
    (tmp_path / "inputs" / "GateVerdict.Q.json").write_text(
        json.dumps({"schema_version": "1.0.0", "run_id": "fixture", "gate_id": "Q", "verdict": "GO"}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    # Inject a WRONG hash for LockedSpec into the evidence manifest.
    em_path = tmp_path / paths["evidence"]
    em = json.loads(em_path.read_text(encoding="utf-8", errors="strict"))
    assert isinstance(em, dict)
    artifacts = em.get("artifacts")
    assert isinstance(artifacts, list)
    locked_sr = paths["locked"]
    artifacts.append(
        {
            "kind": "schema_validation",
            "id": "locked_spec",
            "hash": "0" * 64,
            "media_type": "application/json",
            "storage_ref": locked_sr,
            "produced_by": "R",
        }
    )
    em_path.write_text(json.dumps(em, indent=2, sort_keys=True) + "\n", encoding="utf-8", errors="strict", newline="\n")

    commit_sha = _init_git_repo(tmp_path)

    (tmp_path / "out").mkdir(parents=True, exist_ok=True)

    out_rel = "out/GateVerdict.json"
    snap_rel = "out/EvidenceManifest.r_snapshot.json"
    cp = _run_module(
        "chain.gate_r_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            paths["locked"],
            "--gate-q-verdict",
            gate_q_rel,
            "--evidence-manifest",
            paths["evidence"],
            "--r-snapshot-manifest-out",
            snap_rel,
            "--evaluated-revision",
            commit_sha,
            "--out",
            out_rel,
        ],
        cwd=REPO_ROOT,
    )
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
    gv = _read_json(tmp_path / "out" / "GateVerdict.json")
    assert gv.get("failure_category") == "FR-INVARIANT-FAILED"


def test_gate_r_snapshot_manifest_write_failure_is_no_go(tmp_path: Path) -> None:
    """Gate R must NO-GO if it cannot write the R-snapshot manifest (fail-closed)."""

    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)

    fixture_dir = "gate_r/r_pass_tier1"
    paths = _copy_fixture_inputs(REPO_ROOT, tmp_path, fixture_dir)
    _sync_locked_spec_protocol_identity(
        tmp_path / paths["locked"],
        tmp_path / "protocol_pack" / MANIFEST_FILENAME,
    )

    (tmp_path / "inputs").mkdir(parents=True, exist_ok=True)
    gate_q_rel = "inputs/GateVerdict.Q.json"
    (tmp_path / "inputs" / "GateVerdict.Q.json").write_text(
        json.dumps({"schema_version": "1.0.0", "run_id": "fixture", "gate_id": "Q", "verdict": "GO"}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    commit_sha = _init_git_repo(tmp_path)

    (tmp_path / "out").mkdir(parents=True, exist_ok=True)
    # Ensure snapshot write fails deterministically (parent is a file, not a directory).
    (tmp_path / "nope_dir").write_text("not a directory\n", encoding="utf-8", errors="strict", newline="\n")

    cp = _run_module(
        "chain.gate_r_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            paths["locked"],
            "--gate-q-verdict",
            gate_q_rel,
            "--evidence-manifest",
            paths["evidence"],
            "--r-snapshot-manifest-out",
            "nope_dir/EvidenceManifest.r_snapshot.json",
            "--evaluated-revision",
            commit_sha,
            "--out",
            "out/verify_report.json",
            "--gate-verdict-out",
            "out/GateVerdict.json",
        ],
        cwd=REPO_ROOT,
    )
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
    report = _read_json(tmp_path / "out" / "verify_report.json")
    results = _report_results(report)
    assert [str(row.get("check_id")) for row in results] == [
        "PROTOCOL-IDENTITY-001",
        "R-SNAPSHOT-INDEX-001",
    ]
    assert [str(row.get("status")) for row in results] == ["PASS", "FAIL"]
    assert "Failed to write R-snapshot EvidenceManifest:" in str(results[1].get("message"))
    assert str(results[1].get("remediation_next_instruction")) == (
        "Do fix filesystem permissions/paths so Gate R can write the R-snapshot manifest and establish the persisted evidence anchor, then re-run R."
    )
    gv = _read_json(tmp_path / "out" / "GateVerdict.json")
    assert gv.get("failure_category") == "FR-INVARIANT-FAILED"
    failures = gv.get("failures")
    assert isinstance(failures, list) and failures
    assert failures[0].get("rule_id") == "R-SNAPSHOT-INDEX-001"


def test_gate_r_non_fixture_requires_git_for_revision_resolution(tmp_path: Path) -> None:
    """Outside fixture context, Gate R must remain strict about git commit resolution."""

    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)

    (tmp_path / "inputs").mkdir(parents=True, exist_ok=True)

    (tmp_path / "inputs" / "LockedSpec.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "run_id": "test-non-fixture",
                "tier": {"tier_id": "tier-1"},
                "upstream_state": {"commit_sha": "a" * 40, "dirty_flag": False, "repo_ref": "fixture"},
                "protocol_pack": {
                    "pack_id": "0" * 64,
                    "manifest_sha256": "0" * 64,
                    "pack_name": "fixture",
                    "source": "builtin",
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    (tmp_path / "inputs" / "EvidenceManifest.json").write_text(
        json.dumps({"schema_version": "1.0.0", "run_id": "test-non-fixture", "artifacts": []}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    (tmp_path / "inputs" / "GateVerdict.Q.json").write_text(
        json.dumps({"schema_version": "1.0.0", "run_id": "test-non-fixture", "gate_id": "Q", "verdict": "GO"}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    cp = _run_module(
        "chain.gate_r_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            "inputs/LockedSpec.json",
            "--gate-q-verdict",
            "inputs/GateVerdict.Q.json",
            "--evidence-manifest",
            "inputs/EvidenceManifest.json",
            "--evaluated-revision",
            "b" * 40,
            "--out",
            "out/verify_report.json",
            "--gate-verdict-out",
            "out/GateVerdict.json",
        ],
        cwd=REPO_ROOT,
    )

    assert cp.returncode == 3, (cp.returncode, cp.stdout, cp.stderr)
    assert "rev-parse" in (cp.stderr or "")


# =============================================================================
# Protocol identity mismatch tests (use tmp_path for isolation)
# =============================================================================


def _setup_fake_repo_with_pack(tmp_path: Path, builtin_pack_root: Path) -> Path:
    """Copy builtin protocol pack into tmp_path for testing. Returns pack_root."""
    pack_root = tmp_path / "protocol_pack"
    shutil.copytree(builtin_pack_root, pack_root, dirs_exist_ok=True)
    return pack_root


def _init_git_repo(repo_root: Path) -> str:
    import subprocess

    def _git(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args],
            cwd=str(repo_root),
            check=True,
            capture_output=True,
            text=True,
        )

    _git("init")
    _git("config", "user.email", "ci@example.invalid")
    _git("config", "user.name", "ci")
    _git("config", "core.autocrlf", "false")
    _git("add", "-A")
    _git("commit", "--allow-empty", "-m", "init")
    cp = _git("rev-parse", "HEAD")
    sha = cp.stdout.strip()
    assert sha and len(sha) >= 7
    return sha



def _git_commit_allow_empty(repo_path: Path, msg: str) -> str:
    subprocess.run(["git", "commit", "--allow-empty", "-m", msg], cwd=repo_path, check=True, capture_output=True)
    result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo_path, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def _git_tree_sha(repo_path: Path) -> str:
    result = subprocess.run(["git", "rev-parse", "HEAD^{tree}"], cwd=repo_path, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def test_sweep_repo_revision_uses_tree_sha_stable_under_empty_commit(tmp_path: Path) -> None:
    """Tree SHA is stable for identical trees (empty commit must not change it)."""

    (tmp_path / "a.txt").write_text("hello\n", encoding="utf-8", errors="strict", newline="\n")
    head1 = _init_git_repo(tmp_path)
    tree1 = _git_tree_sha(tmp_path)

    head2 = _git_commit_allow_empty(tmp_path, "empty")
    tree2 = _git_tree_sha(tmp_path)

    assert head2 != head1
    assert tree2 == tree1

    # Also validate tools/sweep.py helper matches git output.
    from tools.sweep import _git_tree_sha as sweep_git_tree_sha

    assert sweep_git_tree_sha(tmp_path) == tree1


def test_sweep_repo_revision_ignores_consistency_sweep_outputs(tmp_path: Path) -> None:
    (tmp_path / "policy").mkdir(parents=True, exist_ok=True)
    (tmp_path / "policy" / "consistency_sweep.json").write_text(
        "{\"artifact_id\":\"policy.consistency_sweep\"}\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    (tmp_path / "policy" / "consistency_sweep.summary.md").write_text(
        "# summary\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    (tmp_path / "a.txt").write_text("hello\n", encoding="utf-8", errors="strict", newline="\n")
    _init_git_repo(tmp_path)

    from tools.sweep import (
        CANONICAL_SWEEP_OUT,
        CANONICAL_SWEEP_SUMMARY,
        _git_tree_sha_excluding,
    )
    from tools.sweep import _git_tree_sha as sweep_git_tree_sha

    tree_full_1 = sweep_git_tree_sha(tmp_path)
    tree_ex_1 = _git_tree_sha_excluding(tmp_path, [CANONICAL_SWEEP_OUT, CANONICAL_SWEEP_SUMMARY])

    (tmp_path / "policy" / "consistency_sweep.json").write_text(
        "{\"artifact_id\":\"policy.consistency_sweep\",\"v\":2}\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    subprocess.run(["git", "add", "policy/consistency_sweep.json"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "update sweep"], cwd=tmp_path, check=True, capture_output=True)

    tree_full_2 = sweep_git_tree_sha(tmp_path)
    tree_ex_2 = _git_tree_sha_excluding(tmp_path, [CANONICAL_SWEEP_OUT, CANONICAL_SWEEP_SUMMARY])

    assert tree_full_2 != tree_full_1
    assert tree_ex_2 == tree_ex_1


def test_sweep_repo_revision_blob_override_changes_tree(tmp_path: Path) -> None:
    (tmp_path / "policy").mkdir(parents=True, exist_ok=True)
    (tmp_path / "policy" / "consistency_sweep.json").write_text(
        "{\"artifact_id\":\"policy.consistency_sweep\"}\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    (tmp_path / "a.txt").write_text("hello\n", encoding="utf-8", errors="strict", newline="\n")
    _init_git_repo(tmp_path)

    from tools.sweep import CANONICAL_SWEEP_OUT, _git_tree_sha_excluding

    tree_base = _git_tree_sha_excluding(tmp_path, [CANONICAL_SWEEP_OUT])
    tree_override = _git_tree_sha_excluding(
        tmp_path,
        [CANONICAL_SWEEP_OUT],
        blob_overrides={"a.txt": b"override\n"},
    )

    assert tree_override != tree_base


def test_sweep_repo_revision_blob_override_preserves_executable_mode(tmp_path: Path) -> None:
    """Blob override must preserve 100755 filemode to avoid CI tree-hash drift."""

    (tmp_path / "x.sh").write_text("echo hi\n", encoding="utf-8", errors="strict", newline="\n")
    _init_git_repo(tmp_path)

    subprocess.run(["git", "config", "core.filemode", "true"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "add", "x.sh"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "update-index", "--chmod=+x", "x.sh"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "add exec"], cwd=tmp_path, check=True, capture_output=True)

    from tools.sweep import _git_tree_sha_excluding

    tree_override = _git_tree_sha_excluding(tmp_path, [], blob_overrides={"x.sh": b"override\n"})
    cp = subprocess.run(
        ["git", "ls-tree", tree_override, "--", "x.sh"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    )
    # Format: "100755 blob <sha>\tx.sh"
    mode = cp.stdout.strip().split(" ", 1)[0]
    assert mode == "100755"


def test_cs_byte_001_tracked_only_ignores_untracked_crlf(tmp_path: Path) -> None:
    """Byte Guard scan in tracked-only mode must not fail on untracked drift."""

    # Tracked clean file.
    (tmp_path / "tracked_lf.txt").write_text("ok\n", encoding="utf-8", errors="strict", newline="\n")
    _init_git_repo(tmp_path)

    # Untracked CRLF file.
    (tmp_path / "untracked_crlf.txt").write_bytes(b"bad\r\n")

    from tools.normalize import scan_byte_guard

    report = scan_byte_guard(tmp_path, tracked_only=True, mode="check")
    assert report["status"] == "PASS"
    assert report["counts"]["drift_files"] == 0


def test_cs_byte_001_tracked_only_fails_on_tracked_crlf(tmp_path: Path) -> None:
    """Byte Guard scan in tracked-only mode must fail on tracked CRLF drift."""

    (tmp_path / "good.txt").write_text("ok\n", encoding="utf-8", errors="strict", newline="\n")
    _init_git_repo(tmp_path)

    (tmp_path / "tracked_crlf.txt").write_bytes(b"line1\r\nline2\r\n")
    subprocess.run(["git", "add", "tracked_crlf.txt"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "add crlf"], cwd=tmp_path, check=True, capture_output=True)

    from tools.normalize import scan_byte_guard

    report = scan_byte_guard(tmp_path, tracked_only=True, mode="check")
    assert report["status"] == "FAIL"
    paths = sorted(d["path"] for d in report["drift_files"])
    assert paths == ["tracked_crlf.txt"]


def test_byte_guard_reports_binary_extension_unsafe_hits(tmp_path: Path) -> None:
    """Binary-extension files are skipped from 'checked' but unsafe drift paths must be reported."""

    (tmp_path / "ok.txt").write_text("ok\n", encoding="utf-8", errors="strict", newline="\n")
    _init_git_repo(tmp_path)

    # Track a binary-extension file with CRLF.
    (tmp_path / "file.pdf").write_bytes(b"%PDF-1.4\r\n")
    subprocess.run(["git", "add", "file.pdf"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "add pdf"], cwd=tmp_path, check=True, capture_output=True)

    from tools.normalize import scan_byte_guard

    report = scan_byte_guard(tmp_path, tracked_only=True, mode="check")
    assert report["status"] == "PASS"
    assert report["counts"]["skipped"] >= 1
    unsafe = report.get("unsafe_drift_files")
    assert isinstance(unsafe, list)
    paths = sorted(d["path"] for d in unsafe if isinstance(d, dict) and isinstance(d.get("path"), str))
    assert paths == ["file.pdf"]


def _copy_fixture_inputs(
    fixture_root: Path, fake_root: Path, fixture_dir: str, include_locked: bool = True
) -> dict[str, str]:
    """Generate synthetic case inputs under fake_root using the historical case id."""

    if fixture_dir.endswith("q_pass_tier0"):
        paths = builders.build_q_repo(fake_root, rel_root=fixture_dir, run_id="q-pass-tier0")
    elif fixture_dir.endswith("q_intent_001_no_yaml_block"):
        paths = builders.build_q_repo(fake_root, rel_root=fixture_dir, run_id="q-intent-001")
        (fake_root / paths["intent"]).write_text("# Intent\nNo YAML block here.\n", encoding="utf-8", errors="strict")
    elif fixture_dir.endswith("r_pass_tier1"):
        paths = builders.build_r_repo(fake_root, rel_root=fixture_dir, run_id="r-pass-tier1")
    elif fixture_dir.endswith("r0_evidence_sufficiency_fail"):
        paths = builders.build_r_repo(fake_root, rel_root=fixture_dir, run_id="r0-evidence-001")
        evidence_path = fake_root / paths["evidence"]
        evidence = _read_json(evidence_path)
        artifacts = evidence.get("artifacts")
        assert isinstance(artifacts, list)
        evidence["artifacts"] = [
            row
            for row in artifacts
            if not (
                isinstance(row, dict)
                and row.get("kind") in {"test_report", "env_attestation"}
            )
        ]
        evidence["envelope_attestation"] = None
        evidence_path.write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            errors="strict",
            newline="\n",
        )
    elif fixture_dir.endswith("s_pass_tier1_unsigned"):
        paths = builders.build_s_repo(fake_root, rel_root=fixture_dir, run_id="s-pass-tier1")
    else:
        raise AssertionError(f"unsupported synthetic case request: {fixture_dir}")

    if not include_locked:
        paths = dict(paths)
        paths.pop("locked", None)
    return paths


def _tamper_locked_spec_pack_id(locked_path: Path, new_pack_id: str) -> None:
    """Overwrite protocol_pack.pack_id in a LockedSpec file."""
    data = json.loads(locked_path.read_text(encoding="utf-8", errors="strict"))
    data["protocol_pack"]["pack_id"] = new_pack_id
    locked_path.write_text(
        json.dumps(data, indent=2, sort_keys=True), encoding="utf-8", errors="strict"
    )


def _sync_locked_spec_protocol_identity(locked_path: Path, protocol_manifest_path: Path) -> None:
    """Align LockedSpec protocol identity with the active protocol pack manifest."""
    data = json.loads(locked_path.read_text(encoding="utf-8", errors="strict"))
    manifest = json.loads(protocol_manifest_path.read_text(encoding="utf-8", errors="strict"))
    data["protocol_pack"]["pack_id"] = manifest["pack_id"]
    data["protocol_pack"]["manifest_sha256"] = _sha256_hex(protocol_manifest_path.read_bytes())
    data["protocol_pack"]["pack_name"] = manifest["pack_name"]
    locked_path.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )


def _remove_locked_spec_protocol_pack(locked_path: Path) -> None:
    """Remove protocol_pack field entirely from LockedSpec file."""
    data = json.loads(locked_path.read_text(encoding="utf-8", errors="strict"))
    del data["protocol_pack"]
    locked_path.write_text(
        json.dumps(data, indent=2, sort_keys=True), encoding="utf-8", errors="strict"
    )


def _report_results(report_obj: dict[str, Any]) -> list[dict[str, Any]]:
    results = report_obj.get("results")
    assert isinstance(results, list)
    out: list[dict[str, Any]] = []
    for row in results:
        assert isinstance(row, dict)
        out.append(row)
    return out


def _first_fail_result(results: list[dict[str, Any]]) -> dict[str, Any]:
    for row in results:
        if str(row.get("status")) == "FAIL":
            return row
    raise AssertionError("expected at least one FAIL result")


def _prepare_r_pass_tier1_fixture_repo(tmp_path: Path) -> dict[str, str]:
    return builders.build_r_repo(
        tmp_path,
        rel_root="gate_r/r_pass_tier1",
        run_id="r-pass-tier1",
    )


def _rewrite_required_report_payload_run_id(
    tmp_path: Path,
    *,
    evidence_rel: str,
    kind: str,
    artifact_id: str,
    run_id: str,
) -> None:
    evidence_path = tmp_path / evidence_rel
    evidence = _read_json(evidence_path)
    artifacts = evidence.get("artifacts")
    assert isinstance(artifacts, list)
    target = next(
        (
            row
            for row in artifacts
            if isinstance(row, dict) and row.get("kind") == kind and row.get("id") == artifact_id
        ),
        None,
    )
    assert isinstance(target, dict)
    storage_ref = target.get("storage_ref")
    assert isinstance(storage_ref, str) and storage_ref

    payload_path = tmp_path / Path(*storage_ref.split("/"))
    payload = _read_json(payload_path)
    payload["run_id"] = run_id
    payload_bytes = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8", errors="strict")
    payload_path.write_bytes(payload_bytes)
    target["hash"] = _sha256_hex(payload_bytes)
    evidence_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )


def _append_hotl_approval_artifact(repo_root: Path, *, evidence_rel: str, rel_root: str, run_id: str) -> None:
    hotl_rel = f"{rel_root}/hotl_approval.json"
    audit_rel = f"{rel_root}/hotl_approval.log"
    locked_rel = f"{rel_root}/LockedSpec.json"
    builders.write_text(repo_root / audit_rel, "synthetic HOTL audit trail\n")
    hotl_payload = {
        "schema_version": "1.0.0",
        "run_id": run_id,
        "approval_id": "hotl.synthetic",
        "approver": "human:operator@example.com",
        "approval_type": "pre-proposal",
        "reviewed_artifacts": [
            {
                "id": "locked.synthetic",
                "hash": _sha256_hex((repo_root / locked_rel).read_bytes()),
                "storage_ref": locked_rel,
            }
        ],
        "decision": "approved",
        "approved_at": "1970-01-01T00:00:00Z",
        "justification": "synthetic HOTL approval for tier-2 coverage",
        "audit_trail_ref": {
            "id": "audit.hotl.synthetic",
            "storage_ref": audit_rel,
        },
    }
    builders.write_json(repo_root / hotl_rel, hotl_payload)

    evidence_path = repo_root / evidence_rel
    evidence = _read_json(evidence_path)
    artifacts = evidence.get("artifacts")
    assert isinstance(artifacts, list)
    artifacts.append(
        {
            "kind": "hotl_approval",
            "id": "hotl.synthetic",
            "hash": _sha256_hex((repo_root / hotl_rel).read_bytes()),
            "media_type": "application/json",
            "produced_by": "C1",
            "storage_ref": hotl_rel,
        }
    )
    evidence_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )


def test_gate_q_q3_duplicate_invariant_ids_is_primary(tmp_path: Path) -> None:
    paths = builders.build_q_repo(
        tmp_path,
        rel_root="gate_q/q3_invariants_duplicate_ids",
        run_id="q3-duplicate",
        invariants=[
            {"id": "INV-001", "description": "first", "severity": "policy"},
            {"id": "INV-001", "description": "second", "severity": "policy"},
        ],
    )

    cp = builders.run_gate_q(tmp_path, intent_rel=paths["intent"], locked_rel=paths["locked"], evidence_rel=paths["evidence"])
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)

    verdict = _read_json(tmp_path / "out" / "GateVerdict.Q.json")
    assert verdict["failure_category"] == "FQ-INVARIANTS-EMPTY"
    failures = verdict.get("failures")
    assert isinstance(failures, list) and failures
    assert failures[0]["rule_id"] == "Q3"


def test_gate_q_q5_missing_pinned_refs_is_primary(tmp_path: Path) -> None:
    paths = builders.build_q_repo(tmp_path, rel_root="gate_q/q5_envelope_missing_pinned_refs", run_id="q5-envelope")
    locked_path = tmp_path / paths["locked"]
    locked = _read_json(locked_path)
    envelope = locked.get("environment_envelope")
    assert isinstance(envelope, dict)
    envelope["pinned_toolchain_refs"] = []
    locked_path.write_text(json.dumps(locked, indent=2, sort_keys=True) + "\n", encoding="utf-8", errors="strict")

    cp = builders.run_gate_q(tmp_path, intent_rel=paths["intent"], locked_rel=paths["locked"], evidence_rel=paths["evidence"])
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)

    verdict = _read_json(tmp_path / "out" / "GateVerdict.Q.json")
    assert verdict["failure_category"] == "FQ-ENVELOPE-MISSING"
    failures = verdict.get("failures")
    assert isinstance(failures, list) and failures
    assert failures[0]["rule_id"] == "Q5"


def test_gate_q_q7_unsupported_tier_is_primary(tmp_path: Path) -> None:
    paths = builders.build_q_repo(tmp_path, rel_root="gate_q/q7_tier_unsupported", run_id="q7-tier")

    intent_path = tmp_path / paths["intent"]
    locked_path = tmp_path / paths["locked"]

    locked = _read_json(locked_path)
    tier = locked.get("tier")
    assert isinstance(tier, dict)
    tier["tier_id"] = "tier-99"
    tier["tier_name"] = "Tier 99"
    locked_path.write_text(json.dumps(locked, indent=2, sort_keys=True) + "\n", encoding="utf-8", errors="strict")

    intent_text = intent_path.read_text(encoding="utf-8", errors="strict").replace('tier_pack_id: "tier-0"', 'tier_pack_id: "tier-99"')
    intent_path.write_text(intent_text, encoding="utf-8", errors="strict")

    cp = builders.run_gate_q(tmp_path, intent_rel=paths["intent"], locked_rel=paths["locked"], evidence_rel=paths["evidence"])
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)

    verdict = _read_json(tmp_path / "out" / "GateVerdict.Q.json")
    assert verdict["failure_category"] == "FQ-TIER-UNKNOWN"
    failures = verdict.get("failures")
    assert isinstance(failures, list) and failures
    assert failures[0]["rule_id"] == "Q7"


def test_gate_q_prompt_001_unlisted_repo_is_primary(tmp_path: Path) -> None:
    paths = builders.build_q_repo(
        tmp_path,
        rel_root="gate_q/q_prompt_001_unlisted_repo",
        run_id="q-prompt-001",
        allowed_repo_refs=["allowed/repo"],
        prompt_storage_ref="blocked/repo/prompt_bundle.txt",
    )

    cp = builders.run_gate_q(tmp_path, intent_rel=paths["intent"], locked_rel=paths["locked"], evidence_rel=paths["evidence"])
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)

    verdict = _read_json(tmp_path / "out" / "GateVerdict.Q.json")
    assert verdict["failure_category"] == "FQ-PROMPT-SOURCE-INVALID"
    failures = verdict.get("failures")
    assert isinstance(failures, list) and failures
    assert failures[0]["rule_id"] == "Q-PROMPT-001"


def test_gate_q_doc_002_tier2_empty_required_paths_passes(tmp_path: Path) -> None:
    paths = builders.build_q_repo(
        tmp_path,
        rel_root="gate_q/q_doc_002_pass_tier2",
        tier_id="tier-2",
        run_id="q-doc-002",
        doc_impact={
            "required_paths": [],
            "note_on_empty": "No documentation change is required for this synthetic tier-2 run.",
        },
        publication_intent={"publish": False, "profile": "internal"},
    )
    _append_hotl_approval_artifact(
        tmp_path,
        evidence_rel=paths["evidence"],
        rel_root="gate_q/q_doc_002_pass_tier2",
        run_id="q-doc-002",
    )

    cp = builders.run_gate_q(tmp_path, intent_rel=paths["intent"], locked_rel=paths["locked"], evidence_rel=paths["evidence"])
    assert cp.returncode == 0, (cp.returncode, cp.stdout, cp.stderr)

    verdict = _read_json(tmp_path / "out" / "GateVerdict.Q.json")
    assert verdict["verdict"] == "GO"
    assert verdict["failure_category"] is None


def test_gate_r_doc_001_required_path_not_touched_is_primary(tmp_path: Path) -> None:
    paths = builders.build_r_repo(
        tmp_path,
        rel_root="gate_r/r_doc_001_required_path_not_touched",
        run_id="r-doc-001",
        doc_impact={"required_paths": ["docs/required.md"]},
        diff_paths=["src/changed.py"],
    )
    tiers = builders.builtin_tiers()
    tiers["tiers"]["tier-1"]["doc_impact_required"] = True
    tiers_rel = builders.write_tiers_override(tmp_path, tiers)
    commit_sha = builders.init_git_repo(tmp_path)

    cp = builders.run_gate_r(
        tmp_path,
        locked_rel=paths["locked"],
        gate_q_rel=paths["gate_q_verdict"],
        evidence_rel=paths["evidence"],
        evaluated_revision=commit_sha,
        tiers_rel=tiers_rel,
    )
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)

    report = _read_json(tmp_path / "out" / "verify_report.json")
    first_fail = _first_fail_result(_report_results(report))
    assert first_fail["check_id"] == "R-DOC-001"

    verdict = _read_json(tmp_path / "out" / "GateVerdict.R.json")
    assert verdict["failure_category"] == "FR-INVARIANT-FAILED"
    failures = verdict.get("failures")
    assert isinstance(failures, list) and failures
    assert failures[0]["rule_id"] == "R-DOC-001"


def test_gate_q_protocol_identity_mismatch_pack_id(tmp_path: Path) -> None:
    """Gate Q MUST emit FQ-PROTOCOL-IDENTITY-MISMATCH on pack_id mismatch."""
    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)

    fixture_dir = "gate_q/q_pass_tier0"
    paths = _copy_fixture_inputs(REPO_ROOT, tmp_path, fixture_dir)

    # Tamper pack_id in LockedSpec.
    locked_path = tmp_path / paths["locked"]
    _tamper_locked_spec_pack_id(locked_path, "0000000000000000000000000000000000000000000000000000000000000000")

    out_rel = "out/GateVerdict.json"
    out_path = tmp_path / "out" / "GateVerdict.json"

    cp = _run_module(
        "chain.gate_q_verify",
        [
            "--repo", str(tmp_path),
            "--protocol-pack", "protocol_pack",
            "--intent-spec", paths["intent"],
            "--locked-spec", paths["locked"],
            "--evidence-manifest", paths["evidence"],
            "--out", out_rel,
        ],
        cwd=REPO_ROOT,
    )

    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
    gv = _read_json(out_path)
    assert gv.get("failure_category") == "FQ-PROTOCOL-IDENTITY-MISMATCH", gv


def test_gate_r_protocol_identity_mismatch_pack_id(tmp_path: Path) -> None:
    """Gate R protocol mismatch must be first in ordered results and primary cause."""
    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)

    fixture_dir = "gate_r/r_pass_tier1"
    paths = _copy_fixture_inputs(REPO_ROOT, tmp_path, fixture_dir)
    _sync_locked_spec_protocol_identity(
        tmp_path / paths["locked"],
        tmp_path / "protocol_pack" / MANIFEST_FILENAME,
    )

    # Tamper pack_id in LockedSpec.
    locked_path = tmp_path / paths["locked"]
    _tamper_locked_spec_pack_id(locked_path, "0000000000000000000000000000000000000000000000000000000000000000")

    # Gate R requires a git repo for --evaluated-revision.
    commit_sha = _init_git_repo(tmp_path)

    # Gate R snapshot indexing requires a GateVerdict(Q) file (bytes-only binding).
    gate_q_rel = "inputs/GateVerdict.Q.json"
    (tmp_path / "inputs").mkdir(parents=True, exist_ok=True)
    (tmp_path / "inputs" / "GateVerdict.Q.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "run_id": "fixture",
                "gate_id": "Q",
                "verdict": "GO",
                "failure_category": None,
                "failures": [],
                "evidence_manifest_ref": {"id": "evidence", "hash": "0" * 64, "storage_ref": "inputs/EvidenceManifest.Q.json"},
                "evaluated_at": "1970-01-01T00:00:00Z",
                "evaluator": "fixture",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    verify_report_rel = "out/verify_report.json"
    verify_report_path = tmp_path / verify_report_rel
    gate_verdict_rel = "out/GateVerdict.json"
    gate_verdict_path = tmp_path / gate_verdict_rel

    cp = _run_module(
        "chain.gate_r_verify",
        [
            "--repo", str(tmp_path),
            "--protocol-pack", "protocol_pack",
            "--locked-spec", paths["locked"],
            "--gate-q-verdict", gate_q_rel,
            "--evidence-manifest", paths["evidence"],
            "--r-snapshot-manifest-out", "out/EvidenceManifest.r_snapshot.json",
            "--evaluated-revision", commit_sha,
            "--out", verify_report_rel,
            "--gate-verdict-out", gate_verdict_rel,
        ],
        cwd=REPO_ROOT,
    )

    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
    verify_report = _read_json(verify_report_path)
    results = _report_results(verify_report)
    assert [str(row.get("check_id")) for row in results] == ["PROTOCOL-IDENTITY-001"]
    assert [str(row.get("status")) for row in results] == ["FAIL"]
    assert not (tmp_path / "out" / "EvidenceManifest.r_snapshot.json").exists()

    gv = _read_json(gate_verdict_path)
    assert gv.get("failure_category") == "FR-PROTOCOL-IDENTITY-MISMATCH", gv
    failures = gv.get("failures")
    assert isinstance(failures, list) and failures
    assert failures[0].get("rule_id") == "PROTOCOL-IDENTITY-001"


def test_gate_r_ordered_results_snapshot_preflight_primary_cause(tmp_path: Path) -> None:
    """Snapshot preflight failure must stay in fixed position and drive primary cause."""

    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)

    fixture_dir = "gate_r/r_pass_tier1"
    paths = _copy_fixture_inputs(REPO_ROOT, tmp_path, fixture_dir)
    _sync_locked_spec_protocol_identity(
        tmp_path / paths["locked"],
        tmp_path / "protocol_pack" / MANIFEST_FILENAME,
    )

    evidence_path = tmp_path / paths["evidence"]
    evidence = _read_json(evidence_path)
    evidence["artifacts"] = "not-a-list"
    evidence_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    commit_sha = _init_git_repo(tmp_path)

    verify_report_rel = "out/verify_report.snapshot_fail.json"
    gate_verdict_rel = "out/GateVerdict.snapshot_fail.json"
    cp = _run_module(
        "chain.gate_r_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            paths["locked"],
            "--gate-q-verdict",
            paths["gate_q_verdict"],
            "--evidence-manifest",
            paths["evidence"],
            "--r-snapshot-manifest-out",
            "out/EvidenceManifest.r_snapshot.json",
            "--evaluated-revision",
            commit_sha,
            "--out",
            verify_report_rel,
            "--gate-verdict-out",
            gate_verdict_rel,
        ],
        cwd=REPO_ROOT,
    )
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)

    verify_report = _read_json(tmp_path / verify_report_rel)
    results = _report_results(verify_report)
    assert [str(row.get("check_id")) for row in results] == [
        "PROTOCOL-IDENTITY-001",
        "R-SNAPSHOT-INDEX-001",
    ]
    assert [str(row.get("status")) for row in results] == ["PASS", "FAIL"]
    assert not (tmp_path / "out" / "EvidenceManifest.r_snapshot.json").exists()

    gate_verdict = _read_json(tmp_path / gate_verdict_rel)
    assert gate_verdict.get("failure_category") == "FR-INVARIANT-FAILED"
    failures = gate_verdict.get("failures")
    assert isinstance(failures, list) and failures
    assert failures[0].get("rule_id") == "R-SNAPSHOT-INDEX-001"


def test_gate_r_normal_pass_writes_snapshot_and_executes_later_checks(tmp_path: Path) -> None:
    """Normal PASS path must still persist the R-snapshot and continue through later checks."""

    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)
    paths = _prepare_r_pass_tier1_fixture_repo(tmp_path)

    commit_sha = _init_git_repo(tmp_path)
    verify_rel = "out/verify_report.pass.json"
    verdict_rel = "out/GateVerdict.pass.json"
    snapshot_path = tmp_path / "out" / "EvidenceManifest.r_snapshot.json"

    cp = _run_module(
        "chain.gate_r_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            paths["locked"],
            "--gate-q-verdict",
            paths["gate_q_verdict"],
            "--evidence-manifest",
            paths["evidence"],
            "--r-snapshot-manifest-out",
            "out/EvidenceManifest.r_snapshot.json",
            "--evaluated-revision",
            commit_sha,
            "--out",
            verify_rel,
            "--gate-verdict-out",
            verdict_rel,
        ],
        cwd=REPO_ROOT,
    )
    assert cp.returncode == 0, (cp.returncode, cp.stdout, cp.stderr)
    assert snapshot_path.exists()

    report = _read_json(tmp_path / verify_rel)
    results = _report_results(report)
    assert [str(row.get("check_id")) for row in results[:2]] == [
        "PROTOCOL-IDENTITY-001",
        "R-SNAPSHOT-INDEX-001",
    ]
    assert [str(row.get("status")) for row in results[:2]] == ["PASS", "PASS"]
    assert any(str(row.get("check_id")) == "R1" for row in results)

    verdict = _read_json(tmp_path / verdict_rel)
    assert verdict.get("verdict") == "GO"
    assert verdict.get("failure_category") is None


@pytest.mark.parametrize(
    ("report_id", "semantic_owner"),
    [
        ("policy.invariant_eval", "R1"),
        ("policy.supplychain", "R7"),
        ("policy.adversarial_scan", "R8"),
    ],
)
def test_gate_r_foreign_run_required_policy_report_is_structurally_invalid(
    tmp_path: Path,
    report_id: str,
    semantic_owner: str,
) -> None:
    """Foreign-run required policy reports must fail under structural invalidity."""

    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)
    paths = _prepare_r_pass_tier1_fixture_repo(tmp_path)

    _rewrite_required_report_payload_run_id(
        tmp_path,
        evidence_rel=paths["evidence"],
        kind="policy_report",
        artifact_id=report_id,
        run_id="foreign-run",
    )

    commit_sha = _init_git_repo(tmp_path)
    verify_rel = f"out/verify_report.{report_id.replace('.', '_')}.foreign_run.json"
    verdict_rel = f"out/GateVerdict.{report_id.replace('.', '_')}.foreign_run.json"
    cp = _run_module(
        "chain.gate_r_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            paths["locked"],
            "--gate-q-verdict",
            paths["gate_q_verdict"],
            "--evidence-manifest",
            paths["evidence"],
            "--evaluated-revision",
            commit_sha,
            "--out",
            verify_rel,
            "--gate-verdict-out",
            verdict_rel,
        ],
        cwd=REPO_ROOT,
    )
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)

    report = _read_json(tmp_path / verify_rel)
    results = _report_results(report)
    first_fail = _first_fail_result(results)
    assert first_fail.get("check_id") == "R4"
    assert first_fail.get("category") == "FR-SCHEMA-ARTIFACT-INVALID"
    assert "belongs to a different run" in str(first_fail.get("message"))
    assert not any(str(row.get("check_id")) == semantic_owner for row in results)

    verdict = _read_json(tmp_path / verdict_rel)
    assert verdict.get("failure_category") == "FR-SCHEMA-ARTIFACT-INVALID"
    failures = verdict.get("failures")
    assert isinstance(failures, list) and failures
    assert failures[0].get("rule_id") == "R4"
    remediation = verdict.get("remediation")
    assert isinstance(remediation, dict)
    assert remediation.get("next_instruction") == "Do regenerate the required report for the current LockedSpec.run_id then re-run R."


def test_gate_r_foreign_run_required_test_report_is_structurally_invalid(tmp_path: Path) -> None:
    """Foreign-run required test reports must fail under structural invalidity."""

    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)
    paths = _prepare_r_pass_tier1_fixture_repo(tmp_path)

    _rewrite_required_report_payload_run_id(
        tmp_path,
        evidence_rel=paths["evidence"],
        kind="test_report",
        artifact_id="tests.report",
        run_id="foreign-run",
    )

    commit_sha = _init_git_repo(tmp_path)
    verify_rel = "out/verify_report.tests_report.foreign_run.json"
    verdict_rel = "out/GateVerdict.tests_report.foreign_run.json"
    cp = _run_module(
        "chain.gate_r_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            paths["locked"],
            "--gate-q-verdict",
            paths["gate_q_verdict"],
            "--evidence-manifest",
            paths["evidence"],
            "--evaluated-revision",
            commit_sha,
            "--out",
            verify_rel,
            "--gate-verdict-out",
            verdict_rel,
        ],
        cwd=REPO_ROOT,
    )
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)

    report = _read_json(tmp_path / verify_rel)
    results = _report_results(report)
    first_fail = _first_fail_result(results)
    assert first_fail.get("check_id") == "R4"
    assert first_fail.get("category") == "FR-SCHEMA-ARTIFACT-INVALID"
    assert "belongs to a different run" in str(first_fail.get("message"))
    assert not any(str(row.get("check_id")) == "R5" for row in results)

    verdict = _read_json(tmp_path / verdict_rel)
    assert verdict.get("failure_category") == "FR-SCHEMA-ARTIFACT-INVALID"
    failures = verdict.get("failures")
    assert isinstance(failures, list) and failures
    assert failures[0].get("rule_id") == "R4"
    remediation = verdict.get("remediation")
    assert isinstance(remediation, dict)
    assert remediation.get("next_instruction") == "Do regenerate the required report for the current LockedSpec.run_id then re-run R."


@pytest.mark.parametrize(
    ("kind", "artifact_id", "semantic_owner"),
    [
        ("policy_report", "policy.invariant_eval", "R1"),
        ("policy_report", "policy.supplychain", "R7"),
        ("policy_report", "policy.adversarial_scan", "R8"),
        ("test_report", "tests.report", "R5"),
    ],
)
def test_gate_r_current_run_required_report_payloads_still_pass(
    tmp_path: Path,
    kind: str,
    artifact_id: str,
    semantic_owner: str,
) -> None:
    """Current-run required report payloads must continue to pass structural binding."""

    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)
    paths = _prepare_r_pass_tier1_fixture_repo(tmp_path)
    locked = _read_json(tmp_path / paths["locked"])
    locked_run_id = str(locked.get("run_id"))

    _rewrite_required_report_payload_run_id(
        tmp_path,
        evidence_rel=paths["evidence"],
        kind=kind,
        artifact_id=artifact_id,
        run_id=locked_run_id,
    )

    commit_sha = _init_git_repo(tmp_path)
    verify_rel = f"out/verify_report.{artifact_id.replace('.', '_')}.current_run.json"
    verdict_rel = f"out/GateVerdict.{artifact_id.replace('.', '_')}.current_run.json"
    cp = _run_module(
        "chain.gate_r_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            paths["locked"],
            "--gate-q-verdict",
            paths["gate_q_verdict"],
            "--evidence-manifest",
            paths["evidence"],
            "--evaluated-revision",
            commit_sha,
            "--out",
            verify_rel,
            "--gate-verdict-out",
            verdict_rel,
        ],
        cwd=REPO_ROOT,
    )
    assert cp.returncode == 0, (cp.returncode, cp.stdout, cp.stderr)
    report = _read_json(tmp_path / verify_rel)
    assert any(str(row.get("check_id")) == semantic_owner for row in _report_results(report))
    verdict = _read_json(tmp_path / verdict_rel)
    assert verdict.get("verdict") == "GO"


def test_gate_r_missing_policy_supplychain_is_owned_by_r7(tmp_path: Path) -> None:
    """Missing policy.supplychain must fail under R7 ownership, not R4 preemption."""

    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)
    paths = _prepare_r_pass_tier1_fixture_repo(tmp_path)

    evidence_path = tmp_path / paths["evidence"]
    evidence = _read_json(evidence_path)
    artifacts = evidence.get("artifacts")
    assert isinstance(artifacts, list)
    evidence["artifacts"] = [
        row
        for row in artifacts
        if not (isinstance(row, dict) and row.get("kind") == "policy_report" and row.get("id") == "policy.supplychain")
    ]
    evidence_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    commit_sha = _init_git_repo(tmp_path)
    verify_rel = "out/verify_report.r7_missing.json"
    verdict_rel = "out/GateVerdict.r7_missing.json"
    cp = _run_module(
        "chain.gate_r_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            paths["locked"],
            "--gate-q-verdict",
            paths["gate_q_verdict"],
            "--evidence-manifest",
            paths["evidence"],
            "--evaluated-revision",
            commit_sha,
            "--out",
            verify_rel,
            "--gate-verdict-out",
            verdict_rel,
        ],
        cwd=REPO_ROOT,
    )
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)

    report = _read_json(tmp_path / verify_rel)
    first_fail = _first_fail_result(_report_results(report))
    assert first_fail.get("check_id") == "R7"

    verdict = _read_json(tmp_path / verdict_rel)
    assert verdict.get("failure_category") == "FR-SUPPLYCHAIN-SCAN-MISSING"
    failures = verdict.get("failures")
    assert isinstance(failures, list) and failures
    assert failures[0].get("rule_id") == "R7"


def test_gate_r_missing_policy_adversarial_scan_is_owned_by_r8(tmp_path: Path) -> None:
    """Missing policy.adversarial_scan must fail under R8 ownership, not R4 preemption."""

    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)
    paths = _prepare_r_pass_tier1_fixture_repo(tmp_path)

    evidence_path = tmp_path / paths["evidence"]
    evidence = _read_json(evidence_path)
    artifacts = evidence.get("artifacts")
    assert isinstance(artifacts, list)
    evidence["artifacts"] = [
        row
        for row in artifacts
        if not (isinstance(row, dict) and row.get("kind") == "policy_report" and row.get("id") == "policy.adversarial_scan")
    ]
    evidence_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    commit_sha = _init_git_repo(tmp_path)
    verify_rel = "out/verify_report.r8_missing.json"
    verdict_rel = "out/GateVerdict.r8_missing.json"
    cp = _run_module(
        "chain.gate_r_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            paths["locked"],
            "--gate-q-verdict",
            paths["gate_q_verdict"],
            "--evidence-manifest",
            paths["evidence"],
            "--evaluated-revision",
            commit_sha,
            "--out",
            verify_rel,
            "--gate-verdict-out",
            verdict_rel,
        ],
        cwd=REPO_ROOT,
    )
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)

    report = _read_json(tmp_path / verify_rel)
    first_fail = _first_fail_result(_report_results(report))
    assert first_fail.get("check_id") == "R8"

    verdict = _read_json(tmp_path / verdict_rel)
    assert verdict.get("failure_category") == "FR-ADVERSARIAL-SCAN-MISSING"
    failures = verdict.get("failures")
    assert isinstance(failures, list) and failures
    assert failures[0].get("rule_id") == "R8"


@pytest.mark.parametrize(
    ("report_id", "expected_rule_id"),
    [
        ("policy.supplychain", "R7"),
        ("policy.adversarial_scan", "R8"),
    ],
)
def test_gate_r_duplicate_required_policy_report_is_owned_by_dedicated_check(
    tmp_path: Path,
    report_id: str,
    expected_rule_id: str,
) -> None:
    """Duplicate required policy report must fail under R7/R8 with schema-invalid category."""

    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)
    paths = _prepare_r_pass_tier1_fixture_repo(tmp_path)

    evidence_path = tmp_path / paths["evidence"]
    evidence = _read_json(evidence_path)
    artifacts = evidence.get("artifacts")
    assert isinstance(artifacts, list)
    target = next(
        (
            row
            for row in artifacts
            if isinstance(row, dict) and row.get("kind") == "policy_report" and row.get("id") == report_id
        ),
        None,
    )
    assert isinstance(target, dict)
    artifacts.append(dict(target))
    evidence_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    commit_sha = _init_git_repo(tmp_path)
    verify_rel = f"out/verify_report.dup.{expected_rule_id}.json"
    verdict_rel = f"out/GateVerdict.dup.{expected_rule_id}.json"
    cp = _run_module(
        "chain.gate_r_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            paths["locked"],
            "--gate-q-verdict",
            paths["gate_q_verdict"],
            "--evidence-manifest",
            paths["evidence"],
            "--evaluated-revision",
            commit_sha,
            "--out",
            verify_rel,
            "--gate-verdict-out",
            verdict_rel,
        ],
        cwd=REPO_ROOT,
    )
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)

    report = _read_json(tmp_path / verify_rel)
    first_fail = _first_fail_result(_report_results(report))
    assert first_fail.get("check_id") == expected_rule_id
    assert first_fail.get("category") == "FR-SCHEMA-ARTIFACT-INVALID"

    verdict = _read_json(tmp_path / verdict_rel)
    assert verdict.get("failure_category") == "FR-SCHEMA-ARTIFACT-INVALID"
    failures = verdict.get("failures")
    assert isinstance(failures, list) and failures
    assert failures[0].get("rule_id") == expected_rule_id


def test_gate_r_overlay_preflight_ordering_and_optional_presence(tmp_path: Path) -> None:
    """Overlay preflight must be deterministic when enabled and absent otherwise."""

    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)
    paths = builders.build_r_repo(tmp_path, rel_root="gate_r/r_pass_tier1", run_id="r-pass-tier1")
    _sync_locked_spec_protocol_identity(
        tmp_path / paths["locked"],
        tmp_path / "protocol_pack" / MANIFEST_FILENAME,
    )
    evidence_path = tmp_path / paths["evidence"]
    evidence = _read_json(evidence_path)
    artifacts = evidence.get("artifacts")
    assert isinstance(artifacts, list)

    overlay_payload = {
        "schema_version": "1.0.0",
        "run_id": "r-pass-tier1",
        "generated_at": "1970-01-01T00:00:00Z",
        "summary": {"total_checks": 1, "passed": 1, "failed": 0},
        "checks": [{"check_id": "ADOPTER-POLICY-001", "passed": True}],
    }
    overlay_rel = "gate_r/r_pass_tier1/policy.overlay_requirements.json"
    overlay_path = tmp_path / Path(*overlay_rel.split("/"))
    overlay_bytes = (json.dumps(overlay_payload, indent=2, sort_keys=True) + "\n").encode("utf-8", errors="strict")
    overlay_path.parent.mkdir(parents=True, exist_ok=True)
    overlay_path.write_bytes(overlay_bytes)
    artifacts.append(
        {
            "kind": "policy_report",
            "id": "policy.overlay_requirements",
            "hash": _sha256_hex(overlay_bytes),
            "media_type": "application/json",
            "storage_ref": overlay_rel,
            "produced_by": "R",
        }
    )
    evidence_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    protocol_manifest_path = tmp_path / "protocol_pack" / MANIFEST_FILENAME
    protocol_manifest = _read_json(protocol_manifest_path)
    (tmp_path / "belgi_pack").mkdir(parents=True, exist_ok=True)
    (tmp_path / "belgi_pack" / "DomainPackManifest.json").write_text(
        json.dumps(
            {
                "format_version": 1,
                "pack_name": "overlay-test",
                "pack_semver": "0.1.0",
                "belgi_protocol_pack_pin": {
                    "pack_name": protocol_manifest["pack_name"],
                    "pack_id": "f" * 64,
                    "manifest_sha256": _sha256_hex(protocol_manifest_path.read_bytes()),
                },
                "required_policy_check_ids": ["ADOPTER-POLICY-001"],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    commit_sha = _init_git_repo(tmp_path)

    verify_report_overlay_rel = "out/verify_report.overlay_fail.json"
    gate_verdict_overlay_rel = "out/GateVerdict.overlay_fail.json"
    cp_overlay = _run_module(
        "chain.gate_r_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            paths["locked"],
            "--gate-q-verdict",
            paths["gate_q_verdict"],
            "--evidence-manifest",
            paths["evidence"],
            "--evaluated-revision",
            commit_sha,
            "--out",
            verify_report_overlay_rel,
            "--gate-verdict-out",
            gate_verdict_overlay_rel,
            "--overlay",
            "belgi_pack",
        ],
        cwd=REPO_ROOT,
    )
    assert cp_overlay.returncode == 2, (cp_overlay.returncode, cp_overlay.stdout, cp_overlay.stderr)
    overlay_report = _read_json(tmp_path / verify_report_overlay_rel)
    overlay_results = _report_results(overlay_report)
    assert [str(overlay_results[idx].get("check_id")) for idx in (0, 1, 2)] == [
        "PROTOCOL-IDENTITY-001",
        "R-SNAPSHOT-INDEX-001",
        "R-OVERLAY-001",
    ]
    assert [str(overlay_results[idx].get("status")) for idx in (0, 1, 2)] == ["PASS", "PASS", "FAIL"]

    overlay_verdict = _read_json(tmp_path / gate_verdict_overlay_rel)
    failures = overlay_verdict.get("failures")
    assert isinstance(failures, list) and failures
    assert failures[0].get("rule_id") == "R-OVERLAY-001"

    verify_report_no_overlay_rel = "out/verify_report.no_overlay.json"
    gate_verdict_no_overlay_rel = "out/GateVerdict.no_overlay.json"
    cp_no_overlay = _run_module(
        "chain.gate_r_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            paths["locked"],
            "--gate-q-verdict",
            paths["gate_q_verdict"],
            "--evidence-manifest",
            paths["evidence"],
            "--evaluated-revision",
            commit_sha,
            "--out",
            verify_report_no_overlay_rel,
            "--gate-verdict-out",
            gate_verdict_no_overlay_rel,
        ],
        cwd=REPO_ROOT,
    )
    assert cp_no_overlay.returncode == 0, (cp_no_overlay.returncode, cp_no_overlay.stdout, cp_no_overlay.stderr)
    no_overlay_report = _read_json(tmp_path / verify_report_no_overlay_rel)
    no_overlay_results = _report_results(no_overlay_report)
    assert all(str(result.get("check_id")) != "R-OVERLAY-001" for result in no_overlay_results)


def test_gate_r_overlay_ignores_non_policy_payload_policy_report(tmp_path: Path) -> None:
    """Overlay enforcement must ignore non-PolicyReportPayload policy_report artifacts."""
    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)
    paths = builders.build_r_repo(tmp_path, rel_root="gate_r/r_pass_tier1", run_id="r-pass-tier1")
    _sync_locked_spec_protocol_identity(
        tmp_path / paths["locked"],
        tmp_path / "protocol_pack" / MANIFEST_FILENAME,
    )

    evidence_path = tmp_path / paths["evidence"]
    evidence = _read_json(evidence_path)
    artifacts = evidence.get("artifacts")
    assert isinstance(artifacts, list)

    overlay_payload = {
        "schema_version": "1.0.0",
        "run_id": "r-pass-tier1",
        "generated_at": "1970-01-01T00:00:00Z",
        "summary": {"total_checks": 1, "passed": 1, "failed": 0},
        "checks": [{"check_id": "ADOPTER-POLICY-001", "passed": True}],
    }
    overlay_rel = "gate_r/r_pass_tier1/policy.overlay_requirements.json"
    overlay_path = tmp_path / Path(*overlay_rel.split("/"))
    overlay_bytes = (json.dumps(overlay_payload, indent=2, sort_keys=True) + "\n").encode("utf-8", errors="strict")
    overlay_path.parent.mkdir(parents=True, exist_ok=True)
    overlay_path.write_bytes(overlay_bytes)

    artifacts.append(
        {
            "kind": "policy_report",
            "id": "policy.overlay_requirements",
            "hash": _sha256_hex(overlay_bytes),
            "media_type": "application/json",
            "storage_ref": overlay_rel,
            "produced_by": "R",
        }
    )
    evidence_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    protocol_manifest_path = tmp_path / "protocol_pack" / MANIFEST_FILENAME
    protocol_manifest = _read_json(protocol_manifest_path)
    (tmp_path / "belgi_pack").mkdir(parents=True, exist_ok=True)
    (tmp_path / "belgi_pack" / "DomainPackManifest.json").write_text(
        json.dumps(
            {
                "format_version": 1,
                "pack_name": "adopter-overlay",
                "pack_semver": "0.1.0",
                "belgi_protocol_pack_pin": {
                    "pack_name": protocol_manifest["pack_name"],
                    "pack_id": protocol_manifest["pack_id"],
                    "manifest_sha256": _sha256_hex(protocol_manifest_path.read_bytes()),
                },
                "required_policy_check_ids": ["ADOPTER-POLICY-001"],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    commit_sha = _init_git_repo(tmp_path)

    verify_report_rel = "out/verify_report.overlay.json"
    gate_verdict_rel = "out/GateVerdict.R.overlay.json"
    cp = _run_module(
        "chain.gate_r_verify",
        [
            "--repo", str(tmp_path),
            "--protocol-pack", "protocol_pack",
            "--locked-spec", paths["locked"],
            "--gate-q-verdict", paths["gate_q_verdict"],
            "--evidence-manifest", paths["evidence"],
            "--evaluated-revision", commit_sha,
            "--out", verify_report_rel,
            "--gate-verdict-out", gate_verdict_rel,
            "--overlay", "belgi_pack",
        ],
        cwd=REPO_ROOT,
    )
    assert cp.returncode == 0, (cp.returncode, cp.stdout, cp.stderr)

    gate_verdict = _read_json(tmp_path / gate_verdict_rel)
    assert gate_verdict.get("verdict") == "GO", gate_verdict
    assert gate_verdict.get("failure_category") is None, gate_verdict


def test_gate_s_protocol_identity_mismatch_pack_id(tmp_path: Path) -> None:
    """Gate S MUST emit FS-PROTOCOL-IDENTITY-MISMATCH on pack_id mismatch."""
    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)

    fixture_dir = "gate_s/s_pass_tier1_unsigned"
    paths = _copy_fixture_inputs(REPO_ROOT, tmp_path, fixture_dir)

    # Tamper pack_id in LockedSpec.
    locked_path = tmp_path / paths["locked"]
    _tamper_locked_spec_pack_id(locked_path, "0000000000000000000000000000000000000000000000000000000000000000")

    out_rel = "out/GateVerdict.json"
    out_path = tmp_path / "out" / "GateVerdict.json"

    cp = _run_module(
        "chain.gate_s_verify",
        [
            "--repo", str(tmp_path),
            "--protocol-pack", "protocol_pack",
            "--locked-spec", paths["locked"],
            "--evidence-manifest", paths["evidence"],
            "--seal-manifest", paths["seal"],
            "--out", out_rel,
        ],
        cwd=REPO_ROOT,
    )

    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
    gv = _read_json(out_path)
    assert gv.get("failure_category") == "FS-PROTOCOL-IDENTITY-MISMATCH", gv


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


def test_gate_q_missing_protocol_pack_field(tmp_path: Path) -> None:
    """Gate Q MUST emit FQ-PROTOCOL-IDENTITY-MISMATCH when protocol_pack field is missing.

    Note: Protocol identity check is inserted at position 0, so it's the first failure
    even though LockedSpec schema validation also fails.
    """
    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)

    fixture_dir = "gate_q/q_pass_tier0"
    paths = _copy_fixture_inputs(REPO_ROOT, tmp_path, fixture_dir)

    # Remove protocol_pack field entirely.
    locked_path = tmp_path / paths["locked"]
    _remove_locked_spec_protocol_pack(locked_path)

    out_rel = "out/GateVerdict.json"
    out_path = tmp_path / "out" / "GateVerdict.json"

    cp = _run_module(
        "chain.gate_q_verify",
        [
            "--repo", str(tmp_path),
            "--protocol-pack", "protocol_pack",
            "--intent-spec", paths["intent"],
            "--locked-spec", paths["locked"],
            "--evidence-manifest", paths["evidence"],
            "--out", out_rel,
        ],
        cwd=REPO_ROOT,
    )

    # Protocol identity check is inserted at position 0, so it's the first failure.
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
    gv = _read_json(out_path)
    assert gv.get("failure_category") == "FQ-PROTOCOL-IDENTITY-MISMATCH", gv


def test_gate_r_missing_protocol_pack_field(tmp_path: Path) -> None:
    """Gate R MUST emit FR-PROTOCOL-IDENTITY-MISMATCH when protocol_pack field is missing."""
    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)

    fixture_dir = "gate_r/r_pass_tier1"
    paths = _copy_fixture_inputs(REPO_ROOT, tmp_path, fixture_dir)

    # Remove protocol_pack field entirely.
    locked_path = tmp_path / paths["locked"]
    _remove_locked_spec_protocol_pack(locked_path)

    # Gate R requires a git repo for --evaluated-revision.
    commit_sha = _init_git_repo(tmp_path)

    gate_q_rel = "inputs/GateVerdict.Q.json"
    (tmp_path / "inputs").mkdir(parents=True, exist_ok=True)
    (tmp_path / "inputs" / "GateVerdict.Q.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "run_id": "fixture",
                "gate_id": "Q",
                "verdict": "GO",
                "failure_category": None,
                "failures": [],
                "evidence_manifest_ref": {"id": "evidence", "hash": "0" * 64, "storage_ref": "inputs/EvidenceManifest.Q.json"},
                "evaluated_at": "1970-01-01T00:00:00Z",
                "evaluator": "fixture",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    out_rel = "out/GateVerdict.json"
    out_path = tmp_path / "out" / "GateVerdict.json"

    cp = _run_module(
        "chain.gate_r_verify",
        [
            "--repo", str(tmp_path),
            "--protocol-pack", "protocol_pack",
            "--locked-spec", paths["locked"],
            "--gate-q-verdict", gate_q_rel,
            "--evidence-manifest", paths["evidence"],
            "--evaluated-revision", commit_sha,
            "--out", out_rel,
        ],
        cwd=REPO_ROOT,
    )

    # Protocol identity check is inserted at position 0, so it's the first failure.
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
    gv = _read_json(out_path)
    assert gv.get("failure_category") == "FR-PROTOCOL-IDENTITY-MISMATCH", gv


def test_gate_s_missing_protocol_pack_field(tmp_path: Path) -> None:
    """Gate S MUST emit FS-PROTOCOL-IDENTITY-MISMATCH when protocol_pack field is missing."""
    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)

    fixture_dir = "gate_s/s_pass_tier1_unsigned"
    paths = _copy_fixture_inputs(REPO_ROOT, tmp_path, fixture_dir)

    # Remove protocol_pack field entirely.
    locked_path = tmp_path / paths["locked"]
    _remove_locked_spec_protocol_pack(locked_path)

    out_rel = "out/GateVerdict.json"
    out_path = tmp_path / "out" / "GateVerdict.json"

    cp = _run_module(
        "chain.gate_s_verify",
        [
            "--repo", str(tmp_path),
            "--protocol-pack", "protocol_pack",
            "--locked-spec", paths["locked"],
            "--evidence-manifest", paths["evidence"],
            "--seal-manifest", paths["seal"],
            "--out", out_rel,
        ],
        cwd=REPO_ROOT,
    )

    # Protocol identity check is inserted at position 0, so it's the first failure.
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
    gv = _read_json(out_path)
    assert gv.get("failure_category") == "FS-PROTOCOL-IDENTITY-MISMATCH", gv


def test_seal_bundle_tier2_requires_cryptographic_signature(tmp_path: Path) -> None:
    def _write_json_rel(rel: str, obj: dict) -> None:
        p = tmp_path / Path(*rel.split("/"))
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8", errors="strict")

    pub_rel = "temp/seal_pubkey.hex"
    pub_hex = _ed25519_pubkey_hex_from_seed("12" * 32)
    pub_bytes = (pub_hex + "\n").encode("utf-8", errors="strict")
    (tmp_path / "temp").mkdir(parents=True, exist_ok=True)
    (tmp_path / "temp" / "seal_pubkey.hex").write_bytes(pub_bytes)
    seal_pubkey_ref = {"id": "seal-pubkey", "hash": _sha256_hex(pub_bytes), "storage_ref": pub_rel}

    _write_json_rel(
        "LockedSpec.json",
        {
            "run_id": "test-run",
            "belgi_version": "0.0.0",
            "tier": {"tier_id": "tier-2"},
            "waivers_applied": [],
            "environment_envelope": {"seal_pubkey_ref": seal_pubkey_ref},
        },
    )
    _write_json_rel("Q.json", {})
    _write_json_rel("R.json", {})
    _write_json_rel("Evidence.json", {})

    cp = _run_module(
        "chain.seal_bundle",
        [
            "--repo",
            str(tmp_path),
            "--locked-spec",
            "LockedSpec.json",
            "--gate-q-verdict",
            "Q.json",
            "--gate-r-verdict",
            "R.json",
            "--evidence-manifest",
            "Evidence.json",
            "--final-commit-sha",
            "0" * 40,
            "--sealed-at",
            "2020-01-01T00:00:00+00:00",
            "--signer",
            "test",
            "--out",
            "out/SealManifest.json",
        ],
        cwd=REPO_ROOT,
    )

    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
    assert "Tier-2/3 requires a cryptographic seal signature" in cp.stderr


def test_seal_bundle_tier2_rejects_invalid_precomputed_signature(tmp_path: Path) -> None:
    def _write_json_rel(rel: str, obj: dict) -> None:
        p = tmp_path / Path(*rel.split("/"))
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8", errors="strict")

    pub_rel = "temp/seal_pubkey.hex"
    pub_hex = _ed25519_pubkey_hex_from_seed("34" * 32)
    pub_bytes = (pub_hex + "\n").encode("utf-8", errors="strict")
    (tmp_path / "temp").mkdir(parents=True, exist_ok=True)
    (tmp_path / "temp" / "seal_pubkey.hex").write_bytes(pub_bytes)
    (tmp_path / "temp" / "seal_signature.b64").write_text(
        base64.b64encode(b"\x00" * 64).decode("ascii") + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    seal_pubkey_ref = {"id": "seal-pubkey", "hash": _sha256_hex(pub_bytes), "storage_ref": pub_rel}

    _write_json_rel(
        "LockedSpec.json",
        {
            "run_id": "test-run",
            "belgi_version": "0.0.0",
            "tier": {"tier_id": "tier-2"},
            "waivers_applied": [],
            "environment_envelope": {"seal_pubkey_ref": seal_pubkey_ref},
        },
    )
    _write_json_rel("Q.json", {})
    _write_json_rel("R.json", {})
    _write_json_rel("Evidence.json", {})

    cp = _run_module(
        "chain.seal_bundle",
        [
            "--repo",
            str(tmp_path),
            "--locked-spec",
            "LockedSpec.json",
            "--gate-q-verdict",
            "Q.json",
            "--gate-r-verdict",
            "R.json",
            "--evidence-manifest",
            "Evidence.json",
            "--final-commit-sha",
            "0" * 40,
            "--sealed-at",
            "2020-01-01T00:00:00+00:00",
            "--signer",
            "test",
            "--seal-signature-file",
            "temp/seal_signature.b64",
            "--out",
            "out/SealManifest.json",
        ],
        cwd=REPO_ROOT,
    )

    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
    assert "Invalid Ed25519 signature (--seal-signature)" in cp.stderr


def test_seal_bundle_tier2_accepts_private_key_from_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def _write_json_rel(rel: str, obj: dict) -> None:
        p = tmp_path / Path(*rel.split("/"))
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8", errors="strict")

    seed_hex = "56" * 32
    pub_rel = "temp/seal_pubkey.hex"
    pub_hex = _ed25519_pubkey_hex_from_seed(seed_hex)
    pub_bytes = (pub_hex + "\n").encode("utf-8", errors="strict")
    (tmp_path / "temp").mkdir(parents=True, exist_ok=True)
    (tmp_path / "temp" / "seal_pubkey.hex").write_bytes(pub_bytes)
    seal_pubkey_ref = {"id": "seal-pubkey", "hash": _sha256_hex(pub_bytes), "storage_ref": pub_rel}

    _write_json_rel(
        "LockedSpec.json",
        {
            "run_id": "test-run",
            "belgi_version": "0.0.0",
            "tier": {"tier_id": "tier-2"},
            "waivers_applied": [],
            "environment_envelope": {"seal_pubkey_ref": seal_pubkey_ref},
        },
    )
    _write_json_rel("Q.json", {})
    _write_json_rel("R.json", {})
    _write_json_rel("Evidence.json", {})

    monkeypatch.setenv("BELGI_TEST_SEAL_PRIVATE_KEY", seed_hex + "\n")
    cp = _run_module(
        "chain.seal_bundle",
        [
            "--repo",
            str(tmp_path),
            "--locked-spec",
            "LockedSpec.json",
            "--gate-q-verdict",
            "Q.json",
            "--gate-r-verdict",
            "R.json",
            "--evidence-manifest",
            "Evidence.json",
            "--final-commit-sha",
            "0" * 40,
            "--sealed-at",
            "2020-01-01T00:00:00+00:00",
            "--signer",
            "test",
            "--seal-private-key-env",
            "BELGI_TEST_SEAL_PRIVATE_KEY",
            "--out",
            "out/SealManifest.json",
        ],
        cwd=REPO_ROOT,
    )

    assert cp.returncode == 0, (cp.returncode, cp.stdout, cp.stderr)
    manifest = _read_json(tmp_path / "out" / "SealManifest.json")
    assert manifest.get("signature_alg") == "ed25519"
    assert isinstance(manifest.get("signature"), str) and bool(str(manifest["signature"]).strip())
