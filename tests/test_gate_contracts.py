from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import hashlib
import os
import stat
import time
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.repo_local

REPO_ROOT = Path(__file__).resolve().parents[1]

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
for _k in list(sys.modules.keys()):
    if _k == "belgi" or _k.startswith("belgi."):
        del sys.modules[_k]

from belgi.protocol.pack import MANIFEST_FILENAME, build_manifest_bytes
from chain.logic.s_checks.context import SCheckContext
from chain.logic.s_checks import s2_objectref_binding


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


def _prompt_block_ids(repo_root: Path) -> list[str]:
    text = (repo_root / "belgi" / "templates" / "PromptBundle.blocks.md").read_text(encoding="utf-8", errors="strict")
    lines = text.splitlines()
    header_idx = None
    for i, line in enumerate(lines):
        if line.strip().startswith("| block_id | block_name |"):
            header_idx = i
            break
    assert header_idx is not None
    i = header_idx + 1
    while i < len(lines) and "|---" not in lines[i]:
        i += 1
    i += 1
    ids: list[str] = []
    while i < len(lines):
        line = lines[i].strip()
        if not line.startswith("|"):
            break
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 3:
            block_id = parts[1]
            if block_id:
                ids.append(block_id)
        i += 1
    ids = sorted(set(ids))
    assert ids
    return ids


def test_gate_q_evidence_002_remediation_substitutes_missing_kind() -> None:
    taxo = _taxonomy_ids(REPO_ROOT)

    work = REPO_ROOT / "temp" / "pytest_gate_contracts" / "q_evidence_002"
    _clean_dir(work)

    # Use the passing fixture's Intent+LockedSpec, but a modified EvidenceManifest with
    # the first required kind removed (tier order => command_log).
    fixture_root = REPO_ROOT / "policy" / "fixtures" / "public" / "gate_q" / "q_pass_tier0"
    intent_rel = "policy/fixtures/public/gate_q/q_pass_tier0/IntentSpec.core.md"
    locked_rel = "policy/fixtures/public/gate_q/q_pass_tier0/LockedSpec.json"

    em = _read_json(fixture_root / "EvidenceManifest.json")
    artifacts = em.get("artifacts")
    assert isinstance(artifacts, list)
    em["artifacts"] = [a for a in artifacts if isinstance(a, dict) and a.get("kind") != "command_log"]

    em_rel = "temp/pytest_gate_contracts/q_evidence_002/EvidenceManifest.missing_command_log.json"
    em_path = REPO_ROOT / Path(*em_rel.split("/"))
    em_path.parent.mkdir(parents=True, exist_ok=True)
    em_path.write_text(json.dumps(em, indent=2, sort_keys=True) + "\n", encoding="utf-8", errors="strict")

    out_rel = "temp/pytest_gate_contracts/q_evidence_002/GateVerdict.json"
    out_path = REPO_ROOT / Path(*out_rel.split("/"))

    cp = _run_module(
        "chain.gate_q_verify",
        [
            "--repo",
            ".",
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


def test_gate_q_r_s_categories_are_taxonomy_valid_for_fixtures() -> None:
    taxo = _taxonomy_ids(REPO_ROOT)

    work = REPO_ROOT / "temp" / "pytest_gate_contracts" / "taxo_valid"
    _clean_dir(work)

    # Gate Q fixture (NO-GO)
    q_out_rel = "temp/pytest_gate_contracts/taxo_valid/Q.GateVerdict.json"
    q_cp = _run_module(
        "chain.gate_q_verify",
        [
            "--repo",
            ".",
            "--intent-spec",
            "policy/fixtures/public/gate_q/q_intent_001_no_yaml_block/IntentSpec.core.md",
            "--locked-spec",
            "policy/fixtures/public/gate_q/q_intent_001_no_yaml_block/LockedSpec.json",
            "--evidence-manifest",
            "policy/fixtures/public/gate_q/q_intent_001_no_yaml_block/EvidenceManifest.json",
            "--out",
            q_out_rel,
        ],
        cwd=REPO_ROOT,
    )
    assert q_cp.returncode == 2, (q_cp.returncode, q_cp.stdout, q_cp.stderr)
    q_gv = _read_json(REPO_ROOT / Path(*q_out_rel.split("/")))
    assert q_gv.get("failure_category") in taxo

    # Gate R fixture (NO-GO)
    r_report_rel = "temp/pytest_gate_contracts/taxo_valid/R.verify_report.json"
    r_gv_rel = "temp/pytest_gate_contracts/taxo_valid/R.GateVerdict.json"
    r_snap_rel = "temp/pytest_gate_contracts/taxo_valid/R.EvidenceManifest.r_snapshot.json"
    r_cp = _run_module(
        "chain.gate_r_verify",
        [
            "--repo",
            ".",
            "--locked-spec",
            "policy/fixtures/public/gate_r/r0_evidence_sufficiency_fail/LockedSpec.json",
            "--gate-q-verdict",
            "policy/fixtures/public/gate_r/r0_evidence_sufficiency_fail/GateVerdict.Q.json",
            "--evidence-manifest",
            "policy/fixtures/public/gate_r/r0_evidence_sufficiency_fail/EvidenceManifest.json",
            "--r-snapshot-manifest-out",
            r_snap_rel,
            "--evaluated-revision",
            "HEAD",
            "--out",
            r_report_rel,
            "--gate-verdict-out",
            r_gv_rel,
        ],
        cwd=REPO_ROOT,
    )
    assert r_cp.returncode == 2, (r_cp.returncode, r_cp.stdout, r_cp.stderr)
    r_gv = _read_json(REPO_ROOT / Path(*r_gv_rel.split("/")))
    assert r_gv.get("failure_category") in taxo

    # Gate S fixture (NO-GO)
    s_out_rel = "temp/pytest_gate_contracts/taxo_valid/S.GateVerdict.json"
    s_cp = _run_module(
        "chain.gate_s_verify",
        [
            "--repo",
            ".",
            "--locked-spec",
            "policy/fixtures/public/gate_s/s_fail_tier1_bad_signature_len/LockedSpec.json",
            "--seal-manifest",
            "policy/fixtures/public/gate_s/s_fail_tier1_bad_signature_len/SealManifest.json",
            "--evidence-manifest",
            "policy/fixtures/public/gate_s/s_fail_tier1_bad_signature_len/EvidenceManifest.json",
            "--out",
            s_out_rel,
        ],
        cwd=REPO_ROOT,
    )
    assert s_cp.returncode == 2, (s_cp.returncode, s_cp.stdout, s_cp.stderr)
    s_gv = _read_json(REPO_ROOT / Path(*s_out_rel.split("/")))
    assert s_gv.get("failure_category") in taxo


def test_gate_q_taxonomy_mismatch_is_internal_error_and_no_output() -> None:
    # Create a fake repo root with an incomplete taxonomy, proving verifiers fail-closed
    # (exit code 3) and do not emit a GateVerdict.
    fake_root = REPO_ROOT / "temp" / "pytest_gate_contracts" / "fake_repo"
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

    # Minimal file set for Gate Q inputs (repo-relative to fake_root).
    for rel in [
        "policy/fixtures/public/gate_q/q_intent_001_no_yaml_block/IntentSpec.core.md",
        "policy/fixtures/public/gate_q/q_intent_001_no_yaml_block/LockedSpec.json",
        "policy/fixtures/public/gate_q/q_intent_001_no_yaml_block/EvidenceManifest.json",
    ]:
        src = REPO_ROOT / Path(*rel.split("/"))
        dst = fake_root / Path(*rel.split("/"))
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(src.read_bytes())

    out_rel = "temp/pytest_gate_contracts/fake_repo/out/GateVerdict.json"
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
            "policy/fixtures/public/gate_q/q_intent_001_no_yaml_block/IntentSpec.core.md",
            "--locked-spec",
            "policy/fixtures/public/gate_q/q_intent_001_no_yaml_block/LockedSpec.json",
            "--evidence-manifest",
            "policy/fixtures/public/gate_q/q_intent_001_no_yaml_block/EvidenceManifest.json",
            "--out",
            "out/GateVerdict.json",
        ],
        cwd=REPO_ROOT,
    )

    assert cp.returncode == 3, (cp.returncode, cp.stdout, cp.stderr)
    assert "category_id not in taxonomy" in cp.stderr
    assert not out_path.exists()


def test_c3_docs_bundle_is_deterministic_and_profile_scoped() -> None:
    fake_root = REPO_ROOT / "temp" / "pytest_gate_contracts" / "c3_bundle_repo"
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

    # Inputs (in fake repo): LockedSpec, GateVerdicts, and snapshot EvidenceManifests.
    locked_rel = "inputs/LockedSpec.json"
    q_rel = "inputs/GateVerdict.Q.json"
    r_rel = "inputs/GateVerdict.R.json"
    qsnap_rel = "inputs/EvidenceManifest.Q.json"
    rsnap_rel = "inputs/EvidenceManifest.R.json"

    (fake_root / "inputs").mkdir(parents=True, exist_ok=True)
    (fake_root / Path(*locked_rel.split("/"))).write_bytes(
        (REPO_ROOT / "policy" / "fixtures" / "public" / "gate_r" / "r_pass_tier1" / "LockedSpec.json").read_bytes()
    )
    run_id = _read_json(fake_root / Path(*locked_rel.split("/"))).get("run_id")
    assert isinstance(run_id, str) and run_id

    # Prompt block hashes mapping must cover all registry block_ids.
    pb_ids = _prompt_block_ids(REPO_ROOT)
    pb_hashes = {bid: _sha256_hex(bid.encode("utf-8", errors="strict")) for bid in pb_ids}
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

    fixture_dir = "policy/fixtures/public/gate_r/r_pass_tier1"
    paths = _copy_fixture_inputs(REPO_ROOT, tmp_path, fixture_dir)

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

    fixture_dir = "policy/fixtures/public/gate_r/r_pass_tier1"
    paths = _copy_fixture_inputs(REPO_ROOT, tmp_path, fixture_dir)
    shutil.copytree(REPO_ROOT / fixture_dir, tmp_path / fixture_dir, dirs_exist_ok=True)

    # r_pass_tier1 references a shared consistency sweep artifact; copy it so Gate R does not fail
    # earlier on missing/mismatched bytes in this write-failure test.
    (tmp_path / "policy").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(REPO_ROOT / "policy" / "consistency_sweep.json", tmp_path / "policy" / "consistency_sweep.json")

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
            "out/GateVerdict.json",
        ],
        cwd=REPO_ROOT,
    )
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
    gv = _read_json(tmp_path / "out" / "GateVerdict.json")
    assert gv.get("failure_category") == "FR-INVARIANT-FAILED"


def test_gate_r_fixture_allows_opaque_revision_without_git(tmp_path: Path) -> None:
    """Gate R fixtures must be runnable without git history (.git absent).

    In fixture context, a 40-hex evaluated revision may be treated as an opaque id,
    and git-dependent checks must use fallbacks instead of raising tool errors.
    """

    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)

    fixture_dir = "policy/fixtures/public/gate_r/r0_evidence_sufficiency_fail"
    shutil.copytree(REPO_ROOT / fixture_dir, tmp_path / fixture_dir, dirs_exist_ok=True)

    # Fixture EvidenceManifests may reference shared policy artifacts.
    (tmp_path / "policy").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(REPO_ROOT / "policy" / "consistency_sweep.json", tmp_path / "policy" / "consistency_sweep.json")

    locked_rel = f"{fixture_dir}/LockedSpec.json"
    evidence_rel = f"{fixture_dir}/EvidenceManifest.json"
    gate_q_rel = f"{fixture_dir}/GateVerdict.Q.json"

    locked_doc = _read_json(tmp_path / locked_rel)
    commit_sha = str(locked_doc.get("upstream_state", {}).get("commit_sha", ""))
    assert len(commit_sha) == 40

    cp = _run_module(
        "chain.gate_r_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            locked_rel,
            "--gate-q-verdict",
            gate_q_rel,
            "--evidence-manifest",
            evidence_rel,
            "--r-snapshot-manifest-out",
            "out/EvidenceManifest.r_snapshot.json",
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
    gv = _read_json(tmp_path / "out" / "GateVerdict.json")
    failures = gv.get("failures")
    assert isinstance(failures, list) and failures
    assert failures[0].get("rule_id") == "R0.evidence_sufficiency"


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

    from tools.sweep import _git_tree_sha as sweep_git_tree_sha
    from tools.sweep import _git_tree_sha_excluding
    from tools.sweep import CANONICAL_SWEEP_OUT, CANONICAL_SWEEP_SUMMARY

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

    from tools.sweep import _git_tree_sha_excluding
    from tools.sweep import CANONICAL_SWEEP_OUT

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


def test_cs_ev_006_fix_manifest_idempotent() -> None:
    from tools.sweep import _fix_cs_ev_006_manifest, CANONICAL_SWEEP_OUT

    expected = "0" * 64
    em = {"artifacts": []}
    assert _fix_cs_ev_006_manifest(em_obj=em, expected_hash=expected) is True
    assert _fix_cs_ev_006_manifest(em_obj=em, expected_hash=expected) is False

    arts = em["artifacts"]
    assert isinstance(arts, list)
    assert len([a for a in arts if a.get("id") == "policy.consistency_sweep"]) == 1
    a0 = next(a for a in arts if a.get("id") == "policy.consistency_sweep")
    assert a0["hash"] == expected
    assert a0["storage_ref"] == CANONICAL_SWEEP_OUT


def test_cs_ev_006_normalization_stable_missing_vs_present() -> None:
    """Normalization used for fixed-point hash must not depend on whether the entry exists.

    Daily-life analogy: we want the 'receipt calculation' to treat a missing line-item as if it
    were present with a $0 placeholder, so adding it later doesn't change the total's hash.
    """

    from tools.sweep import _ev006_normalized_manifest_bytes, CANONICAL_SWEEP_OUT, ZERO_SHA256

    base = {
        "schema_version": "1.0.0",
        "run_id": "r",
        "commands_executed": [],
        "envelope_attestation": None,
    }

    em_missing = dict(base)
    em_present = {
        **base,
        "artifacts": [
            {
                "kind": "policy_report",
                "id": "policy.consistency_sweep",
                "hash": "a" * 64,
                "media_type": "application/json",
                "storage_ref": CANONICAL_SWEEP_OUT,
                "produced_by": "C1",
            }
        ],
    }

    b1 = _ev006_normalized_manifest_bytes(em_missing)
    b2 = _ev006_normalized_manifest_bytes(em_present)

    assert b1 == b2
    assert ZERO_SHA256.encode("utf-8") in b1


def _write_cases_json(repo_root: Path, *, rel: str, case_ids: list[str], expected_exit_code: int = 0) -> None:
    path = repo_root / Path(*rel.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "case_id": cid,
                        "expected_exit_code": expected_exit_code,
                    }
                    for cid in case_ids
                ]
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )


def _write_min_gate_s_fixture_case(repo_root: Path, *, case_id: str, seal_filename: str = "SealManifest.json") -> str:
    case_dir = repo_root / "policy" / "fixtures" / "public" / "gate_s" / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    # Minimal on-disk shape for sweep's seal-related detection and command construction.
    (case_dir / "LockedSpec.json").write_text("{}\n", encoding="utf-8", errors="strict", newline="\n")
    (case_dir / "EvidenceManifest.json").write_text("{}\n", encoding="utf-8", errors="strict", newline="\n")
    (case_dir / seal_filename).write_text("OLD\n", encoding="utf-8", errors="strict", newline="\n")
    return case_dir.relative_to(repo_root).as_posix()


def test_fix_fixtures_does_not_regen_without_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from tools import sweep as sweep_mod

    _write_cases_json(tmp_path, rel="policy/fixtures/public/gate_s/cases.json", case_ids=["case1"], expected_exit_code=0)
    fixture_dir_rel = _write_min_gate_s_fixture_case(tmp_path, case_id="case1")
    seal_path = tmp_path / "policy" / "fixtures" / "public" / "gate_s" / "case1" / "SealManifest.json"
    before = seal_path.read_bytes()

    calls: list[str] = []

    def _fake_run_at(repo_root: Path, cmd: list[str]) -> tuple[int, str, str]:
        assert repo_root == tmp_path
        assert len(cmd) >= 3 and cmd[1] == "-m"
        module = cmd[2]
        calls.append(module)
        if module == "chain.seal_bundle":
            raise AssertionError("seal_bundle must not run unless --regen-seals is set")
        if module == "chain.gate_s_verify":
            # Simulate drift (mismatch vs expected_exit_code=0).
            return 2, "", "gate_s_verify mismatch\n"
        raise AssertionError(f"unexpected module: {module}")

    monkeypatch.setattr(sweep_mod, "_run_at", _fake_run_at)

    rc = sweep_mod._regen_and_verify_seal_related_fixtures(
        repo_root=tmp_path,
        fixture_dirs_rel=[fixture_dir_rel],
        regen_seals=False,
    )

    out = capsys.readouterr()
    assert rc == 2
    assert "REGEN-SEALS NO-GO" in out.err
    assert "Remediation: run `python -m tools.sweep consistency --repo . --fix-fixtures --regen-seals`." in out.err
    assert seal_path.read_bytes() == before
    assert calls.count("chain.seal_bundle") == 0


def test_fix_fixtures_regen_only_touched_seal_fixtures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from tools import sweep as sweep_mod

    _write_cases_json(tmp_path, rel="policy/fixtures/public/gate_s/cases.json", case_ids=["case1", "case2"], expected_exit_code=0)
    case1_rel = _write_min_gate_s_fixture_case(tmp_path, case_id="case1")
    case2_rel = _write_min_gate_s_fixture_case(tmp_path, case_id="case2")

    seal1 = tmp_path / "policy" / "fixtures" / "public" / "gate_s" / "case1" / "SealManifest.json"
    seal2 = tmp_path / "policy" / "fixtures" / "public" / "gate_s" / "case2" / "SealManifest.json"
    before1 = seal1.read_bytes()
    before2 = seal2.read_bytes()

    seal_bundle_outs: list[str] = []
    gate_s_verify_outs: list[str] = []

    def _fake_run_at(repo_root: Path, cmd: list[str]) -> tuple[int, str, str]:
        assert repo_root == tmp_path
        assert len(cmd) >= 3 and cmd[1] == "-m"
        module = cmd[2]

        if module == "chain.seal_bundle":
            out_idx = cmd.index("--out") + 1
            out_rel = cmd[out_idx]
            seal_bundle_outs.append(out_rel)
            out_path = repo_root / Path(*out_rel.split("/"))
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text("REGEN\n", encoding="utf-8", errors="strict", newline="\n")
            return 0, "", ""

        if module == "chain.gate_s_verify":
            out_idx = cmd.index("--out") + 1
            out_rel = cmd[out_idx]
            gate_s_verify_outs.append(out_rel)
            out_path = repo_root / Path(*out_rel.split("/"))
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text("{\"status\":\"PASS\"}\n", encoding="utf-8", errors="strict", newline="\n")
            return 0, "", ""

        raise AssertionError(f"unexpected module: {module}")

    monkeypatch.setattr(sweep_mod, "_run_at", _fake_run_at)

    rc = sweep_mod._regen_and_verify_seal_related_fixtures(
        repo_root=tmp_path,
        fixture_dirs_rel=[case1_rel],
        regen_seals=True,
    )
    assert rc == 0

    assert seal1.read_bytes() != before1
    assert seal1.read_text(encoding="utf-8", errors="strict").startswith("REGEN")
    assert seal2.read_bytes() == before2

    assert len(seal_bundle_outs) == 1
    assert "/case1/" in f"/{seal_bundle_outs[0]}"
    assert all("/case2/" not in f"/{p}" for p in seal_bundle_outs)
    assert len(gate_s_verify_outs) == 1
    assert "S__postregen__case1.json" in gate_s_verify_outs[0]


def test_post_regen_gate_s_verify_passes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from tools import sweep as sweep_mod

    _write_cases_json(tmp_path, rel="policy/fixtures/public/gate_s/cases.json", case_ids=["case1"], expected_exit_code=0)
    fixture_dir_rel = _write_min_gate_s_fixture_case(tmp_path, case_id="case1")

    def _fake_run_at(repo_root: Path, cmd: list[str]) -> tuple[int, str, str]:
        assert repo_root == tmp_path
        assert len(cmd) >= 3 and cmd[1] == "-m"
        module = cmd[2]

        out_idx = cmd.index("--out") + 1
        out_rel = cmd[out_idx]
        out_path = repo_root / Path(*out_rel.split("/"))
        out_path.parent.mkdir(parents=True, exist_ok=True)

        if module == "chain.seal_bundle":
            out_path.write_text("REGEN\n", encoding="utf-8", errors="strict", newline="\n")
            return 0, "", ""
        if module == "chain.gate_s_verify":
            out_path.write_text("{\"status\":\"PASS\"}\n", encoding="utf-8", errors="strict", newline="\n")
            return 0, "", ""

        raise AssertionError(f"unexpected module: {module}")

    monkeypatch.setattr(sweep_mod, "_run_at", _fake_run_at)

    rc = sweep_mod._regen_and_verify_seal_related_fixtures(
        repo_root=tmp_path,
        fixture_dirs_rel=[fixture_dir_rel],
        regen_seals=True,
    )
    assert rc == 0


def test_cs_ev_006_pass_omits_details_and_is_fixed_point_stable(tmp_path: Path) -> None:
    from tools.sweep import InvariantResult, _canonical_json_bytes, _eval_cs_ev_006_expected_hash

    expected_hash = "a" * 64

    cases_dir = tmp_path / "policy" / "fixtures" / "public" / "gate_r"
    fixdir = tmp_path / "policy" / "fixtures" / "public" / "gate_r" / "fixtures" / "case1"
    fixdir.mkdir(parents=True, exist_ok=True)

    locked_rel = "policy/fixtures/public/gate_r/fixtures/case1/LockedSpec.json"
    em_rel = "policy/fixtures/public/gate_r/fixtures/case1/EvidenceManifest.json"

    (tmp_path / Path(*locked_rel.split("/"))).write_text(
        json.dumps({"tier": {"tier_id": "tier-1"}}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    (tmp_path / Path(*em_rel.split("/"))).write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "run_id": "r",
                "artifacts": [
                    {
                        "kind": "policy_report",
                        "id": "policy.consistency_sweep",
                        "hash": expected_hash,
                        "media_type": "application/json",
                        "storage_ref": "policy/consistency_sweep.json",
                        "produced_by": "C1",
                    }
                ],
                "commands_executed": [],
                "envelope_attestation": None,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    (cases_dir / "cases.json").write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "case_id": "case1",
                        "expected_exit_code": 0,
                        "paths": {"locked_spec": locked_rel, "evidence_manifest": em_rel},
                    }
                ]
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    res, modified = _eval_cs_ev_006_expected_hash(tmp_path, expected_hash, fix_fixtures=False)
    assert modified == []
    assert res.invariant_id == "CS-EV-006"
    assert res.status == "PASS"
    assert res.details is None

    # Serialize a minimal report containing only CS-EV-006 and ensure PASS has no details key.
    def _render_one(inv: InvariantResult) -> tuple[bytes, str, dict]:
        report = {
            "artifact_id": "policy.consistency_sweep",
            "generated_at": "1970-01-01T00:00:00Z",
            "sweep_started_at": "1970-01-01T00:00:00Z",
            "sweep_finished_at": "1970-01-01T00:00:00Z",
            "tool": {"name": "consistency-sweep", "version": "1.0.0"},
            "repo_revision": "0" * 40,
            "inputs": [],
            "invariants": [
                {
                    "invariant_id": inv.invariant_id,
                    "status": inv.status,
                    "evidence": inv.evidence,
                    "remediation": "" if inv.status == "PASS" else inv.remediation,
                    **({"details": inv.details} if isinstance(inv.details, dict) else {}),
                }
            ],
            "summary": {
                "total": 1,
                "passed": 1 if inv.status == "PASS" else 0,
                "failed": 0 if inv.status == "PASS" else 1,
            },
            "failures": [],
        }
        b = _canonical_json_bytes(report)
        assert b.endswith(b"\n")
        return b, _sha256_hex(b), report

    cs_pass = InvariantResult("CS-EV-006", "PASS", ["policy/fixtures/public/gate_r/cases.json"], "")
    b1, h1, _ = _render_one(cs_pass)
    b2, h2, report2 = _render_one(res)
    assert b2 == b1
    assert h2 == h1
    assert b2.endswith(b"\n")

    inv_obj = report2["invariants"][0]
    assert inv_obj["invariant_id"] == "CS-EV-006"
    assert inv_obj["status"] == "PASS"
    assert "details" not in inv_obj


def test_consistency_sweep_bytes_deterministic_on_same_tree(tmp_path: Path) -> None:
    import hashlib
    import shutil
    import sys

    from tools.sweep import _canonical_inputs

    repo_root = Path(__file__).resolve().parents[1]
    tmp_repo = tmp_path / "repo"
    tmp_repo.mkdir(parents=True, exist_ok=True)

    # Copy the governed input surface into a throwaway repo so the test doesn't mutate the working tree.
    canon = _canonical_inputs(repo_root)
    for rel in canon:
        src = repo_root / Path(*rel.split("/"))
        dst = tmp_repo / Path(*rel.split("/"))
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    # CS-EV-006 evaluates governed Gate R fixtures; include those too.
    src_gate_r = repo_root / "policy" / "fixtures" / "public" / "gate_r"
    dst_gate_r = tmp_repo / "policy" / "fixtures" / "public" / "gate_r"
    shutil.copytree(src_gate_r, dst_gate_r, dirs_exist_ok=True)

    # Additional governed fixture sets (consistency sweep invariants): Gate S + SEAL.
    src_gate_s = repo_root / "policy" / "fixtures" / "public" / "gate_s"
    dst_gate_s = tmp_repo / "policy" / "fixtures" / "public" / "gate_s"
    shutil.copytree(src_gate_s, dst_gate_s, dirs_exist_ok=True)

    src_seal = repo_root / "policy" / "fixtures" / "public" / "seal"
    dst_seal = tmp_repo / "policy" / "fixtures" / "public" / "seal"
    shutil.copytree(src_seal, dst_seal, dirs_exist_ok=True)

    _init_git_repo(tmp_repo)

    cmd_fix = [sys.executable, "-m", "tools.sweep", "consistency", "--repo", str(tmp_repo), "--fix-fixtures"]
    cmd = [sys.executable, "-m", "tools.sweep", "consistency", "--repo", str(tmp_repo)]

    cp_fix = subprocess.run(cmd_fix, cwd=repo_root, check=False, capture_output=True, text=True)
    assert cp_fix.returncode in {0, 1}
    if cp_fix.returncode == 1:
        assert "FIX-FIXTURES" in (cp_fix.stderr or "")
    cp = subprocess.run(cmd, cwd=repo_root, check=False, capture_output=True, text=True)
    assert cp.returncode == 0, (cp.returncode, cp.stdout, cp.stderr)
    p = tmp_repo / "policy" / "consistency_sweep.json"
    b1 = p.read_bytes()
    h1 = hashlib.sha256(b1).hexdigest()

    cp2 = subprocess.run(cmd, cwd=repo_root, check=False, capture_output=True, text=True)
    assert cp2.returncode == 0, (cp2.returncode, cp2.stdout, cp2.stderr)
    b2 = p.read_bytes()
    h2 = hashlib.sha256(b2).hexdigest()

    assert b1 == b2
    assert h1 == h2
    assert b2.endswith(b"\n")


def test_consistency_sweep_ev006_stable_after_fix_and_commit(tmp_path: Path) -> None:
    import shutil
    import sys

    from tools.sweep import _canonical_inputs

    repo_root = Path(__file__).resolve().parents[1]
    tmp_repo = tmp_path / "repo"
    tmp_repo.mkdir(parents=True, exist_ok=True)

    canon = _canonical_inputs(repo_root)
    for rel in canon:
        src = repo_root / Path(*rel.split("/"))
        dst = tmp_repo / Path(*rel.split("/"))
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    src_gate_r = repo_root / "policy" / "fixtures" / "public" / "gate_r"
    dst_gate_r = tmp_repo / "policy" / "fixtures" / "public" / "gate_r"
    shutil.copytree(src_gate_r, dst_gate_r, dirs_exist_ok=True)

    src_gate_s = repo_root / "policy" / "fixtures" / "public" / "gate_s"
    dst_gate_s = tmp_repo / "policy" / "fixtures" / "public" / "gate_s"
    shutil.copytree(src_gate_s, dst_gate_s, dirs_exist_ok=True)

    src_seal = repo_root / "policy" / "fixtures" / "public" / "seal"
    dst_seal = tmp_repo / "policy" / "fixtures" / "public" / "seal"
    shutil.copytree(src_seal, dst_seal, dirs_exist_ok=True)

    _init_git_repo(tmp_repo)

    cmd_fix = [sys.executable, "-m", "tools.sweep", "consistency", "--repo", str(tmp_repo), "--fix-fixtures"]
    cmd = [sys.executable, "-m", "tools.sweep", "consistency", "--repo", str(tmp_repo)]

    cp_fix = subprocess.run(cmd_fix, cwd=repo_root, check=False, capture_output=True, text=True)
    assert cp_fix.returncode in {0, 1}

    subprocess.run(["git", "add", "-A"], cwd=tmp_repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "--allow-empty", "-m", "fix fixtures"], cwd=tmp_repo, check=True, capture_output=True)

    cp = subprocess.run(cmd, cwd=repo_root, check=False, capture_output=True, text=True)
    assert cp.returncode == 0, (cp.returncode, cp.stdout, cp.stderr)


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
    """Copy fixture inputs into fake_root, return relative paths dict."""
    src_dir = fixture_root / fixture_dir
    dst_dir = fake_root / fixture_dir
    dst_dir.mkdir(parents=True, exist_ok=True)

    out = {}
    for name, key in [
        ("IntentSpec.core.md", "intent"),
        ("LockedSpec.json", "locked"),
        ("EvidenceManifest.json", "evidence"),
        ("SealManifest.json", "seal"),
        ("GateVerdict.Q.json", "gate_q_verdict"),
        ("GateVerdict.R.json", "gate_r_verdict"),
    ]:
        src = src_dir / name
        if not src.exists():
            continue
        if name == "LockedSpec.json" and not include_locked:
            continue
        dst = dst_dir / name
        dst.write_bytes(src.read_bytes())
        out[key] = f"{fixture_dir}/{name}"

    return out


def _tamper_locked_spec_pack_id(locked_path: Path, new_pack_id: str) -> None:
    """Overwrite protocol_pack.pack_id in a LockedSpec file."""
    data = json.loads(locked_path.read_text(encoding="utf-8", errors="strict"))
    data["protocol_pack"]["pack_id"] = new_pack_id
    locked_path.write_text(
        json.dumps(data, indent=2, sort_keys=True), encoding="utf-8", errors="strict"
    )


def _remove_locked_spec_protocol_pack(locked_path: Path) -> None:
    """Remove protocol_pack field entirely from LockedSpec file."""
    data = json.loads(locked_path.read_text(encoding="utf-8", errors="strict"))
    del data["protocol_pack"]
    locked_path.write_text(
        json.dumps(data, indent=2, sort_keys=True), encoding="utf-8", errors="strict"
    )


def test_gate_q_protocol_identity_mismatch_pack_id(tmp_path: Path) -> None:
    """Gate Q MUST emit FQ-PROTOCOL-IDENTITY-MISMATCH on pack_id mismatch."""
    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)

    fixture_dir = "policy/fixtures/public/gate_q/q_pass_tier0"
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
    """Gate R MUST emit FR-PROTOCOL-IDENTITY-MISMATCH on pack_id mismatch."""
    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)

    fixture_dir = "policy/fixtures/public/gate_r/r_pass_tier1"
    paths = _copy_fixture_inputs(REPO_ROOT, tmp_path, fixture_dir)

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

    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
    gv = _read_json(out_path)
    assert gv.get("failure_category") == "FR-PROTOCOL-IDENTITY-MISMATCH", gv


def test_gate_s_protocol_identity_mismatch_pack_id(tmp_path: Path) -> None:
    """Gate S MUST emit FS-PROTOCOL-IDENTITY-MISMATCH on pack_id mismatch."""
    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)

    fixture_dir = "policy/fixtures/public/gate_s/s_pass_tier1_unsigned"
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

    fixture_dir = "policy/fixtures/public/gate_q/q_pass_tier0"
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

    fixture_dir = "policy/fixtures/public/gate_r/r_pass_tier1"
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

    fixture_dir = "policy/fixtures/public/gate_s/s_pass_tier1_unsigned"
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


def test_seal_bundle_fixture_mode_guard_contract(tmp_path: Path) -> None:
    def _write_json_rel(rel: str, obj: dict) -> None:
        p = tmp_path / Path(*rel.split("/"))
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8", errors="strict")

    # Minimal repo layout
    (tmp_path / "policy" / "fixtures").mkdir(parents=True, exist_ok=True)
    (tmp_path / "temp").mkdir(parents=True, exist_ok=True)

    # A deterministic, parseable Ed25519 public key (32 bytes, hex-encoded). Any 32 bytes are accepted.
    pub_rel = "temp/seal_pubkey.hex"
    pub_bytes = (b"0" * 64) + b"\n"
    (tmp_path / "temp" / "seal_pubkey.hex").write_bytes(pub_bytes)
    seal_pubkey_ref = {"id": "seal-pubkey", "hash": _sha256_hex(pub_bytes), "storage_ref": pub_rel}

    _write_json_rel("LockedSpec.json", {
        "run_id": "test-run",
        "belgi_version": "0.0.0",
        "tier": {"tier_id": "tier-1"},
        "waivers_applied": [],
        "environment_envelope": {"seal_pubkey_ref": seal_pubkey_ref},
    })
    _write_json_rel("Q.json", {})
    _write_json_rel("R.json", {})
    _write_json_rel("Evidence.json", {})

    # Fixture key (under policy/fixtures/)
    fixture_key_rel = "policy/fixtures/dev_fixture_key.hex"
    (tmp_path / "policy" / "fixtures" / "dev_fixture_key.hex").write_bytes(b"not-a-key\n")

    # Non-fixture key
    non_fixture_key_rel = "temp/non_fixture_key.hex"
    (tmp_path / "temp" / "non_fixture_key.hex").write_bytes(b"not-a-key\n")

    common_args = [
        "--repo", str(tmp_path),
        "--locked-spec", "LockedSpec.json",
        "--gate-q-verdict", "Q.json",
        "--gate-r-verdict", "R.json",
        "--evidence-manifest", "Evidence.json",
        "--final-commit-sha", "0" * 40,
        "--sealed-at", "2020-01-01T00:00:00+00:00",
        "--signer", "test",
        "--out", "out/SealManifest.json",
    ]

    # Case 1: fixture key path requires --fixture-mode.
    cp = _run_module(
        "chain.seal_bundle",
        [*common_args, "--seal-private-key", fixture_key_rel],
        cwd=REPO_ROOT,
    )
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
    assert "FIXTURE-KEY NO-GO: --seal-private-key requires explicit --fixture-mode" in cp.stderr

    # Case 2: --fixture-mode requires key under policy/fixtures/.
    cp = _run_module(
        "chain.seal_bundle",
        [*common_args, "--fixture-mode", "--seal-private-key", non_fixture_key_rel],
        cwd=REPO_ROOT,
    )
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
    assert "FIXTURE-KEY NO-GO: --seal-private-key must be under policy/fixtures/ when --fixture-mode is set" in cp.stderr

    # Case 3: non-fixture key path allowed without --fixture-mode (should fail later, but not with fixture-mode guard).
    cp = _run_module(
        "chain.seal_bundle",
        [*common_args, "--seal-private-key", non_fixture_key_rel],
        cwd=REPO_ROOT,
    )
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
    assert "FIXTURE-KEY NO-GO" not in cp.stderr

    # Case 4: fixture key allowed with --fixture-mode (should fail later, but not with fixture-mode guard).
    cp = _run_module(
        "chain.seal_bundle",
        [*common_args, "--fixture-mode", "--seal-private-key", fixture_key_rel],
        cwd=REPO_ROOT,
    )
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
    assert "FIXTURE-KEY NO-GO" not in cp.stderr


def test_gate_s_fixture_layout_is_repo_canonical() -> None:
    root = REPO_ROOT / "policy" / "fixtures" / "public" / "gate_s"
    assert (root / "cases.json").exists()
    assert not (root / "fixtures").exists(), "Gate S fixtures must not be nested under gate_s/fixtures/"

    cases_doc = _read_json(root / "cases.json")
    cases = cases_doc.get("cases")
    assert isinstance(cases, list) and cases

    for case in cases:
        assert isinstance(case, dict)
        case_id = case.get("case_id")
        assert isinstance(case_id, str) and case_id
        case_dir = root / case_id
        assert case_dir.is_dir(), case_id

        paths = case.get("paths")
        assert isinstance(paths, dict)
        for k in ["locked_spec", "evidence_manifest", "seal_manifest"]:
            p = paths.get(k)
            assert isinstance(p, str) and p
            expected_prefix = f"policy/fixtures/public/gate_s/{case_id}/"
            assert p.replace("\\", "/").startswith(expected_prefix)
