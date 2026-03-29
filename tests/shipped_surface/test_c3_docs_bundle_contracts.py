from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from tests.helpers import builders

pytestmark = pytest.mark.repo_local

REPO_ROOT = Path(__file__).resolve().parents[2]


def _read_json(path: Path) -> dict[str, Any]:
    obj = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    assert isinstance(obj, dict)
    return obj


def _rmtree_retry(path: Path, *, attempts: int = 12, base_delay_s: float = 0.03) -> None:
    def _onerror(func, p, exc_info):
        _ = exc_info
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
        except (PermissionError, OSError) as exc:
            last_exc = exc
            if i == attempts - 1:
                raise
            time.sleep(base_delay_s * (i + 1))

    if last_exc is not None:
        raise last_exc


def _clean_dir(path: Path) -> None:
    if path.exists():
        _rmtree_retry(path)
    path.mkdir(parents=True, exist_ok=True)


def _sha256_hex(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


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
    for path in _walk_files_sorted(bundle_dir):
        rel = path.relative_to(bundle_dir).as_posix()
        if rel == "docs_bundle_manifest.json":
            continue
        files.append((rel, _sha256_hex(path.read_bytes())))
    payload = "".join(f"{rel}\n{digest}\n" for rel, digest in files).encode("utf-8", errors="strict")
    return _sha256_hex(payload)


def _compute_bundle_root_sha256(*, docs_bundle_manifest_sha256: str, bundle_sha256: str) -> str:
    payload = f"manifest\n{docs_bundle_manifest_sha256}\nbundle\n{bundle_sha256}\n".encode("utf-8", errors="strict")
    return _sha256_hex(payload)


def _write_manual_c1_builtin_toolchain(repo_root: Path, *, expected_runner: str) -> str:
    rel = "out/inputs/toolchain.json"
    path = repo_root / Path(*rel.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "python_version": sys.version.split()[0],
                "runner": expected_runner,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        errors="strict",
    )
    return f"toolchain.main={rel}"


def _generate_prompt_block_hashes_via_c1(
    repo_root: Path,
    *,
    rel_root: str,
    run_id: str,
    out_locked_rel: str,
    builtin_toolchain_ref: str,
) -> tuple[str, dict[str, str]]:
    prompt_bundle_rel = f"{rel_root}/generated/prompt_bundle.txt"
    prompt_block_hashes_rel = f"{rel_root}/generated/prompt_block_hashes.json"
    cp = subprocess.run(
        [
            sys.executable,
            "-m",
            "chain.compiler_c1_intent",
            "--repo",
            str(repo_root),
            "--intent-spec",
            f"{rel_root}/IntentSpec.core.md",
            "--out",
            out_locked_rel,
            "--run-id",
            run_id,
            "--repo-ref",
            "synthetic",
            "--prompt-bundle-out",
            prompt_bundle_rel,
            "--prompt-block-hashes-out",
            prompt_block_hashes_rel,
            "--tolerances",
            f"tier.tolerances={rel_root}/tolerances.json",
            "--envelope-id",
            "env.synthetic",
            "--envelope-description",
            "synthetic envelope",
            "--expected-runner",
            "ci:synthetic",
            "--toolchain-set",
            f"env.toolchains={rel_root}/toolchain-set.json",
            "--toolchain-ref",
            builtin_toolchain_ref,
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    assert cp.returncode == 0, (cp.returncode, cp.stdout, cp.stderr)
    hashes_obj = _read_json(repo_root / Path(*prompt_block_hashes_rel.split("/")))
    return prompt_block_hashes_rel, {str(k): str(v) for k, v in hashes_obj.items()}


def test_c3_docs_bundle_is_deterministic_and_profile_scoped(tmp_path: Path) -> None:
    fake_root = tmp_path / "c3_bundle_repo"
    _clean_dir(fake_root)
    rel_root = "inputs/r_pass_tier1"

    def _copy_rel(rel: str) -> None:
        src = REPO_ROOT / Path(*rel.split("/"))
        dst = fake_root / Path(*rel.split("/"))
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(src, dst, dirs_exist_ok=True)
        else:
            dst.write_bytes(src.read_bytes())

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

    synthetic_r = builders.build_r_repo(fake_root, rel_root=rel_root, run_id="c3-bundle")
    locked_rel = synthetic_r["locked"]
    q_rel = "inputs/GateVerdict.Q.json"
    r_rel = "inputs/GateVerdict.R.json"
    qsnap_rel = "inputs/EvidenceManifest.Q.json"
    rsnap_rel = "inputs/EvidenceManifest.R.json"

    run_id = _read_json(fake_root / Path(*locked_rel.split("/"))).get("run_id")
    assert isinstance(run_id, str) and run_id

    builtin_toolchain_ref = _write_manual_c1_builtin_toolchain(fake_root, expected_runner="ci:synthetic")
    builders.init_git_repo(fake_root)
    prompt_block_hashes_rel, prompt_block_hashes = _generate_prompt_block_hashes_via_c1(
        fake_root,
        rel_root=rel_root,
        run_id=run_id,
        out_locked_rel=locked_rel,
        builtin_toolchain_ref=builtin_toolchain_ref,
    )

    def _write_json(root: Path, rel: str, obj: dict[str, Any]) -> None:
        path = root / Path(*rel.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8", errors="strict")

    def _object_ref(*, obj_id: str, storage_ref: str, file_bytes: bytes) -> dict[str, str]:
        return {"id": obj_id, "storage_ref": storage_ref, "hash": _sha256_hex(file_bytes)}

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
        "commands_executed": ["synthetic"],
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
        "evidence_manifest_ref": _object_ref(
            obj_id="evidence.q_snapshot",
            storage_ref=qsnap_rel,
            file_bytes=qsnap_bytes,
        ),
        "evaluated_at": "1970-01-01T00:00:00Z",
        "evaluator": "synthetic",
    }
    _write_json(fake_root, q_rel, qv_obj)
    qv_bytes = (fake_root / Path(*q_rel.split("/"))).read_bytes()

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
        "commands_executed": ["synthetic"],
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
        "evidence_manifest_ref": _object_ref(
            obj_id="evidence.r_snapshot",
            storage_ref=rsnap_rel,
            file_bytes=rsnap_bytes,
        ),
        "evaluated_at": "1970-01-01T00:00:00Z",
        "evaluator": "synthetic",
    }
    _write_json(fake_root, r_rel, rv_obj)

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
                prompt_block_hashes_rel,
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
            path = fake_root / Path(*rel.split("/"))
            if path.is_dir():
                _rmtree_retry(path)
            elif path.exists():
                path.unlink()

    outs1 = {
        "out_final_rel": "out/EvidenceManifest.final.json",
        "out_docs_rel": "out/docs.md",
        "out_bundle_dir_rel": "out/bundle",
        "out_root_sha_rel": "out/bundle_root.sha256",
    }

    cp1 = _run_c3("public", **outs1)
    assert cp1.returncode == 0, (cp1.returncode, cp1.stdout, cp1.stderr)

    prompt_block_hashes_path = fake_root / Path(*prompt_block_hashes_rel.split("/"))
    selected_ids = list(prompt_block_hashes.keys())
    assert selected_ids
    selected_first = selected_ids[0]

    prompt_block_hashes_missing = dict(prompt_block_hashes)
    prompt_block_hashes_missing.pop(selected_first)
    prompt_block_hashes_path.write_text(
        json.dumps(prompt_block_hashes_missing, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
    )
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

    prompt_block_hashes_mismatch = dict(prompt_block_hashes)
    prompt_block_hashes_mismatch[selected_first] = "f" * 64
    prompt_block_hashes_path.write_text(
        json.dumps(prompt_block_hashes_mismatch, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
    )
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

    prompt_block_hashes_extra = dict(prompt_block_hashes)
    prompt_block_hashes_extra["PB-999"] = "0" * 64
    prompt_block_hashes_path.write_text(
        json.dumps(prompt_block_hashes_extra, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
    )
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

    prompt_block_hashes_path.write_text(
        json.dumps(prompt_block_hashes, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
    )

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

    cp1_rebaseline = _run_c3("public", **outs1)
    assert cp1_rebaseline.returncode == 0, (
        cp1_rebaseline.returncode,
        cp1_rebaseline.stdout,
        cp1_rebaseline.stderr,
    )

    bundle_dir1 = fake_root / Path(*outs1["out_bundle_dir_rel"].split("/"))
    manifest_bytes_1 = (bundle_dir1 / "docs_bundle_manifest.json").read_bytes()
    root_sha_1 = (fake_root / Path(*outs1["out_root_sha_rel"].split("/"))).read_text(
        encoding="utf-8",
        errors="strict",
    )

    public_manifest = json.loads(manifest_bytes_1.decode("utf-8"))
    public_inputs = public_manifest.get("inputs")
    assert isinstance(public_inputs, list)
    assert all(not str(path).startswith("docs/research/") for path in public_inputs)
    assert not (bundle_dir1 / "docs" / "research").exists()

    r_snapshot_loaded = _read_json(fake_root / Path(*rsnap_rel.split("/")))
    final_loaded = _read_json(fake_root / Path(*outs1["out_final_rel"].split("/")))
    r_snapshot_artifacts = r_snapshot_loaded.get("artifacts")
    final_artifacts = final_loaded.get("artifacts")
    assert isinstance(r_snapshot_artifacts, list) and isinstance(final_artifacts, list)
    assert len(final_artifacts) == len(r_snapshot_artifacts) + 1
    new_artifacts = [row for row in final_artifacts if isinstance(row, dict) and row.get("id") == "docs.compilation_log"]
    assert len(new_artifacts) == 1
    assert new_artifacts[0].get("kind") == "docs_compilation_log"
    assert new_artifacts[0].get("storage_ref") == "docs/docs_compilation_log.json"
    assert new_artifacts[0].get("produced_by") == "C3"

    log_obj = _read_json(fake_root / Path(*out_log_rel.split("/")))
    outputs = log_obj.get("outputs")
    assert isinstance(outputs, dict)
    for key in [
        "bundle_sha256",
        "docs_bundle_manifest_sha256",
        "bundle_root_sha256",
        "docs_markdown",
        "bundle_manifest",
        "bundle_toc",
        "bundle_root_sha_file",
        "bundle_dir",
    ]:
        assert key in outputs
    assert outputs["bundle_dir"] == outs1["out_bundle_dir_rel"]
    assert outputs["bundle_manifest"]["path"] == f"{outs1['out_bundle_dir_rel']}/docs_bundle_manifest.json"
    assert outputs["bundle_toc"]["path"] == f"{outs1['out_bundle_dir_rel']}/TOC.md"
    assert outputs["docs_markdown"]["path"] == outs1["out_docs_rel"]
    assert outputs["bundle_root_sha_file"]["path"] == outs1["out_root_sha_rel"]

    outs2 = outs1
    try:
        _clean_outputs()
    except (PermissionError, OSError):
        outs2 = _outs("out/run2")

    cp2 = _run_c3("public", **outs2)
    assert cp2.returncode == 0, (cp2.returncode, cp2.stdout, cp2.stderr)

    bundle_dir2 = fake_root / Path(*outs2["out_bundle_dir_rel"].split("/"))
    manifest_bytes_2 = (bundle_dir2 / "docs_bundle_manifest.json").read_bytes()
    root_sha_2 = (fake_root / Path(*outs2["out_root_sha_rel"].split("/"))).read_text(
        encoding="utf-8",
        errors="strict",
    )
    assert manifest_bytes_2 == manifest_bytes_1
    assert root_sha_2 == root_sha_1

    manifest_obj = json.loads(manifest_bytes_2.decode("utf-8"))
    bundle_sha = _compute_bundle_sha256(bundle_dir2)
    assert manifest_obj["bundle_sha256"] == bundle_sha

    (bundle_dir2 / "docs_bundle_manifest.json").write_text(
        json.dumps(manifest_obj, indent=4, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
    )
    bundle_sha_2 = _compute_bundle_sha256(bundle_dir2)
    assert bundle_sha_2 == bundle_sha
    manifest_sha_2 = _sha256_hex((bundle_dir2 / "docs_bundle_manifest.json").read_bytes())
    root_sha_2_calc = _compute_bundle_root_sha256(
        docs_bundle_manifest_sha256=manifest_sha_2,
        bundle_sha256=bundle_sha,
    )
    assert root_sha_2_calc.strip() != root_sha_1.strip()

    target = bundle_dir2 / "CANONICALS.md"
    target.write_text(
        target.read_text(encoding="utf-8", errors="strict") + "tamper\n",
        encoding="utf-8",
        errors="strict",
    )
    assert _compute_bundle_sha256(bundle_dir2) != bundle_sha

    outs3 = _outs("out/internal")
    cp3 = _run_c3("internal", **outs3)
    assert cp3.returncode == 0, (cp3.returncode, cp3.stdout, cp3.stderr)
    bundle_dir3 = fake_root / Path(*outs3["out_bundle_dir_rel"].split("/"))
    internal_manifest = _read_json(bundle_dir3 / "docs_bundle_manifest.json")
    internal_inputs = internal_manifest.get("inputs")
    internal_files = internal_manifest.get("files")
    assert isinstance(internal_inputs, list)
    assert isinstance(internal_files, list)
    research_inputs = sorted(str(path) for path in internal_inputs if str(path).startswith("docs/research/"))
    research_files = sorted(
        str(row.get("path"))
        for row in internal_files
        if isinstance(row, dict) and isinstance(row.get("path"), str) and str(row.get("path")).startswith("docs/research/")
    )
    assert research_inputs
    assert research_files
    for rel in research_files:
        assert (bundle_dir3 / Path(*rel.split("/"))).is_file()

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
        "commands_executed": ["synthetic"],
        "envelope_attestation": None,
    }
    _write_json(fake_root, rsnap_rel, rsnap_obj_missing_q)
    rsnap_bytes_2 = (fake_root / Path(*rsnap_rel.split("/"))).read_bytes()
    rv_obj_missing_q = dict(rv_obj)
    rv_obj_missing_q["evidence_manifest_ref"] = _object_ref(
        obj_id="evidence.r_snapshot",
        storage_ref=rsnap_rel,
        file_bytes=rsnap_bytes_2,
    )
    _write_json(fake_root, r_rel, rv_obj_missing_q)

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
