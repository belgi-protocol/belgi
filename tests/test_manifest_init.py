from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
import uuid

import pytest

pytestmark = pytest.mark.repo_local

REPO_ROOT = Path(__file__).resolve().parents[1]


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


def test_manifest_init_produces_schema_valid_manifest(tmp_path: Path) -> None:
    (tmp_path / "inputs").mkdir(parents=True, exist_ok=True)
    target = tmp_path / "inputs" / "LockedSpec.json"
    target.write_text("{\"run_id\":\"run\"}\n", encoding="utf-8", errors="strict")

    cp = _run_module(
        "tools.belgi",
        [
            "manifest-init",
            "--repo",
            str(tmp_path),
            "--out",
            "EvidenceManifest.json",
            "--run-id",
            "run",
            "--add",
            "schema_validation:locked:inputs/LockedSpec.json:application/json:C1",
        ],
        cwd=REPO_ROOT,
    )
    assert cp.returncode == 0, (cp.returncode, cp.stdout, cp.stderr)

    em = _read_json(tmp_path / "EvidenceManifest.json")

    # Validate against pinned schema using BELGI's deterministic validator.
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))

    from belgi.core.schema import validate_schema

    schema = _read_json(REPO_ROOT / "schemas" / "EvidenceManifest.schema.json")
    errs = validate_schema(em, schema, root_schema=schema, path="EvidenceManifest")
    assert errs == []


def test_manifest_init_hash_changes_when_bytes_change(tmp_path: Path) -> None:
    (tmp_path / "inputs").mkdir(parents=True, exist_ok=True)
    target = tmp_path / "inputs" / "LockedSpec.json"
    target.write_text("one\n", encoding="utf-8", errors="strict")

    args = [
        "manifest-init",
        "--repo",
        str(tmp_path),
        "--out",
        "EvidenceManifest.json",
        "--run-id",
        "run",
        "--add",
        "schema_validation:locked:inputs/LockedSpec.json:text/plain:C1",
        "--overwrite",
    ]

    cp1 = _run_module("tools.belgi", args, cwd=REPO_ROOT)
    assert cp1.returncode == 0, (cp1.returncode, cp1.stdout, cp1.stderr)
    h1 = _read_json(tmp_path / "EvidenceManifest.json")["artifacts"][0]["hash"]

    target.write_text("two\n", encoding="utf-8", errors="strict")

    cp2 = _run_module("tools.belgi", args, cwd=REPO_ROOT)
    assert cp2.returncode == 0, (cp2.returncode, cp2.stdout, cp2.stderr)
    h2 = _read_json(tmp_path / "EvidenceManifest.json")["artifacts"][0]["hash"]

    assert h1 != h2


def test_manifest_init_fail_closed_on_missing_file(tmp_path: Path) -> None:
    cp = _run_module(
        "tools.belgi",
        [
            "manifest-init",
            "--repo",
            str(tmp_path),
            "--out",
            "EvidenceManifest.json",
            "--run-id",
            "run",
            "--add",
            "schema_validation:locked:inputs/missing.json:application/json:C1",
        ],
        cwd=REPO_ROOT,
    )
    assert cp.returncode != 0


def test_manifest_init_fail_closed_on_scope_escape(tmp_path: Path) -> None:
    (tmp_path / "x.txt").write_text("x\n", encoding="utf-8", errors="strict")

    cp = _run_module(
        "tools.belgi",
        [
            "manifest-init",
            "--repo",
            str(tmp_path),
            "--out",
            "EvidenceManifest.json",
            "--run-id",
            "run",
            "--add",
            "schema_validation:locked:../x.txt:text/plain:C1",
        ],
        cwd=REPO_ROOT,
    )
    assert cp.returncode != 0


def test_manifest_init_fail_closed_on_windows_drive_path(tmp_path: Path) -> None:
    cp = _run_module(
        "tools.belgi",
        [
            "manifest-init",
            "--repo",
            str(tmp_path),
            "--out",
            "EvidenceManifest.json",
            "--run-id",
            "run",
            "--add",
            "schema_validation:locked:C:/Windows/System32/drivers/etc/hosts:text/plain:C1",
        ],
        cwd=REPO_ROOT,
    )
    assert cp.returncode != 0


def test_manifest_init_fail_closed_on_schema_invalid_kind(tmp_path: Path) -> None:
    (tmp_path / "inputs").mkdir(parents=True, exist_ok=True)
    target = tmp_path / "inputs" / "LockedSpec.json"
    target.write_text("{}\n", encoding="utf-8", errors="strict")

    cp = _run_module(
        "tools.belgi",
        [
            "manifest-init",
            "--repo",
            str(tmp_path),
            "--out",
            "EvidenceManifest.json",
            "--run-id",
            "run",
            "--add",
            "not_a_kind:locked:inputs/LockedSpec.json:application/json:C1",
        ],
        cwd=REPO_ROOT,
    )
    assert cp.returncode != 0


def test_manifest_init_gate_q_integration_passes_fixture() -> None:
    uniq = uuid.uuid4().hex
    base_rel = f"temp/pytest_gate_contracts/manifest_init_q/{uniq}"
    work = REPO_ROOT / Path(*base_rel.split("/"))
    work.mkdir(parents=True, exist_ok=True)

    fixture_root = REPO_ROOT / "policy" / "fixtures" / "public" / "gate_q" / "q_pass_tier0"
    locked_rel = "policy/fixtures/public/gate_q/q_pass_tier0/LockedSpec.json"
    intent_rel = "policy/fixtures/public/gate_q/q_pass_tier0/IntentSpec.core.md"

    em_rel = f"{base_rel}/EvidenceManifest.init.json"
    out_rel = f"{base_rel}/GateVerdict.json"

    cp_init = _run_module(
        "tools.belgi",
        [
            "manifest-init",
            "--repo",
            ".",
            "--out",
            em_rel,
            "--locked-spec",
            locked_rel,
            "--add",
            f"command_log:command_log.fixture:{locked_rel}:application/octet-stream:C1",
            "--add",
            f"policy_report:policy_report.fixture:{locked_rel}:application/octet-stream:C1",
            "--add",
            f"schema_validation:schema_validation.fixture:{locked_rel}:application/octet-stream:C1",
            "--overwrite",
        ],
        cwd=REPO_ROOT,
    )
    assert cp_init.returncode == 0, (cp_init.returncode, cp_init.stdout, cp_init.stderr)

    cp_q = _run_module(
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
    assert cp_q.returncode == 0, (cp_q.returncode, cp_q.stdout, cp_q.stderr)
