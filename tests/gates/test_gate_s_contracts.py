from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers import builders
from tests.gates.gate_test_support import (
    REPO_ROOT,
    _read_json,
    _remove_locked_spec_protocol_pack,
    _run_module,
    _setup_fake_repo_with_pack,
    _tamper_locked_spec_pack_id,
)

pytestmark = pytest.mark.repo_local


def test_gate_s_protocol_identity_mismatch_pack_id(tmp_path: Path) -> None:
    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)

    paths = builders.build_s_repo(tmp_path, rel_root="gate_s/s_pass_tier1_unsigned", run_id="s-pass-tier1")
    locked_path = tmp_path / paths["locked"]
    _tamper_locked_spec_pack_id(locked_path, "0" * 64)

    cp = _run_module(
        "chain.gate_s_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            paths["locked"],
            "--evidence-manifest",
            paths["evidence"],
            "--seal-manifest",
            paths["seal"],
            "--out",
            "out/GateVerdict.json",
        ],
        cwd=REPO_ROOT,
    )

    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
    gate_verdict = _read_json(tmp_path / "out" / "GateVerdict.json")
    assert gate_verdict.get("failure_category") == "FS-PROTOCOL-IDENTITY-MISMATCH", gate_verdict


def test_gate_s_missing_protocol_pack_field(tmp_path: Path) -> None:
    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)

    paths = builders.build_s_repo(tmp_path, rel_root="gate_s/s_pass_tier1_unsigned", run_id="s-pass-tier1")
    locked_path = tmp_path / paths["locked"]
    _remove_locked_spec_protocol_pack(locked_path)

    cp = _run_module(
        "chain.gate_s_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            paths["locked"],
            "--evidence-manifest",
            paths["evidence"],
            "--seal-manifest",
            paths["seal"],
            "--out",
            "out/GateVerdict.json",
        ],
        cwd=REPO_ROOT,
    )

    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
    gate_verdict = _read_json(tmp_path / "out" / "GateVerdict.json")
    assert gate_verdict.get("failure_category") == "FS-PROTOCOL-IDENTITY-MISMATCH", gate_verdict
