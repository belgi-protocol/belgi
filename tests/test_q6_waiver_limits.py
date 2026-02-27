from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from belgi.protocol.pack import get_builtin_protocol_context

pytestmark = pytest.mark.repo_local

REPO_ROOT = Path(__file__).resolve().parents[1]


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", errors="strict")


def _make_waiver_doc(waiver_id: str) -> dict:
    return {
        "schema_version": "1.0.0",
        "waiver_id": waiver_id,
        "gate_id": "R",
        "rule_id": "ADV-EXEC-001",
        "scope": "path:tests/unit/test_loot.py",
        "justification": "Deterministic test waiver.",
        "mitigation": "Remove risky primitive in follow-up.",
        "approver": "human:test@example.com",
        "created_at": "1970-01-01T00:00:00Z",
        "expires_at": "2100-01-01T00:00:00Z",
        "audit_trail_ref": {"id": f"audit-{waiver_id}", "storage_ref": f"waivers/{waiver_id}.log"},
        "status": "active",
    }


def _prepare_gate_q_repo(tmp_path: Path, *, waiver_count: int) -> Path:
    fixture = REPO_ROOT / "policy" / "fixtures" / "public" / "gate_q" / "q_pass_tier0"
    repo = tmp_path / "repo"
    repo.mkdir(parents=True, exist_ok=True)

    (repo / "IntentSpec.core.md").write_text(
        (fixture / "IntentSpec.core.md").read_text(encoding="utf-8", errors="strict"),
        encoding="utf-8",
        errors="strict",
    )
    (repo / "EvidenceManifest.json").write_text(
        (fixture / "EvidenceManifest.json").read_text(encoding="utf-8", errors="strict"),
        encoding="utf-8",
        errors="strict",
    )

    locked = json.loads((fixture / "LockedSpec.json").read_text(encoding="utf-8", errors="strict"))
    proto = get_builtin_protocol_context()
    locked["protocol_pack"] = {
        "pack_id": proto.pack_id,
        "pack_name": proto.pack_name,
        "manifest_sha256": proto.manifest_sha256,
        "source": "builtin",
    }

    waivers: list[str] = []
    for idx in range(waiver_count):
        rel = f"waivers/waiver-{idx + 1:03d}.json"
        _write_json(repo / rel, _make_waiver_doc(f"waiver-{idx + 1:03d}"))
        waivers.append(rel)

    locked["waivers_applied"] = waivers
    _write_json(repo / "LockedSpec.json", locked)
    return repo


def _write_tiers_override(repo: Path, *, max_active_waivers: int) -> None:
    tiers = json.loads((REPO_ROOT / "tiers" / "tier-packs.json").read_text(encoding="utf-8", errors="strict"))
    tiers["tiers"]["tier-0"]["waiver_policy"]["max_active_waivers"] = max_active_waivers
    _write_json(repo / "tiers.override.json", tiers)


def _run_gate_q_with_override(repo: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["BELGI_DEV"] = "1"
    env.pop("CI", None)
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "chain.gate_q_verify",
            "--repo",
            str(repo),
            "--intent-spec",
            "IntentSpec.core.md",
            "--locked-spec",
            "LockedSpec.json",
            "--evidence-manifest",
            "EvidenceManifest.json",
            "--out",
            "GateVerdict.Q.json",
            "--tiers",
            "tiers.override.json",
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        env=env,
    )


def test_q6_fails_when_active_waivers_exceed_limit(tmp_path: Path) -> None:
    repo = _prepare_gate_q_repo(tmp_path, waiver_count=3)
    _write_tiers_override(repo, max_active_waivers=2)

    cp = _run_gate_q_with_override(repo)
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)

    verdict = json.loads((repo / "GateVerdict.Q.json").read_text(encoding="utf-8", errors="strict"))
    assert verdict["verdict"] == "NO-GO"
    failure = verdict["failures"][0]
    assert failure["id"] == "Q-Q6-001"
    assert failure["rule_id"] == "Q6"
    assert "Too many active waivers: 3 > max_active_waivers 2." in failure["message"]


def test_q6_passes_when_active_waivers_within_limit(tmp_path: Path) -> None:
    repo = _prepare_gate_q_repo(tmp_path, waiver_count=3)
    _write_tiers_override(repo, max_active_waivers=10)

    cp = _run_gate_q_with_override(repo)
    assert cp.returncode == 0, (cp.returncode, cp.stdout, cp.stderr)

    verdict = json.loads((repo / "GateVerdict.Q.json").read_text(encoding="utf-8", errors="strict"))
    assert verdict["verdict"] == "GO"
    assert verdict["failures"] == []
