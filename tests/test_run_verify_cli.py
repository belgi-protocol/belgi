from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
for _k in list(sys.modules.keys()):
    if _k == "belgi" or _k.startswith("belgi."):
        del sys.modules[_k]

from belgi.cli import main as belgi_main


def _list_dirs(path: Path) -> list[Path]:
    return sorted([p for p in path.iterdir() if p.is_dir()], key=lambda p: p.name)


def _fresh_repo_clone(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    cp = subprocess.run(
        ["git", "clone", "--quiet", "--shared", str(REPO_ROOT), str(repo)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert cp.returncode == 0, cp.stderr
    return repo


def test_run_tier_uses_stable_run_key_and_unique_attempt_id(tmp_path: Path) -> None:
    repo = _fresh_repo_clone(tmp_path)

    rc_init = belgi_main(["init", "--repo", str(repo)])
    assert rc_init == 0

    rc1 = belgi_main(["run", "--repo", str(repo), "--tier", "tier-0"])
    assert rc1 == 0

    runs_root = repo / ".belgi" / "runs"
    run_dirs = _list_dirs(runs_root)
    assert len(run_dirs) == 1
    run_key_dir = run_dirs[0]
    assert len(run_key_dir.name) == 64

    attempts_after_first = _list_dirs(run_key_dir)
    assert [p.name for p in attempts_after_first] == ["attempt-0001"]
    first_attempt = attempts_after_first[0]

    summary1 = json.loads((first_attempt / "run.summary.json").read_text(encoding="utf-8", errors="strict"))
    assert summary1["run_key"] == run_key_dir.name
    assert summary1["attempt_id"] == "attempt-0001"
    assert summary1["run_key_preimage"]["normalized_inputs"]["intent_spec_source"] == "(auto)"
    evidence1 = json.loads(
        (first_attempt / "repo" / "out" / "EvidenceManifest.json").read_text(encoding="utf-8", errors="strict")
    )
    assert evidence1["run_id"] == run_key_dir.name
    seal = json.loads((first_attempt / "repo" / "out" / "SealManifest.json").read_text(encoding="utf-8", errors="strict"))
    assert seal["run_id"] == run_key_dir.name
    prompt_hashes = json.loads(
        (first_attempt / "repo" / "out" / "prompt_block_hashes.json").read_text(encoding="utf-8", errors="strict")
    )
    assert prompt_hashes
    assert all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v) for v in prompt_hashes.values())
    assert all(v != "0" * 64 for v in prompt_hashes.values())

    rc_verify_1 = belgi_main(["verify", "--repo", str(repo)])
    assert rc_verify_1 == 0

    rc2 = belgi_main(["run", "--repo", str(repo), "--tier", "tier-0"])
    assert rc2 == 0

    run_dirs_after_second = _list_dirs(runs_root)
    assert [p.name for p in run_dirs_after_second] == [run_key_dir.name]
    attempts_after_second = _list_dirs(run_key_dir)
    assert [p.name for p in attempts_after_second] == ["attempt-0001", "attempt-0002"]

    summary2 = json.loads((attempts_after_second[1] / "run.summary.json").read_text(encoding="utf-8", errors="strict"))
    assert summary2["run_key"] == run_key_dir.name
    assert summary2["attempt_id"] == "attempt-0002"

    rc_verify_2 = belgi_main(["verify", "--repo", str(repo)])
    assert rc_verify_2 == 0


def test_init_custom_workspace_updates_gitignore_and_run_path(tmp_path: Path) -> None:
    repo = _fresh_repo_clone(tmp_path)

    rc_init = belgi_main(["init", "--repo", str(repo), "--workspace", ".belgi_alt"])
    assert rc_init == 0

    gitignore = (repo / ".gitignore").read_text(encoding="utf-8", errors="strict")
    assert ".belgi/" in gitignore
    assert ".belgi_alt/" in gitignore

    rc_run = belgi_main(["run", "--repo", str(repo), "--tier", "tier-1", "--workspace", ".belgi_alt"])
    assert rc_run == 0

    runs_root = repo / ".belgi_alt" / "runs"
    run_dirs = _list_dirs(runs_root)
    assert len(run_dirs) == 1
    attempts = _list_dirs(run_dirs[0])
    assert [p.name for p in attempts] == ["attempt-0001"]

    rc_verify = belgi_main(["verify", "--repo", str(repo), "--workspace", ".belgi_alt"])
    assert rc_verify == 0


def test_verify_fails_closed_on_mutated_evidence_manifest(tmp_path: Path) -> None:
    repo = _fresh_repo_clone(tmp_path)

    rc_init = belgi_main(["init", "--repo", str(repo)])
    assert rc_init == 0
    rc_run = belgi_main(["run", "--repo", str(repo), "--tier", "tier-0"])
    assert rc_run == 0

    runs_root = repo / ".belgi" / "runs"
    run_key_dir = _list_dirs(runs_root)[0]
    attempt_dir = _list_dirs(run_key_dir)[0]
    manifest_path = attempt_dir / "repo" / "out" / "EvidenceManifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8", errors="strict"))
    manifest["run_id"] = "tampered"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    rc_verify = belgi_main(["verify", "--repo", str(repo)])
    assert rc_verify == 1


def test_run_fails_closed_when_repo_head_sha_is_unavailable(tmp_path: Path) -> None:
    rc_init = belgi_main(["init", "--repo", str(tmp_path)])
    assert rc_init == 0

    rc_run = belgi_main(["run", "--repo", str(tmp_path), "--tier", "tier-0"])
    assert rc_run == 1
