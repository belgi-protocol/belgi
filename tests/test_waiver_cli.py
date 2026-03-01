from __future__ import annotations

import json
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
from belgi.core.run_orchestrator import render_default_intent_spec
from belgi.core.schema import validate_schema
from belgi.protocol.pack import get_builtin_protocol_context


def _run_git(repo: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    cp = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    assert cp.returncode == 0, f"git {' '.join(args)} failed: {cp.stderr or cp.stdout}"
    return cp


def _init_git_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    _run_git(path, ["init"])
    _run_git(path, ["config", "user.email", "test@example.com"])
    _run_git(path, ["config", "user.name", "BELGI Test"])
    (path / "README.md").write_text("# test\n", encoding="utf-8", errors="strict", newline="\n")
    _run_git(path, ["add", "README.md"])
    _run_git(path, ["commit", "-m", "init"])
    return path


def _head_sha(repo: Path) -> str:
    cp = _run_git(repo, ["rev-parse", "HEAD"])
    sha = cp.stdout.strip().lower()
    assert len(sha) == 40
    return sha


def test_waiver_new_default_output_is_schema_valid(tmp_path: Path) -> None:
    repo = _init_git_repo(tmp_path / "repo")
    assert belgi_main(["init", "--repo", str(repo)]) == 0
    run_id = "run-waiver-001"
    assert belgi_main(["run", "new", "--repo", str(repo), "--run-id", run_id]) == 0

    rc = belgi_main(
        [
            "waiver",
            "new",
            "--repo",
            str(repo),
            "--run-id",
            run_id,
            "--gate",
            "R",
            "--rule-id",
            "ADV-EXEC-001",
            "--waiver-id",
            "waiver-001",
            "--expires-at",
            "2100-01-01T00:00:00Z",
        ]
    )
    assert rc == 0

    waiver_path = repo / ".belgi" / "runs" / run_id / "inputs" / "waivers" / "waiver-001.json"
    assert waiver_path.is_file()
    waiver_obj = json.loads(waiver_path.read_text(encoding="utf-8", errors="strict"))
    schema_obj = get_builtin_protocol_context().read_json("schemas/Waiver.schema.json")
    errors = validate_schema(waiver_obj, schema_obj, root_schema=schema_obj, path="waiver")
    assert errors == []


def test_waiver_apply_writes_deterministic_run_refs_and_is_consumed_by_run(tmp_path: Path, capsys: object) -> None:
    repo = _init_git_repo(tmp_path / "repo")
    assert belgi_main(["init", "--repo", str(repo)]) == 0
    run_id = "run-waiver-apply-001"
    assert belgi_main(["run", "new", "--repo", str(repo), "--run-id", run_id]) == 0
    _ = capsys.readouterr()

    waiver_rel = f".belgi/runs/{run_id}/inputs/waivers/waiver-001.json"
    rc_new = belgi_main(
        [
            "waiver",
            "new",
            "--repo",
            str(repo),
            "--run-id",
            run_id,
            "--gate",
            "R",
            "--rule-id",
            "ADV-EXEC-001",
            "--waiver-id",
            "waiver-001",
            "--expires-at",
            "2100-01-01T00:00:00Z",
        ]
    )
    assert rc_new == 0
    _ = capsys.readouterr()

    rc_apply_1 = belgi_main(["waiver", "apply", "--repo", str(repo), "--run-id", run_id, "--waiver", waiver_rel])
    assert rc_apply_1 == 0
    _ = capsys.readouterr()

    rc_apply_2 = belgi_main(["waiver", "apply", "--repo", str(repo), "--run-id", run_id, "--waiver", waiver_rel])
    assert rc_apply_2 == 0
    _ = capsys.readouterr()

    applied_refs_path = repo / ".belgi" / "runs" / run_id / "inputs" / "waivers_applied.json"
    applied_obj = json.loads(applied_refs_path.read_text(encoding="utf-8", errors="strict"))
    assert applied_obj == {
        "schema_version": "1.0.0",
        "run_id": run_id,
        "waivers": [waiver_rel],
    }

    intent_path = repo / ".belgi" / "runs" / run_id / "inputs" / "intent" / "IntentSpec.core.md"
    intent_path.write_bytes(render_default_intent_spec(tier_id="tier-1"))

    base_sha = _head_sha(repo)
    rc_run = belgi_main(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-1",
            "--intent-spec",
            f".belgi/runs/{run_id}/inputs/intent/IntentSpec.core.md",
            "--base-revision",
            base_sha,
        ]
    )
    assert rc_run == 10
    captured = capsys.readouterr()
    machine = json.loads(captured.out.splitlines()[0])
    assert machine["verdict"] == "NO-GO"
    run_key = str(machine["run_key"])
    attempt_id = str(machine["attempt_id"])
    locked_spec_path = repo / ".belgi" / "runs" / run_key / attempt_id / "repo" / "out" / "LockedSpec.json"
    locked_obj = json.loads(locked_spec_path.read_text(encoding="utf-8", errors="strict"))
    assert locked_obj.get("waivers_applied") == ["out/inputs/waivers_applied/waiver-001.json"]
