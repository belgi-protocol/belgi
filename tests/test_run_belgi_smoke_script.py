from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path, PureWindowsPath


def _load_module():
    repo_root = Path(__file__).resolve().parents[1]
    script_path = repo_root / ".github" / "scripts" / "run_belgi_smoke.py"
    spec = importlib.util.spec_from_file_location("run_belgi_smoke_script", script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load run_belgi_smoke.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _cp(cmd: list[str], rc: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=cmd, returncode=rc, stdout=stdout, stderr=stderr)


def test_main_sets_attempt_dir_to_store_layout(tmp_path: Path, monkeypatch, capsys) -> None:
    mod = _load_module()
    repo = tmp_path / "repo"
    repo.mkdir(parents=True, exist_ok=True)

    run_key = "rk-001"
    attempt_id = "attempt-0001"

    def fake_run(cmd: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
        if cmd[:3] == ["git", "rev-parse", "--verify"]:
            return _cp(cmd, 0, "0" * 40 + "\n")
        if cmd[:2] == ["belgi", "init"]:
            return _cp(cmd, 0, "")
        if cmd[:2] == ["belgi", "run"]:
            attempt_dir = cwd / ".belgi" / "store" / "runs" / run_key / attempt_id
            (attempt_dir / "repo" / "out").mkdir(parents=True, exist_ok=True)
            (attempt_dir / "run.summary.json").write_text("{}\n", encoding="utf-8", errors="strict")
            first = json.dumps(
                {
                    "ok": True,
                    "verdict": "GO",
                    "run_key": run_key,
                    "attempt_id": attempt_id,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            return _cp(cmd, 0, first + "\nextra human line\n")
        if cmd[:2] == ["belgi", "verify"]:
            first = json.dumps(
                {
                    "ok": True,
                    "verdict": "GO",
                    "run_key": run_key,
                    "attempt_id": attempt_id,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            return _cp(cmd, 0, first + "\n")
        raise AssertionError(f"unexpected command: {cmd}")

    monkeypatch.setattr(mod.shutil, "which", lambda _: "belgi")
    monkeypatch.setattr(mod, "_run", fake_run)

    rc = mod.main(["--repo", str(repo), "--tier", "tier-1"])
    assert rc == 0

    out = capsys.readouterr().out.strip().splitlines()
    assert out
    payload = json.loads(out[-1])
    assert payload["attempt_dir"] == f".belgi/store/runs/{run_key}/{attempt_id}"
    assert "\\" not in payload["attempt_dir"]
    assert ".belgi/runs/" not in payload["attempt_dir"]


def test_main_fails_closed_when_store_attempt_dir_missing(tmp_path: Path, monkeypatch, capsys) -> None:
    mod = _load_module()
    repo = tmp_path / "repo"
    repo.mkdir(parents=True, exist_ok=True)

    run_key = "rk-002"
    attempt_id = "attempt-0002"

    def fake_run(cmd: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
        if cmd[:3] == ["git", "rev-parse", "--verify"]:
            return _cp(cmd, 0, "1" * 40 + "\n")
        if cmd[:2] == ["belgi", "init"]:
            return _cp(cmd, 0, "")
        if cmd[:2] == ["belgi", "run"]:
            first = json.dumps(
                {
                    "ok": True,
                    "verdict": "GO",
                    "run_key": run_key,
                    "attempt_id": attempt_id,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            return _cp(cmd, 0, first + "\nnoise\n")
        raise AssertionError(f"unexpected command: {cmd}")

    monkeypatch.setattr(mod.shutil, "which", lambda _: "belgi")
    monkeypatch.setattr(mod, "_run", fake_run)

    rc = mod.main(["--repo", str(repo), "--tier", "tier-1"])
    assert rc == 1

    err = capsys.readouterr().err
    assert "missing attempt directory under .belgi/store/runs" in err
    assert run_key in err
    assert attempt_id in err


def test_first_line_machine_json_reads_first_line_only() -> None:
    mod = _load_module()
    first_line = json.dumps(
        {"ok": True, "verdict": "GO", "run_key": "rk", "attempt_id": "a"},
        sort_keys=True,
        separators=(",", ":"),
    )
    parsed = mod._first_line_machine_json(first_line + "\nnot-json-line\n", label="belgi run")
    assert parsed["run_key"] == "rk"
    assert parsed["attempt_id"] == "a"


def test_append_github_output_normalizes_forward_slashes(tmp_path: Path, monkeypatch) -> None:
    mod = _load_module()
    out_file = tmp_path / "github_output.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))

    mod._append_github_output(
        run_key="rk",
        attempt_id="attempt-0003",
        attempt_dir=PureWindowsPath(r".belgi\store\runs\rk\attempt-0003"),
        run_log=PureWindowsPath(r".belgi\run.stdout.log"),
    )

    output_text = out_file.read_text(encoding="utf-8", errors="strict")
    assert "attempt_dir=.belgi/store/runs/rk/attempt-0003\n" in output_text
    assert "run_log=.belgi/run.stdout.log\n" in output_text
