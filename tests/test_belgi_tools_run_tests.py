from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_engine_smoke_does_not_require_pytest(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir(parents=True, exist_ok=True)
    out_rel = "out/tests.report.json"

    cp = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.belgi_tools",
            "run-tests",
            "--repo",
            str(repo),
            "--run-id",
            "run-test-001",
            "--out",
            out_rel,
            "--deterministic",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert cp.returncode == 0, cp.stderr
    combined = cp.stdout + cp.stderr
    combined_lower = combined.lower()
    assert "[belgi run-tests] mode=engine_smoke check:" in combined_lower
    assert " -m pytest" not in combined_lower

    report_path = repo / Path(*out_rel.split("/"))
    report = json.loads(report_path.read_text(encoding="utf-8", errors="strict"))
    assert report.get("mode") == "engine_smoke"
    assert report.get("status") == "pass"
    assert isinstance(report.get("exit_code"), int)
