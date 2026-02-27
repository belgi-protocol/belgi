from __future__ import annotations

import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
for _k in list(sys.modules.keys()):
    if _k == "belgi" or _k.startswith("belgi."):
        del sys.modules[_k]

from belgi.cli import main as belgi_main


def _assert_machine_user_error(stdout_text: str) -> dict[str, object]:
    lines = stdout_text.splitlines()
    assert lines, "expected machine-result line on stdout"
    obj = json.loads(lines[0])
    assert obj["ok"] is False
    assert obj["verdict"] == "NO-GO"
    assert obj["tier_id"] is None
    assert obj["run_key"] is None
    assert obj["attempt_id"] is None
    assert isinstance(obj["primary_reason"], str) and obj["primary_reason"]
    return obj


def test_unknown_subcommand_returns_user_error_and_machine_json(capsys: object) -> None:
    rc = belgi_main(["unknown-subcommand"])
    captured = capsys.readouterr()

    assert rc == 20
    machine = _assert_machine_user_error(captured.out)
    assert "invalid choice" in str(machine["primary_reason"])


def test_missing_required_args_returns_user_error_and_machine_json(capsys: object) -> None:
    rc = belgi_main(["manifest", "add", "--repo", "."])
    captured = capsys.readouterr()

    assert rc == 20
    machine = _assert_machine_user_error(captured.out)
    assert "required" in str(machine["primary_reason"]).lower()


def test_legacy_subcommand_rc_maps_to_cli_user_error() -> None:
    rc = belgi_main(["pack", "verify", "--in", "missing-pack-dir"])
    assert rc == 20
