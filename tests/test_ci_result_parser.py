from __future__ import annotations

import json
from pathlib import Path

import pytest

from belgi.ci_result import ensure_belgi_result_line, parse_belgi_result_file


def test_parse_belgi_result_with_noise_lines(tmp_path: Path) -> None:
    log_path = tmp_path / "run.stdout.log"
    log_path.write_text(
        "noise line\n"
        "another noise line\n"
        'BELGI_RESULT {"ok":true,"verdict":"GO","tier_id":"tier-1","run_key":"abc","attempt_id":"attempt-0001","primary_reason":""}\n',
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    parsed = parse_belgi_result_file(log_path)
    assert parsed["ok"] is True
    assert parsed["verdict"] == "GO"
    assert parsed["run_key"] == "abc"
    assert parsed["attempt_id"] == "attempt-0001"


def test_parse_belgi_result_fails_when_marker_missing(tmp_path: Path) -> None:
    log_path = tmp_path / "run.stdout.log"
    log_path.write_text(
        '{"ok":true,"verdict":"GO","tier_id":"tier-1","run_key":"abc","attempt_id":"attempt-0001","primary_reason":""}\n',
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    with pytest.raises(ValueError, match="missing BELGI_RESULT line in"):
        parse_belgi_result_file(log_path)


def test_ensure_belgi_result_line_appends_marker_from_json_line(tmp_path: Path) -> None:
    log_path = tmp_path / "run.stdout.log"
    machine = {
        "ok": True,
        "verdict": "GO",
        "tier_id": "tier-1",
        "run_key": "abc",
        "attempt_id": "attempt-0001",
        "primary_reason": "",
    }
    log_path.write_text(
        "prefix noise\n" + json.dumps(machine, separators=(",", ":"), sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    ensured = ensure_belgi_result_line(log_path)
    assert ensured["run_key"] == "abc"
    assert ensured["attempt_id"] == "attempt-0001"

    parsed = parse_belgi_result_file(log_path)
    assert parsed["run_key"] == "abc"
    assert parsed["attempt_id"] == "attempt-0001"


def test_ensure_belgi_result_line_noop_when_marker_exists(tmp_path: Path) -> None:
    log_path = tmp_path / "run.stdout.log"
    log_path.write_text(
        'BELGI_RESULT {"ok":true,"verdict":"GO","tier_id":"tier-1","run_key":"abc","attempt_id":"attempt-0001","primary_reason":""}\n',
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    before = log_path.read_text(encoding="utf-8", errors="strict")

    ensured = ensure_belgi_result_line(log_path)
    after = log_path.read_text(encoding="utf-8", errors="strict")

    assert ensured["run_key"] == "abc"
    assert ensured["attempt_id"] == "attempt-0001"
    assert before == after


def test_ensure_belgi_result_line_rejects_incomplete_json_fallback(tmp_path: Path) -> None:
    log_path = tmp_path / "run.stdout.log"
    log_path.write_text(
        '{"ok":true,"run_key":"abc","attempt_id":"attempt-0001"}\n',
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    with pytest.raises(ValueError, match="missing BELGI_RESULT line in"):
        ensure_belgi_result_line(log_path)


def test_ensure_belgi_result_line_selects_valid_machine_json(tmp_path: Path) -> None:
    log_path = tmp_path / "run.stdout.log"
    log_path.write_text(
        '{"run_key":"bad","attempt_id":"attempt-0001"}\n'
        '{"ok":true,"verdict":"GO","tier_id":"tier-1","run_key":"good","attempt_id":"attempt-0002","primary_reason":""}\n',
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    ensured = ensure_belgi_result_line(log_path)
    assert ensured["run_key"] == "good"
    assert ensured["attempt_id"] == "attempt-0002"

    parsed = parse_belgi_result_file(log_path)
    assert parsed["run_key"] == "good"
    assert parsed["attempt_id"] == "attempt-0002"
