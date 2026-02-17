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
    )

    with pytest.raises(ValueError, match="missing BELGI_RESULT line in"):
        parse_belgi_result_file(log_path)


def test_parse_belgi_result_uses_last_marker_when_multiple(tmp_path: Path) -> None:
    log_path = tmp_path / "run.stdout.log"
    log_path.write_text(
        'BELGI_RESULT {"ok":true,"verdict":"NO-GO","tier_id":"tier-1","run_key":"older","attempt_id":"attempt-0001","primary_reason":"older"}\n'
        'BELGI_RESULT {"ok":true,"verdict":"GO","tier_id":"tier-1","run_key":"newer","attempt_id":"attempt-0002","primary_reason":"newer"}\n',
        encoding="utf-8",
        errors="strict",
    )

    parsed = parse_belgi_result_file(log_path)
    assert parsed["run_key"] == "newer"
    assert parsed["attempt_id"] == "attempt-0002"
    assert parsed["primary_reason"] == "newer"


def test_parse_belgi_result_ignores_later_json_noise_after_last_marker(tmp_path: Path) -> None:
    log_path = tmp_path / "run.stdout.log"
    log_path.write_text(
        'BELGI_RESULT {"ok":false,"verdict":"NO-GO","tier_id":"tier-1","run_key":"older","attempt_id":"attempt-0001","primary_reason":"older"}\n'
        'BELGI_RESULT {"ok":true,"verdict":"GO","tier_id":"tier-1","run_key":"newer","attempt_id":"attempt-0002","primary_reason":"newer"}\n'
        '{"ok":true,"verdict":"GO","tier_id":"tier-1","run_key":"json-noise","attempt_id":"attempt-9999","primary_reason":"noise"}\n',
        encoding="utf-8",
        errors="strict",
    )

    parsed = parse_belgi_result_file(log_path)
    assert parsed["run_key"] == "newer"
    assert parsed["attempt_id"] == "attempt-0002"
    assert parsed["primary_reason"] == "newer"


def test_parse_belgi_result_accepts_whitespace_marker_with_crlf(tmp_path: Path) -> None:
    log_path = tmp_path / "run.stdout.log"
    log_path.write_bytes(
        b"noise line\r\n"
        b"  BELGI_RESULT {\"ok\":true,\"verdict\":\"GO\",\"tier_id\":\"tier-1\",\"run_key\":\"crlf\",\"attempt_id\":\"attempt-0003\",\"primary_reason\":\"\"}  \r\n"
    )

    parsed = parse_belgi_result_file(log_path)
    assert parsed["run_key"] == "crlf"
    assert parsed["attempt_id"] == "attempt-0003"


def test_parse_belgi_result_uses_last_marker_with_whitespace_variants(tmp_path: Path) -> None:
    log_path = tmp_path / "run.stdout.log"
    log_path.write_text(
        'BELGI_RESULT {"ok":true,"verdict":"NO-GO","tier_id":"tier-1","run_key":"older","attempt_id":"attempt-0001","primary_reason":"older"}\n'
        '  BELGI_RESULT {"ok":true,"verdict":"GO","tier_id":"tier-1","run_key":"newer","attempt_id":"attempt-0002","primary_reason":"newer"}  \n'
        '\tBELGI_RESULT {"ok":true,"verdict":"GO","tier_id":"tier-1","run_key":"newest","attempt_id":"attempt-0003","primary_reason":"newest"}\n',
        encoding="utf-8",
        errors="strict",
    )

    parsed = parse_belgi_result_file(log_path)
    assert parsed["run_key"] == "newest"
    assert parsed["attempt_id"] == "attempt-0003"
    assert parsed["primary_reason"] == "newest"


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
        '{"ok":true}\n',
        encoding="utf-8",
        errors="strict",
    )

    with pytest.raises(ValueError, match="missing BELGI_RESULT line in"):
        ensure_belgi_result_line(log_path)


def test_ensure_belgi_result_line_selects_latest_valid_machine_json(tmp_path: Path) -> None:
    log_path = tmp_path / "run.stdout.log"
    log_path.write_text(
        '{"ok":true,"verdict":"GO","tier_id":"tier-1","run_key":"older","attempt_id":"attempt-0001","primary_reason":""}\n'
        '{"ok":true,"verdict":"GO","tier_id":"tier-1","run_key":"newer","attempt_id":"attempt-0002","primary_reason":""}\n',
        encoding="utf-8",
        errors="strict",
    )

    ensured = ensure_belgi_result_line(log_path)
    assert ensured["run_key"] == "newer"
    assert ensured["attempt_id"] == "attempt-0002"

    parsed = parse_belgi_result_file(log_path)
    assert parsed["run_key"] == "newer"
    assert parsed["attempt_id"] == "attempt-0002"
