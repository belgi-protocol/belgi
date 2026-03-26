from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.helpers import subprocess_cli
from tests.helpers.repo_imports import BelgiCliSurface, import_fresh_belgi_cli_surface

clear_base_revision_env = subprocess_cli.clear_base_revision_env
_fresh_repo_clone = subprocess_cli._fresh_repo_clone
_commit_file = subprocess_cli._commit_file
_write_tolerances_object = subprocess_cli._write_tolerances_object
_write_toolchain_set_object = subprocess_cli._write_toolchain_set_object
_write_local_json_object = subprocess_cli._write_local_json_object
_run_git = subprocess_cli._run_git
_git_rev_parse = subprocess_cli._git_rev_parse
_unset_upstream_if_present = subprocess_cli._unset_upstream_if_present
_extract_run_human_block = subprocess_cli._extract_run_human_block
_open_target_labels = subprocess_cli._open_target_labels
_remove_tests_tree_and_commit = subprocess_cli._remove_tests_tree_and_commit
_write_applied_waiver = subprocess_cli._write_applied_waiver
_ed25519_pubkey_hex = subprocess_cli._ed25519_pubkey_hex
_rewrite_shared_run_intent_for_empty_doc_impact = subprocess_cli._rewrite_shared_run_intent_for_empty_doc_impact
_write_operator_anchors = subprocess_cli._write_operator_anchors
_write_run_evidence_inputs = subprocess_cli._write_run_evidence_inputs
_refresh_summary_artifact_hashes = subprocess_cli._refresh_summary_artifact_hashes
_assert_no_persisted_signing_material = subprocess_cli._assert_no_persisted_signing_material
_FIXED_TIER2_SHARED_PATH_ANCHOR_UTC = "2000-01-01T00:00:00Z"


def fresh_belgi_cli_surface() -> BelgiCliSurface:
    return import_fresh_belgi_cli_surface()


def _run_tier1_and_get_attempt(
    repo: Path,
    capsys: object,
    *,
    cli_surface: BelgiCliSurface,
) -> tuple[dict[str, object], Path]:
    belgi_main = cli_surface.main

    rc_init = belgi_main(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()

    _unset_upstream_if_present(repo)
    head_sha = _git_rev_parse(repo, "HEAD")
    rc_run = belgi_main(["run", "--repo", str(repo), "--tier", "tier-1", "--base-revision", head_sha])
    assert rc_run == 0
    captured = capsys.readouterr()

    machine = json.loads(captured.out.splitlines()[0])
    run_key = str(machine["run_key"])
    attempt_id = str(machine["attempt_id"])
    attempt_dir = repo / ".belgi" / "store" / "runs" / run_key / attempt_id
    assert attempt_dir.is_dir()
    return machine, attempt_dir


def _prepare_shared_run_intent(
    repo: Path,
    *,
    capsys: object,
    run_id: str,
    tier_id: str,
    cli_surface: BelgiCliSurface,
) -> Path:
    belgi_main = cli_surface.main

    rc_new = belgi_main(["run", "new", "--repo", str(repo), "--run-id", run_id])
    assert rc_new == 0
    _ = capsys.readouterr()
    return _rewrite_shared_run_intent_for_empty_doc_impact(
        repo,
        run_id=run_id,
        note="No documentation updates are required for this deterministic shared-path test run.",
        tier_id=tier_id,
    )


def _pin_shared_path_anchor_time(monkeypatch: pytest.MonkeyPatch, *, cli_surface: BelgiCliSurface) -> None:
    run_orchestrator = cli_surface.run_orchestrator

    # Precomputed seal signatures bind the exact unsigned seal anchor bytes for the target run.
    # Pin the run-time waiver anchor so the private-key and precomputed-signature entry paths
    # exercise the same shared Tier-2 payload in this regression harness.
    monkeypatch.setattr(
        run_orchestrator,
        "utc_timestamp_iso_z",
        lambda *args, **kwargs: _FIXED_TIER2_SHARED_PATH_ANCHOR_UTC,
    )
