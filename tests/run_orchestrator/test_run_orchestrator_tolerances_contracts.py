from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.helpers.repo_imports import BelgiCliSurface, import_fresh_belgi_cli_surface

pytestmark = pytest.mark.repo_local


@pytest.fixture
def fresh_cli_surface() -> BelgiCliSurface:
    return import_fresh_belgi_cli_surface()


def test_orchestrate_generates_default_tolerances_object_for_c1(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fresh_cli_surface: BelgiCliSurface,
) -> None:
    run_orchestrator = fresh_cli_surface.run_orchestrator
    captured: dict[str, object] = {}

    class _StopAfterC1(RuntimeError):
        pass

    def _fake_clone_at_commit(*, source_repo: Path, dest_repo: Path, commit_sha: str) -> None:
        source_repo.mkdir(parents=True, exist_ok=True)
        dest_repo.mkdir(parents=True, exist_ok=True)

    def _fake_run_module_subprocess_expect_rc(
        module_name: str,
        argv: list[str],
        *,
        allowed: tuple[int, ...] = (0,),
        env: dict[str, str] | None = None,
    ) -> None:
        captured["module_name"] = module_name
        captured["argv"] = list(argv)
        raise _StopAfterC1("stop after c1")

    monkeypatch.setattr(run_orchestrator, "_command_log_mode_for_tier", lambda **_: "strings")
    monkeypatch.setattr(run_orchestrator, "_git_clone_at_commit", _fake_clone_at_commit)
    monkeypatch.setattr(run_orchestrator, "run_supplychain_scan", lambda **_: 0)
    monkeypatch.setattr(run_orchestrator, "ensure_chain_templates", lambda **_: None)
    monkeypatch.setattr(
        run_orchestrator,
        "_run_module_subprocess_expect_rc",
        _fake_run_module_subprocess_expect_rc,
    )

    with pytest.raises(_StopAfterC1, match="stop after c1"):
        run_orchestrator.orchestrate_chain_run(
            source_repo_root=tmp_path / "src",
            chain_repo_dir=tmp_path / "chain",
            run_key="run-key",
            tier_id="tier-0",
            base_revision="0123456789abcdef0123456789abcdef01234567",
            evaluated_revision="89abcdef012345670123456789abcdef01234567",
            revision_discovery_method="explicit",
            upstream_ref=None,
            intent_bytes=b"intent",
            protocol=fresh_cli_surface.get_builtin_protocol_context(),
        )

    assert captured["module_name"] == "chain.compiler_c1_intent"
    assert "--tolerances" in captured["argv"]
    tolerances_arg = captured["argv"][captured["argv"].index("--tolerances") + 1]
    assert tolerances_arg == "tier.tolerances=out/inputs/tolerances.json"

    tolerances_obj = json.loads(
        (tmp_path / "chain" / "out" / "inputs" / "tolerances.json").read_text(
            encoding="utf-8",
            errors="strict",
        )
    )
    assert tolerances_obj == {
        "schema_version": "1.0.0",
        "tier_id": "tier-0",
        "scope_budgets": {
            "max_touched_files": 50,
            "max_loc_delta": 5000,
        },
    }


def test_orchestrate_rejects_noncanonical_tolerances_ref_before_c1(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fresh_cli_surface: BelgiCliSurface,
) -> None:
    run_orchestrator = fresh_cli_surface.run_orchestrator

    def _fake_clone_at_commit(*, source_repo: Path, dest_repo: Path, commit_sha: str) -> None:
        source_repo.mkdir(parents=True, exist_ok=True)
        dest_repo.mkdir(parents=True, exist_ok=True)
        dest_path = dest_repo / "policy" / "tolerances" / "tier-0.json"
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        dest_path.write_text(
            json.dumps(
                {
                    "schema_version": "1.0.0",
                    "tier_id": "tier-0",
                    "scope_budgets": {
                        "max_touched_files": 50,
                        "max_loc_delta": 5000,
                    },
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
            errors="strict",
        )

    monkeypatch.setattr(run_orchestrator, "_command_log_mode_for_tier", lambda **_: "strings")
    monkeypatch.setattr(run_orchestrator, "_git_clone_at_commit", _fake_clone_at_commit)
    monkeypatch.setattr(
        run_orchestrator,
        "run_supplychain_scan",
        lambda **_: pytest.fail("run_supplychain_scan should not execute after noncanonical tolerances rejection"),
    )

    with pytest.raises(
        ValueError,
        match=r"declared tolerances ref must match the current run canonical path: \.belgi/runs/run-001/inputs/environment/tolerances\.json",
    ):
        run_orchestrator.orchestrate_chain_run(
            source_repo_root=tmp_path / "src",
            chain_repo_dir=tmp_path / "chain",
            run_key="run-key",
            tier_id="tier-0",
            base_revision="0123456789abcdef0123456789abcdef01234567",
            evaluated_revision="89abcdef012345670123456789abcdef01234567",
            revision_discovery_method="explicit",
            upstream_ref=None,
            intent_bytes=b"intent",
            protocol=fresh_cli_surface.get_builtin_protocol_context(),
            declared_tolerances_ref="tier.tolerances=policy/tolerances/tier-0.json",
            workspace_rel=".belgi",
            current_run_id="run-001",
        )


def test_orchestrate_stages_run_local_tolerances_ref_before_c1(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fresh_cli_surface: BelgiCliSurface,
) -> None:
    run_orchestrator = fresh_cli_surface.run_orchestrator
    captured: dict[str, object] = {}
    source_repo = tmp_path / "src"
    source_tolerances_path = source_repo / ".belgi" / "runs" / "run-001" / "inputs" / "environment" / "tolerances.json"
    source_tolerances_path.parent.mkdir(parents=True, exist_ok=True)
    source_tolerances_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "tier_id": "tier-0",
                "scope_budgets": {
                    "max_touched_files": 50,
                    "max_loc_delta": 5000,
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        errors="strict",
    )

    class _StopAfterC1(RuntimeError):
        pass

    def _fake_clone_at_commit(*, source_repo: Path, dest_repo: Path, commit_sha: str) -> None:
        source_repo.mkdir(parents=True, exist_ok=True)
        dest_repo.mkdir(parents=True, exist_ok=True)

    def _fake_run_module_subprocess_expect_rc(
        module_name: str,
        argv: list[str],
        *,
        allowed: tuple[int, ...] = (0,),
        env: dict[str, str] | None = None,
    ) -> None:
        captured["module_name"] = module_name
        captured["argv"] = list(argv)
        raise _StopAfterC1("stop after c1")

    monkeypatch.setattr(run_orchestrator, "_command_log_mode_for_tier", lambda **_: "strings")
    monkeypatch.setattr(run_orchestrator, "_git_clone_at_commit", _fake_clone_at_commit)
    monkeypatch.setattr(run_orchestrator, "run_supplychain_scan", lambda **_: 0)
    monkeypatch.setattr(run_orchestrator, "ensure_chain_templates", lambda **_: None)
    monkeypatch.setattr(
        run_orchestrator,
        "_run_module_subprocess_expect_rc",
        _fake_run_module_subprocess_expect_rc,
    )

    with pytest.raises(_StopAfterC1, match="stop after c1"):
        run_orchestrator.orchestrate_chain_run(
            source_repo_root=source_repo,
            chain_repo_dir=tmp_path / "chain",
            run_key="run-key",
            tier_id="tier-0",
            base_revision="0123456789abcdef0123456789abcdef01234567",
            evaluated_revision="89abcdef012345670123456789abcdef01234567",
            revision_discovery_method="explicit",
            upstream_ref=None,
            intent_bytes=b"intent",
            protocol=fresh_cli_surface.get_builtin_protocol_context(),
            declared_tolerances_ref="tier.tolerances=.belgi/runs/run-001/inputs/environment/tolerances.json",
            workspace_rel=".belgi",
            current_run_id="run-001",
        )

    assert captured["module_name"] == "chain.compiler_c1_intent"
    assert "--tolerances" in captured["argv"]
    tolerances_arg = captured["argv"][captured["argv"].index("--tolerances") + 1]
    assert tolerances_arg == "tier.tolerances=out/inputs/environment/tolerances.json"
    staged_obj = json.loads(
        (tmp_path / "chain" / "out" / "inputs" / "environment" / "tolerances.json").read_text(
            encoding="utf-8",
            errors="strict",
        )
    )
    assert staged_obj["tier_id"] == "tier-0"


def test_orchestrate_rejects_wrong_leaf_tolerances_ref_before_c1(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fresh_cli_surface: BelgiCliSurface,
) -> None:
    run_orchestrator = fresh_cli_surface.run_orchestrator
    source_repo = tmp_path / "src"
    source_tolerances_path = source_repo / ".belgi" / "runs" / "run-001" / "inputs" / "environment" / "tier-0.json"
    source_tolerances_path.parent.mkdir(parents=True, exist_ok=True)
    source_tolerances_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "tier_id": "tier-0",
                "scope_budgets": {
                    "max_touched_files": 50,
                    "max_loc_delta": 5000,
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        errors="strict",
    )

    def _fake_clone_at_commit(*, source_repo: Path, dest_repo: Path, commit_sha: str) -> None:
        source_repo.mkdir(parents=True, exist_ok=True)
        dest_repo.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(run_orchestrator, "_command_log_mode_for_tier", lambda **_: "strings")
    monkeypatch.setattr(run_orchestrator, "_git_clone_at_commit", _fake_clone_at_commit)
    monkeypatch.setattr(
        run_orchestrator,
        "run_supplychain_scan",
        lambda **_: pytest.fail("run_supplychain_scan should not execute after wrong-leaf tolerances rejection"),
    )

    with pytest.raises(
        ValueError,
        match=r"declared tolerances ref must match the current run canonical path: \.belgi/runs/run-001/inputs/environment/tolerances\.json",
    ):
        run_orchestrator.orchestrate_chain_run(
            source_repo_root=source_repo,
            chain_repo_dir=tmp_path / "chain",
            run_key="run-key",
            tier_id="tier-0",
            base_revision="0123456789abcdef0123456789abcdef01234567",
            evaluated_revision="89abcdef012345670123456789abcdef01234567",
            revision_discovery_method="explicit",
            upstream_ref=None,
            intent_bytes=b"intent",
            protocol=fresh_cli_surface.get_builtin_protocol_context(),
            declared_tolerances_ref="tier.tolerances=.belgi/runs/run-001/inputs/environment/tier-0.json",
            workspace_rel=".belgi",
            current_run_id="run-001",
        )
