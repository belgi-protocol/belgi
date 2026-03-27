from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.helpers.repo_imports import BelgiCliSurface, import_fresh_belgi_cli_surface

pytestmark = pytest.mark.repo_local


@pytest.fixture
def fresh_cli_surface() -> BelgiCliSurface:
    return import_fresh_belgi_cli_surface()


def test_orchestrate_passes_explicit_run_toolchain_refs_to_supplychain_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fresh_cli_surface: BelgiCliSurface,
) -> None:
    run_orchestrator = fresh_cli_surface.run_orchestrator
    observed_refs: dict[str, object] = {}

    class _StopAfterEnsure(RuntimeError):
        pass

    def _fake_clone_at_commit(*, source_repo: Path, dest_repo: Path, commit_sha: str) -> None:
        source_repo.mkdir(parents=True, exist_ok=True)
        dest_repo.mkdir(parents=True, exist_ok=True)
        source_path = source_repo / "toolchains" / "python.lock.json"
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_text("{\"python\":\"3.11.0\"}\n", encoding="utf-8", errors="strict")
        dest_path = dest_repo / "toolchains" / "python.lock.json"
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        dest_path.write_text("{\"python\":\"3.11.0\"}\n", encoding="utf-8", errors="strict")

    def _fake_supplychain_scan(
        *,
        repo: Path,
        base_revision: str,
        evaluated_revision: str,
        declared_toolchain_refs: list[str],
        out_path: Path,
        deterministic: bool,
        run_id: str = "unknown",
    ) -> int:
        observed_refs["declared_toolchain_refs"] = list(declared_toolchain_refs)
        return 0

    def _fake_ensure_chain_templates(*, chain_repo_root: Path) -> None:
        raise _StopAfterEnsure("stop after hydration")

    monkeypatch.setattr(run_orchestrator, "_command_log_mode_for_tier", lambda **_: "strings")
    monkeypatch.setattr(run_orchestrator, "_git_clone_at_commit", _fake_clone_at_commit)
    monkeypatch.setattr(run_orchestrator, "run_supplychain_scan", _fake_supplychain_scan)
    monkeypatch.setattr(run_orchestrator, "ensure_chain_templates", _fake_ensure_chain_templates)

    with pytest.raises(_StopAfterEnsure, match="stop after hydration"):
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
            declared_toolchain_refs=["deps.python=toolchains/python.lock.json"],
        )

    assert observed_refs["declared_toolchain_refs"] == [
        "toolchain.main=out/inputs/toolchain.json",
        "deps.python=toolchains/python.lock.json",
    ]


def test_orchestrate_rejects_noncanonical_toolchain_set_ref_before_c1(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fresh_cli_surface: BelgiCliSurface,
) -> None:
    run_orchestrator = fresh_cli_surface.run_orchestrator

    def _fake_clone_at_commit(*, source_repo: Path, dest_repo: Path, commit_sha: str) -> None:
        source_repo.mkdir(parents=True, exist_ok=True)
        dest_repo.mkdir(parents=True, exist_ok=True)
        toolchain_path = dest_repo / "toolchains" / "python.lock.json"
        toolchain_path.parent.mkdir(parents=True, exist_ok=True)
        toolchain_path.write_text("{\"python\":\"3.11.0\"}\n", encoding="utf-8", errors="strict")
        toolchain_set_path = dest_repo / "policy" / "environment" / "toolchain-set.json"
        toolchain_set_path.parent.mkdir(parents=True, exist_ok=True)
        toolchain_set_path.write_text(
            json.dumps(
                {
                    "schema_version": "1.0.0",
                    "toolchain_set_id": "env.toolchains",
                    "refs": [{"id": "deps.python", "path": "toolchains/python.lock.json"}],
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
        lambda **_: pytest.fail(
            "run_supplychain_scan should not execute after noncanonical ToolchainSet rejection"
        ),
    )

    with pytest.raises(
        ValueError,
        match=r"declared ToolchainSet ref must match the current run canonical path: \.belgi/runs/run-001/inputs/environment/toolchain-set\.json",
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
            declared_toolchain_set_ref="env.toolchains=policy/environment/toolchain-set.json",
            workspace_rel=".belgi",
            current_run_id="run-001",
        )


def test_orchestrate_stages_run_local_toolchain_set_ref_before_scan_and_c1(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fresh_cli_surface: BelgiCliSurface,
) -> None:
    run_orchestrator = fresh_cli_surface.run_orchestrator
    captured: dict[str, object] = {}
    source_repo = tmp_path / "src"
    source_toolchain_set_path = (
        source_repo / ".belgi" / "runs" / "run-001" / "inputs" / "environment" / "toolchain-set.json"
    )
    source_toolchain_set_path.parent.mkdir(parents=True, exist_ok=True)
    source_toolchain_set_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "toolchain_set_id": "env.toolchains",
                "refs": [{"id": "deps.python", "path": "toolchains/python.lock.json"}],
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
        toolchain_path = dest_repo / "toolchains" / "python.lock.json"
        toolchain_path.parent.mkdir(parents=True, exist_ok=True)
        toolchain_path.write_text("{\"python\":\"3.11.0\"}\n", encoding="utf-8", errors="strict")

    def _fake_supplychain_scan(
        *,
        repo: Path,
        base_revision: str,
        evaluated_revision: str,
        declared_toolchain_refs: list[str],
        out_path: Path,
        deterministic: bool,
        run_id: str = "unknown",
    ) -> int:
        captured["declared_toolchain_refs"] = list(declared_toolchain_refs)
        return 0

    def _fake_run_module_expect_rc(module_name: str, argv: list[str]) -> None:
        captured["module_name"] = module_name
        captured["argv"] = list(argv)
        raise _StopAfterC1("stop after c1")

    monkeypatch.setattr(run_orchestrator, "_command_log_mode_for_tier", lambda **_: "strings")
    monkeypatch.setattr(run_orchestrator, "_git_clone_at_commit", _fake_clone_at_commit)
    monkeypatch.setattr(run_orchestrator, "run_supplychain_scan", _fake_supplychain_scan)
    monkeypatch.setattr(run_orchestrator, "ensure_chain_templates", lambda **_: None)
    monkeypatch.setattr(run_orchestrator, "_run_module_expect_rc", _fake_run_module_expect_rc)

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
            declared_toolchain_set_ref="env.toolchains=.belgi/runs/run-001/inputs/environment/toolchain-set.json",
            workspace_rel=".belgi",
            current_run_id="run-001",
        )

    assert captured["declared_toolchain_refs"] == [
        "toolchain.main=out/inputs/toolchain.json",
        "deps.python=toolchains/python.lock.json",
    ]
    assert captured["module_name"] == "chain.compiler_c1_intent"
    assert "--toolchain-set" in captured["argv"]
    toolchain_set_arg = captured["argv"][captured["argv"].index("--toolchain-set") + 1]
    assert toolchain_set_arg == "env.toolchains=out/inputs/environment/toolchain-set.json"
    staged_obj = json.loads(
        (tmp_path / "chain" / "out" / "inputs" / "environment" / "toolchain-set.json").read_text(
            encoding="utf-8",
            errors="strict",
        )
    )
    assert staged_obj["toolchain_set_id"] == "env.toolchains"


def test_orchestrate_rejects_duplicate_toolchain_id_after_builtin_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fresh_cli_surface: BelgiCliSurface,
) -> None:
    run_orchestrator = fresh_cli_surface.run_orchestrator

    def _fake_clone_at_commit(*, source_repo: Path, dest_repo: Path, commit_sha: str) -> None:
        source_repo.mkdir(parents=True, exist_ok=True)
        dest_repo.mkdir(parents=True, exist_ok=True)

    def _fail_if_called(*args: object, **kwargs: object) -> int:
        raise AssertionError("run_supplychain_scan should not execute after duplicate toolchain-id detection")

    monkeypatch.setattr(run_orchestrator, "_command_log_mode_for_tier", lambda **_: "strings")
    monkeypatch.setattr(run_orchestrator, "_git_clone_at_commit", _fake_clone_at_commit)
    monkeypatch.setattr(
        run_orchestrator,
        "_bind_declared_toolchain_refs",
        lambda **_: ["toolchain.main=requirements-dev.txt"],
    )
    monkeypatch.setattr(run_orchestrator, "run_supplychain_scan", _fail_if_called)

    with pytest.raises(ValueError, match="duplicate toolchain id after built-in binding: toolchain.main"):
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


def test_orchestrate_rejects_foreign_run_toolchain_set_ref_before_c1(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fresh_cli_surface: BelgiCliSurface,
) -> None:
    run_orchestrator = fresh_cli_surface.run_orchestrator
    source_repo = tmp_path / "src"
    source_toolchain_set_path = (
        source_repo / ".belgi" / "runs" / "run-999" / "inputs" / "environment" / "toolchain-set.json"
    )
    source_toolchain_set_path.parent.mkdir(parents=True, exist_ok=True)
    source_toolchain_set_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "toolchain_set_id": "env.toolchains",
                "refs": [{"id": "deps.python", "path": "toolchains/python.lock.json"}],
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
        lambda **_: pytest.fail("run_supplychain_scan should not execute after foreign-run ToolchainSet rejection"),
    )

    with pytest.raises(
        ValueError,
        match=r"declared ToolchainSet ref must match the current run canonical path: \.belgi/runs/run-001/inputs/environment/toolchain-set\.json",
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
            declared_toolchain_set_ref="env.toolchains=.belgi/runs/run-999/inputs/environment/toolchain-set.json",
            workspace_rel=".belgi",
            current_run_id="run-001",
        )
