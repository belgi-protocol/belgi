from __future__ import annotations

import json
from importlib.resources import files as resource_files
from pathlib import Path

import pytest

from belgi.core import run_orchestrator
from belgi.core.run_orchestrator import (
    ensure_chain_c3_canonicals,
    ensure_chain_templates,
)


def _builtin_template_bytes(name: str) -> bytes:
    return resource_files("belgi").joinpath("templates", name).read_bytes()


def _builtin_canonical_bytes(*parts: str) -> bytes:
    return resource_files("belgi").joinpath("canonicals", *parts).read_bytes()


def test_builtin_template_resources_are_readable() -> None:
    prompt_bytes = _builtin_template_bytes("PromptBundle.blocks.md")
    docs_bytes = _builtin_template_bytes("DocsCompiler.template.md")

    assert prompt_bytes
    assert docs_bytes


def test_builtin_canonical_resources_are_readable() -> None:
    canonical_bytes = _builtin_canonical_bytes("CANONICALS.md")
    terminology_bytes = _builtin_canonical_bytes("terminology.md")
    trust_model_bytes = _builtin_canonical_bytes("trust-model.md")

    assert canonical_bytes
    assert terminology_bytes
    assert trust_model_bytes


def test_ensure_chain_templates_hydrates_missing_templates(tmp_path: Path) -> None:
    ensure_chain_templates(chain_repo_root=tmp_path)

    prompt_path = tmp_path / "belgi" / "templates" / "PromptBundle.blocks.md"
    docs_path = tmp_path / "belgi" / "templates" / "DocsCompiler.template.md"

    assert prompt_path.is_file()
    assert docs_path.is_file()
    assert prompt_path.read_bytes() == _builtin_template_bytes("PromptBundle.blocks.md")
    assert docs_path.read_bytes() == _builtin_template_bytes("DocsCompiler.template.md")

    # Idempotency for deterministic re-entry.
    ensure_chain_templates(chain_repo_root=tmp_path)


def test_ensure_chain_templates_fail_closed_on_mismatch(tmp_path: Path) -> None:
    prompt_path = tmp_path / "belgi" / "templates" / "PromptBundle.blocks.md"
    prompt_path.parent.mkdir(parents=True, exist_ok=True)
    prompt_path.write_bytes(b"override-not-allowed\n")

    with pytest.raises(ValueError) as exc:
        ensure_chain_templates(chain_repo_root=tmp_path)

    message = str(exc.value)
    assert "CHAIN_TEMPLATE_MISMATCH: belgi/templates/PromptBundle.blocks.md" in message
    assert "adopter overrides are not allowed" in message


def test_ensure_chain_c3_canonicals_hydrates_missing_files(tmp_path: Path) -> None:
    ensure_chain_c3_canonicals(chain_repo_root=tmp_path)

    root = tmp_path / ".belgi" / "engine" / "c3_canonicals"
    canonical_path = root / "CANONICALS.md"
    terminology_path = root / "terminology.md"
    trust_model_path = root / "trust-model.md"
    operator_anchors_path = root / "docs" / "operations" / "operator-anchors.md"

    assert canonical_path.is_file()
    assert terminology_path.is_file()
    assert trust_model_path.is_file()
    assert operator_anchors_path.is_file()
    assert canonical_path.read_bytes() == _builtin_canonical_bytes("CANONICALS.md")
    assert terminology_path.read_bytes() == _builtin_canonical_bytes("terminology.md")
    assert trust_model_path.read_bytes() == _builtin_canonical_bytes("trust-model.md")
    assert operator_anchors_path.read_bytes() == _builtin_canonical_bytes("docs", "operations", "operator-anchors.md")

    # Idempotency for deterministic re-entry.
    ensure_chain_c3_canonicals(chain_repo_root=tmp_path)


def test_ensure_chain_c3_canonicals_fail_closed_on_mismatch(tmp_path: Path) -> None:
    term_path = tmp_path / ".belgi" / "engine" / "c3_canonicals" / "terminology.md"
    term_path.parent.mkdir(parents=True, exist_ok=True)
    term_path.write_bytes(b"override-not-allowed\n")

    with pytest.raises(ValueError) as exc:
        ensure_chain_c3_canonicals(chain_repo_root=tmp_path)

    message = str(exc.value)
    assert "CHAIN_CANONICAL_MISMATCH: .belgi/engine/c3_canonicals/terminology.md" in message
    assert "staged engine canonicals are immutable" in message


def test_orchestrate_runs_supplychain_before_template_hydration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from belgi.protocol.pack import get_builtin_protocol_context

    events: list[str] = []

    class _StopAfterEnsure(RuntimeError):
        pass

    def _fake_clone_at_commit(*, source_repo: Path, dest_repo: Path, commit_sha: str) -> None:
        source_repo.mkdir(parents=True, exist_ok=True)
        dest_repo.mkdir(parents=True, exist_ok=True)

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
        events.append("supplychain")
        return 0

    def _fake_ensure_chain_templates(*, chain_repo_root: Path) -> None:
        events.append("hydrate")
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
            evaluated_revision="0123456789abcdef0123456789abcdef01234567",
            revision_discovery_method="explicit",
            upstream_ref=None,
            intent_bytes=b"intent",
            protocol=get_builtin_protocol_context(),
        )

    assert events == ["supplychain", "hydrate"]


def test_orchestrate_passes_evaluated_revision_to_supplychain_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from belgi.protocol.pack import get_builtin_protocol_context

    observed_revisions: dict[str, object] = {}

    class _StopAfterEnsure(RuntimeError):
        pass

    def _fake_clone_at_commit(*, source_repo: Path, dest_repo: Path, commit_sha: str) -> None:
        source_repo.mkdir(parents=True, exist_ok=True)
        dest_repo.mkdir(parents=True, exist_ok=True)

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
        observed_revisions["base_revision"] = base_revision
        observed_revisions["evaluated_revision"] = evaluated_revision
        observed_revisions["declared_toolchain_refs"] = list(declared_toolchain_refs)
        return 0

    def _fake_ensure_chain_templates(*, chain_repo_root: Path) -> None:
        raise _StopAfterEnsure("stop after hydration")

    base_revision = "0123456789abcdef0123456789abcdef01234567"
    evaluated_revision = "89abcdef012345670123456789abcdef01234567"

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
            base_revision=base_revision,
            evaluated_revision=evaluated_revision,
            revision_discovery_method="explicit",
            upstream_ref=None,
            intent_bytes=b"intent",
            protocol=get_builtin_protocol_context(),
        )

    assert observed_revisions == {
        "base_revision": base_revision,
        "evaluated_revision": evaluated_revision,
        "declared_toolchain_refs": ["toolchain.main=out/inputs/toolchain.json"],
    }


def test_orchestrate_passes_explicit_run_toolchain_refs_to_supplychain_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from belgi.protocol.pack import get_builtin_protocol_context

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
            protocol=get_builtin_protocol_context(),
            declared_toolchain_refs=["deps.python=toolchains/python.lock.json"],
        )

    assert observed_refs["declared_toolchain_refs"] == [
        "toolchain.main=out/inputs/toolchain.json",
        "deps.python=toolchains/python.lock.json",
    ]


def test_orchestrate_passes_explicit_toolchain_set_ref_to_c1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from belgi.protocol.pack import get_builtin_protocol_context

    captured: dict[str, object] = {}

    class _StopAfterC1(RuntimeError):
        pass

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

    def _fake_run_module_expect_rc(module_name: str, argv: list[str]) -> None:
        captured["module_name"] = module_name
        captured["argv"] = list(argv)
        raise _StopAfterC1("stop after c1")

    monkeypatch.setattr(run_orchestrator, "_command_log_mode_for_tier", lambda **_: "strings")
    monkeypatch.setattr(run_orchestrator, "_git_clone_at_commit", _fake_clone_at_commit)
    monkeypatch.setattr(run_orchestrator, "run_supplychain_scan", lambda **_: 0)
    monkeypatch.setattr(run_orchestrator, "ensure_chain_templates", lambda **_: None)
    monkeypatch.setattr(run_orchestrator, "_run_module_expect_rc", _fake_run_module_expect_rc)

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
            protocol=get_builtin_protocol_context(),
            declared_toolchain_set_ref="env.toolchains=policy/environment/toolchain-set.json",
        )

    assert captured["module_name"] == "chain.compiler_c1_intent"
    assert "--toolchain-set" in captured["argv"]
    toolchain_set_arg = captured["argv"][captured["argv"].index("--toolchain-set") + 1]
    assert toolchain_set_arg == "env.toolchains=policy/environment/toolchain-set.json"
    toolchain_ref_args = [
        captured["argv"][idx + 1]
        for idx, token in enumerate(captured["argv"])
        if token == "--toolchain-ref"
    ]
    assert toolchain_ref_args == ["toolchain.main=out/inputs/toolchain.json"]


def test_orchestrate_rejects_duplicate_toolchain_id_after_builtin_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from belgi.protocol.pack import get_builtin_protocol_context

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
            protocol=get_builtin_protocol_context(),
        )


def test_orchestrate_generates_default_tolerances_object_for_c1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from belgi.protocol.pack import get_builtin_protocol_context

    captured: dict[str, object] = {}

    class _StopAfterC1(RuntimeError):
        pass

    def _fake_clone_at_commit(*, source_repo: Path, dest_repo: Path, commit_sha: str) -> None:
        source_repo.mkdir(parents=True, exist_ok=True)
        dest_repo.mkdir(parents=True, exist_ok=True)

    def _fake_run_module_expect_rc(module_name: str, argv: list[str]) -> None:
        captured["module_name"] = module_name
        captured["argv"] = list(argv)
        raise _StopAfterC1("stop after c1")

    monkeypatch.setattr(run_orchestrator, "_command_log_mode_for_tier", lambda **_: "strings")
    monkeypatch.setattr(run_orchestrator, "_git_clone_at_commit", _fake_clone_at_commit)
    monkeypatch.setattr(run_orchestrator, "run_supplychain_scan", lambda **_: 0)
    monkeypatch.setattr(run_orchestrator, "ensure_chain_templates", lambda **_: None)
    monkeypatch.setattr(run_orchestrator, "_run_module_expect_rc", _fake_run_module_expect_rc)

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
            protocol=get_builtin_protocol_context(),
        )

    assert captured["module_name"] == "chain.compiler_c1_intent"
    assert "--tolerances" in captured["argv"]
    tolerances_arg = captured["argv"][captured["argv"].index("--tolerances") + 1]
    assert tolerances_arg == "tier.tolerances=out/inputs/tolerances.json"

    tolerances_obj = json.loads(
        (tmp_path / "chain" / "out" / "inputs" / "tolerances.json").read_text(encoding="utf-8", errors="strict")
    )
    assert tolerances_obj == {
        "schema_version": "1.0.0",
        "tier_id": "tier-0",
        "scope_budgets": {
            "max_touched_files": 50,
            "max_loc_delta": 5000,
        },
    }


def test_orchestrate_passes_explicit_tolerances_ref_to_c1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from belgi.protocol.pack import get_builtin_protocol_context

    captured: dict[str, object] = {}

    class _StopAfterC1(RuntimeError):
        pass

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

    def _fake_run_module_expect_rc(module_name: str, argv: list[str]) -> None:
        captured["module_name"] = module_name
        captured["argv"] = list(argv)
        raise _StopAfterC1("stop after c1")

    monkeypatch.setattr(run_orchestrator, "_command_log_mode_for_tier", lambda **_: "strings")
    monkeypatch.setattr(run_orchestrator, "_git_clone_at_commit", _fake_clone_at_commit)
    monkeypatch.setattr(run_orchestrator, "run_supplychain_scan", lambda **_: 0)
    monkeypatch.setattr(run_orchestrator, "ensure_chain_templates", lambda **_: None)
    monkeypatch.setattr(run_orchestrator, "_run_module_expect_rc", _fake_run_module_expect_rc)

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
            protocol=get_builtin_protocol_context(),
            declared_tolerances_ref="tier.tolerances=policy/tolerances/tier-0.json",
        )

    assert captured["module_name"] == "chain.compiler_c1_intent"
    assert "--tolerances" in captured["argv"]
    tolerances_arg = captured["argv"][captured["argv"].index("--tolerances") + 1]
    assert tolerances_arg == "tier.tolerances=policy/tolerances/tier-0.json"
    assert not (tmp_path / "chain" / "out" / "inputs" / "tolerances.json").exists()
