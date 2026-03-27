from __future__ import annotations

import json
from pathlib import Path

from tests.helpers import subprocess_cli as cli_subprocess

run_belgi = cli_subprocess.run_belgi
_commit_file = cli_subprocess._commit_file
_fresh_repo_clone = cli_subprocess._fresh_repo_clone
_git_rev_parse = cli_subprocess._git_rev_parse
_prepare_shared_run_intent = cli_subprocess._prepare_shared_run_intent
_rewrite_shared_run_intent_for_empty_doc_impact = cli_subprocess._rewrite_shared_run_intent_for_empty_doc_impact
_unset_upstream_if_present = cli_subprocess._unset_upstream_if_present
_write_local_json_object = cli_subprocess._write_local_json_object
_write_toolchain_set_object = cli_subprocess._write_toolchain_set_object
_write_tolerances_object = cli_subprocess._write_tolerances_object


def test_tier0_emits_findings_signal_in_summary_and_machine_json(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    _commit_file(repo, "src/risky_exec.py", "exec('1')\n", "add risky primitive")

    rc_init = run_belgi(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()
    intent_path = _prepare_shared_run_intent(
        repo,
        capsys=capsys,
        run_id="run-tier0-findings-001",
        tier_id="tier-0",
    )

    _unset_upstream_if_present(repo)
    base_sha = _git_rev_parse(repo, "HEAD~1")
    rc_run = run_belgi(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-0",
            "--intent-spec",
            intent_path.relative_to(repo).as_posix(),
            "--base-revision",
            base_sha,
        ]
    )
    assert rc_run == 0
    captured = capsys.readouterr()

    machine = json.loads(captured.out.splitlines()[0])
    run_key = machine["run_key"]
    attempt_dir = repo / ".belgi" / "store" / "runs" / run_key / "attempt-0001"

    summary_obj = json.loads((attempt_dir / "run.summary.json").read_text(encoding="utf-8", errors="strict"))
    adv = summary_obj.get("adversarial_scan")
    assert isinstance(adv, dict)
    assert adv.get("findings_present") is True
    assert isinstance(adv.get("finding_count"), int) and int(adv["finding_count"]) > 0
    assert machine.get("findings_present") is adv["findings_present"]
    assert machine.get("finding_count") == adv["finding_count"]

    adv_report = json.loads(
        (attempt_dir / "repo" / "out" / "artifacts" / "policy.adversarial_scan.json").read_text(
            encoding="utf-8", errors="strict"
        )
    )
    assert adv_report.get("findings_present") is True
    assert isinstance(adv_report.get("finding_count"), int) and int(adv_report["finding_count"]) > 0
    assert machine.get("findings_present") is adv_report["findings_present"]
    assert machine.get("finding_count") == adv_report["finding_count"]


def test_tier0_fails_r7_when_changed_declaration_surface_is_unaccounted(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    base_sha = _git_rev_parse(repo, "HEAD")
    requirements_path = repo / "requirements-dev.txt"
    baseline = requirements_path.read_text(encoding="utf-8", errors="strict").rstrip("\n")
    _commit_file(
        repo,
        "requirements-dev.txt",
        baseline + "\npytest-r7-accounting==1.0.0\n",
        "change dependency declaration",
    )

    rc_init = run_belgi(["init", "--repo", str(repo)])
    assert rc_init == 0
    run_id = "run-r7-unaccounted-001"
    rc_new = run_belgi(["run", "new", "--repo", str(repo), "--run-id", run_id])
    assert rc_new == 0
    _ = capsys.readouterr()

    intent_path = _rewrite_shared_run_intent_for_empty_doc_impact(
        repo,
        run_id=run_id,
        note="No documentation updates are required for this deterministic R7 accounting test.",
        tier_id="tier-0",
        allowed_dirs=["requirements-dev.txt"],
    )

    _unset_upstream_if_present(repo)
    rc_run = run_belgi(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-0",
            "--intent-spec",
            intent_path.relative_to(repo).as_posix(),
            "--base-revision",
            base_sha,
        ]
    )
    assert rc_run == 10
    captured = capsys.readouterr()

    machine = json.loads(captured.out.splitlines()[0])
    assert machine["ok"] is False
    assert machine["verdict"] == "NO-GO"

    run_key = str(machine["run_key"])
    attempt_id = str(machine["attempt_id"])
    attempt_dir = repo / ".belgi" / "store" / "runs" / run_key / attempt_id
    gate_r = json.loads((attempt_dir / "repo" / "out" / "GateVerdict.R.json").read_text(encoding="utf-8", errors="strict"))
    assert gate_r.get("failure_category") == "FR-SUPPLYCHAIN-CHANGE-UNACCOUNTED"
    assert gate_r.get("remediation", {}).get("next_instruction") == (
        "Do account for the changed dependency/toolchain surface in declared envelope refs or remove the change then re-run R."
    )

    locked_spec = json.loads((attempt_dir / "repo" / "out" / "LockedSpec.json").read_text(encoding="utf-8", errors="strict"))
    envelope = locked_spec.get("environment_envelope")
    pinned_refs = envelope.get("pinned_toolchain_refs") if isinstance(envelope, dict) else None
    assert isinstance(pinned_refs, list)
    assert len(pinned_refs) == 1
    assert pinned_refs[0]["id"] == "toolchain.main"
    assert pinned_refs[0]["storage_ref"] == "out/inputs/toolchain.json"

    policy_supply = json.loads(
        (attempt_dir / "repo" / "out" / "artifacts" / "policy.supplychain.json").read_text(
            encoding="utf-8", errors="strict"
        )
    )
    assert policy_supply.get("declared_toolchain_refs") == ["out/inputs/toolchain.json"]
    assert policy_supply.get("relevant_changed_paths") == ["requirements-dev.txt"]
    assert policy_supply.get("unaccounted_paths") == ["requirements-dev.txt"]


def test_tier0_run_locks_generated_default_tolerances_object(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    base_sha = _git_rev_parse(repo, "HEAD")

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    _ = capsys.readouterr()

    rc_run = run_belgi(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-0",
            "--base-revision",
            base_sha,
        ]
    )
    assert rc_run == 0
    captured = capsys.readouterr()

    machine = json.loads(captured.out.splitlines()[0])
    run_key = str(machine["run_key"])
    attempt_id = str(machine["attempt_id"])
    attempt_dir = repo / ".belgi" / "store" / "runs" / run_key / attempt_id

    locked_spec = json.loads((attempt_dir / "repo" / "out" / "LockedSpec.json").read_text(encoding="utf-8", errors="strict"))
    tier_obj = locked_spec.get("tier")
    tolerances_ref = tier_obj.get("tolerances_ref") if isinstance(tier_obj, dict) else None
    assert isinstance(tolerances_ref, dict)
    assert tolerances_ref["id"] == "tier.tolerances"
    assert tolerances_ref["storage_ref"] == "out/inputs/tolerances.json"

    tolerances_obj = json.loads(
        (attempt_dir / "repo" / "out" / "inputs" / "tolerances.json").read_text(encoding="utf-8", errors="strict")
    )
    assert tolerances_obj == {
        "schema_version": "1.0.0",
        "tier_id": "tier-0",
        "scope_budgets": {
            "max_touched_files": 50,
            "max_loc_delta": 5000,
        },
    }


def test_tier0_run_rejects_repo_relative_tolerances_ref_on_shipped_spine(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    _write_tolerances_object(
        repo,
        "policy/tolerances/tier-0.json",
        tier_id="tier-0",
        max_touched_files=50,
        max_loc_delta=5000,
        msg="add explicit tolerances object",
    )
    base_sha = _git_rev_parse(repo, "HEAD")

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    run_id = "run-repo-relative-tolerances-001"
    assert run_belgi(["run", "new", "--repo", str(repo), "--run-id", run_id]) == 0
    _ = capsys.readouterr()
    _unset_upstream_if_present(repo)

    rc_run = run_belgi(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-0",
            "--intent-spec",
            f".belgi/runs/{run_id}/inputs/intent/IntentSpec.core.md",
            "--base-revision",
            base_sha,
            "--tolerances-ref",
            "tier.tolerances=policy/tolerances/tier-0.json",
        ]
    )
    assert rc_run == 20
    captured = capsys.readouterr()

    machine = json.loads(captured.out.splitlines()[0])
    assert machine["ok"] is False
    assert machine["verdict"] == "NO-GO"
    assert str(machine.get("primary_reason") or "") == (
        f"--tolerances-ref must point to the current run canonical input: "
        f".belgi/runs/{run_id}/inputs/environment/tolerances.json"
    )


def test_tier0_run_accepts_run_local_tolerances_ref_on_shipped_spine(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    base_sha = _git_rev_parse(repo, "HEAD")

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    run_id = "run-local-tolerances-001"
    assert run_belgi(["run", "new", "--repo", str(repo), "--run-id", run_id]) == 0
    _ = capsys.readouterr()
    intent_path = _rewrite_shared_run_intent_for_empty_doc_impact(
        repo,
        run_id=run_id,
        note="No documentation updates are required for this deterministic run-local tolerances ingress test.",
        tier_id="tier-0",
    )

    tolerances_rel = f".belgi/runs/{run_id}/inputs/environment/tolerances.json"
    _write_local_json_object(
        repo,
        tolerances_rel,
        {
            "schema_version": "1.0.0",
            "tier_id": "tier-0",
            "scope_budgets": {
                "max_touched_files": 50,
                "max_loc_delta": 5000,
            },
        },
    )
    _unset_upstream_if_present(repo)

    rc_run = run_belgi(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-0",
            "--intent-spec",
            intent_path.relative_to(repo).as_posix(),
            "--base-revision",
            base_sha,
            "--tolerances-ref",
            f"tier.tolerances={tolerances_rel}",
        ]
    )
    assert rc_run == 0
    captured = capsys.readouterr()

    machine = json.loads(captured.out.splitlines()[0])
    run_key = str(machine["run_key"])
    attempt_id = str(machine["attempt_id"])
    attempt_dir = repo / ".belgi" / "store" / "runs" / run_key / attempt_id

    locked_spec = json.loads(
        (attempt_dir / "repo" / "out" / "LockedSpec.json").read_text(encoding="utf-8", errors="strict")
    )
    tier_obj = locked_spec.get("tier")
    tolerances_ref = tier_obj.get("tolerances_ref") if isinstance(tier_obj, dict) else None
    assert isinstance(tolerances_ref, dict)
    assert tolerances_ref["id"] == "tier.tolerances"
    assert tolerances_ref["storage_ref"] == "out/inputs/environment/tolerances.json"

    staged_obj = json.loads(
        (attempt_dir / "repo" / "out" / "inputs" / "environment" / "tolerances.json").read_text(
            encoding="utf-8", errors="strict"
        )
    )
    assert staged_obj == {
        "schema_version": "1.0.0",
        "tier_id": "tier-0",
        "scope_budgets": {
            "max_touched_files": 50,
            "max_loc_delta": 5000,
        },
    }

    summary = json.loads((attempt_dir / "run.summary.json").read_text(encoding="utf-8", errors="strict"))
    assert summary["run_key_preimage"]["normalized_inputs"]["tolerances_ref"] == (
        f"tier.tolerances={tolerances_rel}"
    )


def test_tier0_run_accepts_stricter_run_local_tolerances_ref_on_shipped_spine(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    base_sha = _git_rev_parse(repo, "HEAD")

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    run_id = "run-local-tolerances-tighten-001"
    assert run_belgi(["run", "new", "--repo", str(repo), "--run-id", run_id]) == 0
    _ = capsys.readouterr()
    intent_path = _rewrite_shared_run_intent_for_empty_doc_impact(
        repo,
        run_id=run_id,
        note="No documentation updates are required for this deterministic stricter tolerances ingress test.",
        tier_id="tier-0",
    )

    tolerances_rel = f".belgi/runs/{run_id}/inputs/environment/tolerances.json"
    _write_local_json_object(
        repo,
        tolerances_rel,
        {
            "schema_version": "1.0.0",
            "tier_id": "tier-0",
            "scope_budgets": {
                "max_touched_files": 10,
                "max_loc_delta": 1000,
            },
        },
    )
    _unset_upstream_if_present(repo)

    rc_run = run_belgi(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-0",
            "--intent-spec",
            intent_path.relative_to(repo).as_posix(),
            "--base-revision",
            base_sha,
            "--tolerances-ref",
            f"tier.tolerances={tolerances_rel}",
        ]
    )
    assert rc_run == 0
    captured = capsys.readouterr()

    machine = json.loads(captured.out.splitlines()[0])
    run_key = str(machine["run_key"])
    attempt_id = str(machine["attempt_id"])
    attempt_dir = repo / ".belgi" / "store" / "runs" / run_key / attempt_id

    staged_obj = json.loads(
        (attempt_dir / "repo" / "out" / "inputs" / "environment" / "tolerances.json").read_text(
            encoding="utf-8", errors="strict"
        )
    )
    assert staged_obj == {
        "schema_version": "1.0.0",
        "tier_id": "tier-0",
        "scope_budgets": {
            "max_touched_files": 10,
            "max_loc_delta": 1000,
        },
    }


def test_tier0_run_toolchain_ref_accounts_for_changed_declaration_surface(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    base_sha = _git_rev_parse(repo, "HEAD")
    requirements_path = repo / "requirements-dev.txt"
    baseline = requirements_path.read_text(encoding="utf-8", errors="strict").rstrip("\n")
    _commit_file(
        repo,
        "requirements-dev.txt",
        baseline + "\npytest-r7-accounted==1.0.0\n",
        "change dependency declaration",
    )

    rc_init = run_belgi(["init", "--repo", str(repo)])
    assert rc_init == 0
    run_id = "run-r7-accounted-001"
    rc_new = run_belgi(["run", "new", "--repo", str(repo), "--run-id", run_id])
    assert rc_new == 0
    _ = capsys.readouterr()

    intent_path = _rewrite_shared_run_intent_for_empty_doc_impact(
        repo,
        run_id=run_id,
        note="No documentation updates are required for this deterministic R7 accounting test.",
        tier_id="tier-0",
        allowed_dirs=["requirements-dev.txt"],
    )

    _unset_upstream_if_present(repo)
    rc_run = run_belgi(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-0",
            "--intent-spec",
            intent_path.relative_to(repo).as_posix(),
            "--base-revision",
            base_sha,
            "--toolchain-ref",
            "deps.requirements=requirements-dev.txt",
        ]
    )
    assert rc_run == 0
    captured = capsys.readouterr()

    machine = json.loads(captured.out.splitlines()[0])
    assert machine["ok"] is True
    assert machine["verdict"] == "GO"

    run_key = str(machine["run_key"])
    attempt_id = str(machine["attempt_id"])
    attempt_dir = repo / ".belgi" / "store" / "runs" / run_key / attempt_id
    locked_spec = json.loads((attempt_dir / "repo" / "out" / "LockedSpec.json").read_text(encoding="utf-8", errors="strict"))
    envelope = locked_spec.get("environment_envelope")
    toolchain_set_ref = envelope.get("toolchain_set_ref") if isinstance(envelope, dict) else None
    assert isinstance(toolchain_set_ref, dict)
    assert toolchain_set_ref["id"] == "env.toolchains"
    assert toolchain_set_ref["storage_ref"] == "out/inputs/toolchain-set.json"
    pinned_refs = envelope.get("pinned_toolchain_refs") if isinstance(envelope, dict) else None
    assert isinstance(pinned_refs, list)
    assert [(ref["id"], ref["storage_ref"]) for ref in pinned_refs] == [
        ("toolchain.main", "out/inputs/toolchain.json"),
        ("deps.requirements", "requirements-dev.txt"),
    ]

    toolchain_set_obj = json.loads(
        (attempt_dir / "repo" / "out" / "inputs" / "toolchain-set.json").read_text(
            encoding="utf-8", errors="strict"
        )
    )
    assert toolchain_set_obj == {
        "schema_version": "1.0.0",
        "toolchain_set_id": "env.toolchains",
        "refs": [
            {
                "id": "deps.requirements",
                "path": "requirements-dev.txt",
            }
        ],
    }

    policy_supply = json.loads(
        (attempt_dir / "repo" / "out" / "artifacts" / "policy.supplychain.json").read_text(
            encoding="utf-8", errors="strict"
        )
    )
    assert policy_supply.get("declared_toolchain_refs") == ["out/inputs/toolchain.json", "requirements-dev.txt"]
    assert policy_supply.get("relevant_changed_paths") == ["requirements-dev.txt"]
    assert policy_supply.get("unaccounted_paths") == []

    gate_r = json.loads((attempt_dir / "repo" / "out" / "GateVerdict.R.json").read_text(encoding="utf-8", errors="strict"))
    assert gate_r.get("verdict") == "GO"


def test_tier0_rejects_legacy_intent_numeric_budgets_with_migration_guidance(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    base_sha = _git_rev_parse(repo, "HEAD")

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    run_id = "run-r2-widen-001"
    assert run_belgi(["run", "new", "--repo", str(repo), "--run-id", run_id]) == 0
    _ = capsys.readouterr()

    intent_path = _rewrite_shared_run_intent_for_empty_doc_impact(
        repo,
        run_id=run_id,
        note="No documentation updates are required for this deterministic R2 ceiling test.",
        tier_id="tier-0",
    )
    intent_text = intent_path.read_text(encoding="utf-8", errors="strict")
    updated_intent = intent_text.replace(
        '  forbidden_dirs:\n    - "secrets/"\n',
        '  forbidden_dirs:\n    - "secrets/"\n  max_touched_files: 999\n  max_loc_delta: 999999\n',
        1,
    )
    assert updated_intent != intent_text
    intent_path.write_text(updated_intent, encoding="utf-8", errors="strict", newline="\n")

    _unset_upstream_if_present(repo)
    rc_run = run_belgi(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-0",
            "--intent-spec",
            intent_path.relative_to(repo).as_posix(),
            "--base-revision",
            base_sha,
        ]
    )
    assert rc_run == 10
    captured = capsys.readouterr()

    machine = json.loads(captured.out.splitlines()[0])
    assert machine["ok"] is False
    assert machine["verdict"] == "NO-GO"

    run_key = str(machine["run_key"])
    attempt_id = str(machine["attempt_id"])
    attempt_dir = repo / ".belgi" / "store" / "runs" / run_key / attempt_id
    chain_out_dir = attempt_dir / "repo" / "out"
    assert not (chain_out_dir / "GateVerdict.Q.json").exists()
    assert "IntentSpec.scope numeric budgets are retired" in captured.err
    assert "remove IntentSpec.scope.max_*" in captured.err
    assert "move numeric budgets into a Tolerances object" in captured.err


def test_tier0_run_rejects_repo_relative_toolchain_set_ref_on_shipped_spine(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    _write_toolchain_set_object(
        repo,
        "policy/environment/toolchain-set.json",
        toolchain_set_id="env.toolchains",
        refs=[{"id": "deps.requirements", "path": "requirements-dev.txt"}],
        msg="add explicit ToolchainSet object",
    )
    base_sha = _git_rev_parse(repo, "HEAD")

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    run_id = "run-repo-relative-toolchain-set-001"
    assert run_belgi(["run", "new", "--repo", str(repo), "--run-id", run_id]) == 0
    _ = capsys.readouterr()
    _unset_upstream_if_present(repo)

    rc_run = run_belgi(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-0",
            "--intent-spec",
            f".belgi/runs/{run_id}/inputs/intent/IntentSpec.core.md",
            "--base-revision",
            base_sha,
            "--toolchain-set-ref",
            "env.toolchains=policy/environment/toolchain-set.json",
        ]
    )
    assert rc_run == 20
    captured = capsys.readouterr()

    machine = json.loads(captured.out.splitlines()[0])
    assert machine["ok"] is False
    assert machine["verdict"] == "NO-GO"
    assert str(machine.get("primary_reason") or "") == (
        f"--toolchain-set-ref must point to the current run canonical input: "
        f".belgi/runs/{run_id}/inputs/environment/toolchain-set.json"
    )


def test_tier0_run_accepts_run_local_toolchain_set_ref_on_shipped_spine(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    base_sha = _git_rev_parse(repo, "HEAD")

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    run_id = "run-local-toolchain-set-001"
    assert run_belgi(["run", "new", "--repo", str(repo), "--run-id", run_id]) == 0
    _ = capsys.readouterr()
    intent_path = _rewrite_shared_run_intent_for_empty_doc_impact(
        repo,
        run_id=run_id,
        note="No documentation updates are required for this deterministic run-local ToolchainSet ingress test.",
        tier_id="tier-0",
    )

    toolchain_set_rel = f".belgi/runs/{run_id}/inputs/environment/toolchain-set.json"
    _write_local_json_object(
        repo,
        toolchain_set_rel,
        {
            "schema_version": "1.0.0",
            "toolchain_set_id": "env.toolchains",
            "refs": [{"id": "deps.requirements", "path": "requirements-dev.txt"}],
        },
    )
    _unset_upstream_if_present(repo)

    rc_run = run_belgi(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-0",
            "--intent-spec",
            intent_path.relative_to(repo).as_posix(),
            "--base-revision",
            base_sha,
            "--toolchain-set-ref",
            f"env.toolchains={toolchain_set_rel}",
        ]
    )
    assert rc_run == 0
    captured = capsys.readouterr()

    machine = json.loads(captured.out.splitlines()[0])
    run_key = str(machine["run_key"])
    attempt_id = str(machine["attempt_id"])
    attempt_dir = repo / ".belgi" / "store" / "runs" / run_key / attempt_id

    locked_spec = json.loads(
        (attempt_dir / "repo" / "out" / "LockedSpec.json").read_text(encoding="utf-8", errors="strict")
    )
    envelope = locked_spec.get("environment_envelope")
    toolchain_set_ref = envelope.get("toolchain_set_ref") if isinstance(envelope, dict) else None
    pinned_refs = envelope.get("pinned_toolchain_refs") if isinstance(envelope, dict) else None

    assert isinstance(toolchain_set_ref, dict)
    assert toolchain_set_ref["id"] == "env.toolchains"
    assert toolchain_set_ref["storage_ref"] == "out/inputs/environment/toolchain-set.json"
    assert isinstance(pinned_refs, list)
    assert [(ref["id"], ref["storage_ref"]) for ref in pinned_refs] == [
        ("toolchain.main", "out/inputs/toolchain.json"),
        ("deps.requirements", "requirements-dev.txt"),
    ]

    staged_obj = json.loads(
        (attempt_dir / "repo" / "out" / "inputs" / "environment" / "toolchain-set.json").read_text(
            encoding="utf-8", errors="strict"
        )
    )
    assert staged_obj == {
        "schema_version": "1.0.0",
        "toolchain_set_id": "env.toolchains",
        "refs": [
            {
                "id": "deps.requirements",
                "path": "requirements-dev.txt",
            }
        ],
    }

    summary = json.loads((attempt_dir / "run.summary.json").read_text(encoding="utf-8", errors="strict"))
    assert summary["run_key_preimage"]["normalized_inputs"]["toolchain_set_ref"] == (
        f"env.toolchains={toolchain_set_rel}"
    )


def test_tier0_rejects_foreign_run_tolerances_ref_on_shipped_spine(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    base_sha = _git_rev_parse(repo, "HEAD")

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    current_run_id = "run-current-tolerances-001"
    foreign_run_id = "run-foreign-tolerances-001"
    assert run_belgi(["run", "new", "--repo", str(repo), "--run-id", current_run_id]) == 0
    assert run_belgi(["run", "new", "--repo", str(repo), "--run-id", foreign_run_id]) == 0
    _ = capsys.readouterr()

    foreign_tolerances_rel = f".belgi/runs/{foreign_run_id}/inputs/environment/tolerances.json"
    _write_local_json_object(
        repo,
        foreign_tolerances_rel,
        {
            "schema_version": "1.0.0",
            "tier_id": "tier-0",
            "scope_budgets": {
                "max_touched_files": 50,
                "max_loc_delta": 5000,
            },
        },
    )
    _unset_upstream_if_present(repo)

    rc_run = run_belgi(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-0",
            "--intent-spec",
            f".belgi/runs/{current_run_id}/inputs/intent/IntentSpec.core.md",
            "--base-revision",
            base_sha,
            "--tolerances-ref",
            f"tier.tolerances={foreign_tolerances_rel}",
        ]
    )
    assert rc_run == 20
    captured = capsys.readouterr()
    machine = json.loads(captured.out.splitlines()[0])
    assert machine["ok"] is False
    assert machine["verdict"] == "NO-GO"
    assert str(machine.get("primary_reason") or "") == (
        f"--tolerances-ref must point to the current run canonical input: "
        f".belgi/runs/{current_run_id}/inputs/environment/tolerances.json"
    )


def test_tier0_run_rejects_wider_run_local_tolerances_ref_on_shipped_spine(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    base_sha = _git_rev_parse(repo, "HEAD")

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    run_id = "run-local-tolerances-wide-001"
    assert run_belgi(["run", "new", "--repo", str(repo), "--run-id", run_id]) == 0
    _ = capsys.readouterr()
    intent_path = _rewrite_shared_run_intent_for_empty_doc_impact(
        repo,
        run_id=run_id,
        note="No documentation updates are required for this deterministic wider tolerances rejection test.",
        tier_id="tier-0",
    )

    tolerances_rel = f".belgi/runs/{run_id}/inputs/environment/tolerances.json"
    _write_local_json_object(
        repo,
        tolerances_rel,
        {
            "schema_version": "1.0.0",
            "tier_id": "tier-0",
            "scope_budgets": {
                "max_touched_files": 99,
                "max_loc_delta": 9999,
            },
        },
    )
    _unset_upstream_if_present(repo)

    rc_run = run_belgi(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-0",
            "--intent-spec",
            intent_path.relative_to(repo).as_posix(),
            "--base-revision",
            base_sha,
            "--tolerances-ref",
            f"tier.tolerances={tolerances_rel}",
        ]
    )
    assert rc_run == 10
    captured = capsys.readouterr()

    machine = json.loads(captured.out.splitlines()[0])
    assert machine["ok"] is False
    assert machine["verdict"] == "NO-GO"
    assert "widens selected tier ceilings" in str(machine.get("primary_reason") or "")
    assert "max_touched_files=99" in str(machine.get("primary_reason") or "")
    assert "max_loc_delta=9999" in str(machine.get("primary_reason") or "")


def test_tier0_run_rejects_mismatched_tier_run_local_tolerances_ref_on_shipped_spine(
    tmp_path: Path, capsys: object
) -> None:
    repo = _fresh_repo_clone(tmp_path)
    base_sha = _git_rev_parse(repo, "HEAD")

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    run_id = "run-local-tolerances-tier-mismatch-001"
    assert run_belgi(["run", "new", "--repo", str(repo), "--run-id", run_id]) == 0
    _ = capsys.readouterr()
    intent_path = _rewrite_shared_run_intent_for_empty_doc_impact(
        repo,
        run_id=run_id,
        note="No documentation updates are required for this deterministic tier mismatch test.",
        tier_id="tier-0",
    )

    tolerances_rel = f".belgi/runs/{run_id}/inputs/environment/tolerances.json"
    _write_local_json_object(
        repo,
        tolerances_rel,
        {
            "schema_version": "1.0.0",
            "tier_id": "tier-1",
            "scope_budgets": {
                "max_touched_files": 50,
                "max_loc_delta": 5000,
            },
        },
    )
    _unset_upstream_if_present(repo)

    rc_run = run_belgi(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-0",
            "--intent-spec",
            intent_path.relative_to(repo).as_posix(),
            "--base-revision",
            base_sha,
            "--tolerances-ref",
            f"tier.tolerances={tolerances_rel}",
        ]
    )
    assert rc_run == 10
    captured = capsys.readouterr()

    machine = json.loads(captured.out.splitlines()[0])
    assert machine["ok"] is False
    assert machine["verdict"] == "NO-GO"
    assert "Locked tolerances object tier mismatch" in str(machine.get("primary_reason") or "")


def test_tier0_rejects_wrong_leaf_toolchain_set_ref_on_shipped_spine(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    base_sha = _git_rev_parse(repo, "HEAD")

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    run_id = "run-wrong-leaf-toolchain-001"
    assert run_belgi(["run", "new", "--repo", str(repo), "--run-id", run_id]) == 0
    _ = capsys.readouterr()

    wrong_leaf_rel = f".belgi/runs/{run_id}/inputs/environment/toolchain-other.json"
    _write_local_json_object(
        repo,
        wrong_leaf_rel,
        {
            "schema_version": "1.0.0",
            "toolchain_set_id": "env.toolchains",
            "refs": [{"id": "deps.requirements", "path": "requirements-dev.txt"}],
        },
    )
    _unset_upstream_if_present(repo)

    rc_run = run_belgi(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-0",
            "--intent-spec",
            f".belgi/runs/{run_id}/inputs/intent/IntentSpec.core.md",
            "--base-revision",
            base_sha,
            "--toolchain-set-ref",
            f"env.toolchains={wrong_leaf_rel}",
        ]
    )
    assert rc_run == 20
    captured = capsys.readouterr()
    machine = json.loads(captured.out.splitlines()[0])
    assert machine["ok"] is False
    assert machine["verdict"] == "NO-GO"
    assert str(machine.get("primary_reason") or "") == (
        f"--toolchain-set-ref must point to the current run canonical input: "
        f".belgi/runs/{run_id}/inputs/environment/toolchain-set.json"
    )


def test_tier0_rejects_toolchain_ref_missing_path(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    base_sha = _git_rev_parse(repo, "HEAD")

    rc_init = run_belgi(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()

    rc_run = run_belgi(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-0",
            "--base-revision",
            base_sha,
            "--toolchain-ref",
            "deps.missing=toolchains/missing.lock.json",
        ]
    )
    assert rc_run == 20
    captured = capsys.readouterr()
    machine = json.loads(captured.out.splitlines()[0])
    assert machine["ok"] is False
    assert machine["verdict"] == "NO-GO"
    assert "toolchains/missing.lock.json" in str(machine.get("primary_reason") or "")


def test_tier0_rejects_toolchain_ref_outside_evaluated_revision(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    base_sha = _git_rev_parse(repo, "HEAD")
    local_only_path = repo / "toolchains" / "local-only.lock.json"
    local_only_path.parent.mkdir(parents=True, exist_ok=True)
    local_only_path.write_text("{\"python\":\"3.11.0\"}\n", encoding="utf-8", errors="strict")

    rc_init = run_belgi(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()

    rc_run = run_belgi(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-0",
            "--base-revision",
            base_sha,
            "--toolchain-ref",
            "deps.local=toolchains/local-only.lock.json",
        ]
    )
    assert rc_run == 20
    captured = capsys.readouterr()
    machine = json.loads(captured.out.splitlines()[0])
    assert machine["ok"] is False
    assert machine["verdict"] == "NO-GO"
    reason = str(machine.get("primary_reason") or "")
    assert "present in the evaluated revision" in reason
    assert "toolchains/local-only.lock.json" in reason


def test_tier0_rejects_malformed_run_local_tolerances_ref(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    base_sha = _git_rev_parse(repo, "HEAD")

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    _ = capsys.readouterr()

    rc_run = run_belgi(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-0",
            "--base-revision",
            base_sha,
            "--tolerances-ref",
            "tier.tolerances",
        ]
    )
    assert rc_run == 20
    captured = capsys.readouterr()
    machine = json.loads(captured.out.splitlines()[0])
    assert machine["ok"] is False
    assert machine["verdict"] == "NO-GO"
    assert "--tolerances-ref must use <object_id>=<repo-relative-path>" in str(machine.get("primary_reason") or "")


def test_tier0_rejects_run_local_tolerances_ref_missing_path(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    base_sha = _git_rev_parse(repo, "HEAD")

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    run_id = "run-local-missing-tolerances-001"
    assert run_belgi(["run", "new", "--repo", str(repo), "--run-id", run_id]) == 0
    _ = capsys.readouterr()

    tolerances_rel = f".belgi/runs/{run_id}/inputs/environment/tolerances.json"
    rc_run = run_belgi(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-0",
            "--intent-spec",
            f".belgi/runs/{run_id}/inputs/intent/IntentSpec.core.md",
            "--base-revision",
            base_sha,
            "--tolerances-ref",
            f"tier.tolerances={tolerances_rel}",
        ]
    )
    assert rc_run == 20
    captured = capsys.readouterr()
    machine = json.loads(captured.out.splitlines()[0])
    assert machine["ok"] is False
    assert machine["verdict"] == "NO-GO"
    assert tolerances_rel in str(machine.get("primary_reason") or "")


def test_tier0_rejects_run_local_toolchain_set_ref_with_local_only_member_path(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    base_sha = _git_rev_parse(repo, "HEAD")

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    run_id = "run-local-toolchain-invalid-001"
    assert run_belgi(["run", "new", "--repo", str(repo), "--run-id", run_id]) == 0
    _ = capsys.readouterr()

    local_member_rel = f".belgi/runs/{run_id}/inputs/environment/local-only.lock.json"
    _write_local_json_object(repo, local_member_rel, {"python": "3.11.0"})
    toolchain_set_rel = f".belgi/runs/{run_id}/inputs/environment/toolchain-set.json"
    _write_local_json_object(
        repo,
        toolchain_set_rel,
        {
            "schema_version": "1.0.0",
            "toolchain_set_id": "env.toolchains",
            "refs": [{"id": "deps.local", "path": local_member_rel}],
        },
    )
    _unset_upstream_if_present(repo)

    rc_run = run_belgi(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-0",
            "--intent-spec",
            f".belgi/runs/{run_id}/inputs/intent/IntentSpec.core.md",
            "--base-revision",
            base_sha,
            "--toolchain-set-ref",
            f"env.toolchains={toolchain_set_rel}",
        ]
    )
    assert rc_run == 10
    captured = capsys.readouterr()
    machine = json.loads(captured.out.splitlines()[0])
    assert machine["ok"] is False
    assert machine["verdict"] == "NO-GO"
    reason = str(machine.get("primary_reason") or "")
    assert "declared ToolchainSet ref missing/invalid in evaluated revision" in reason
    assert local_member_rel in reason


def test_tier0_rejects_reserved_toolchain_main_id(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    base_sha = _git_rev_parse(repo, "HEAD")

    rc_init = run_belgi(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()

    rc_run = run_belgi(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-0",
            "--base-revision",
            base_sha,
            "--toolchain-ref",
            "toolchain.main=requirements-dev.txt",
        ]
    )
    assert rc_run == 20
    captured = capsys.readouterr()
    machine = json.loads(captured.out.splitlines()[0])
    assert machine["ok"] is False
    assert machine["verdict"] == "NO-GO"
    assert "toolchain.main" in str(machine.get("primary_reason") or "")
    assert "reserved" in str(machine.get("primary_reason") or "")
