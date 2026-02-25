"""Integration tests: belgi scan outputs satisfy Gate R R7/R8 checks.

These are ENGINE-only tests: we generate real scan artifacts and feed them into
R7/R8 check functions (not just schema validation).
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any
from pathlib import Path

import pytest

pytestmark = pytest.mark.repo_local


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def _init_git_repo(tmp_repo: Path) -> None:
    _git(tmp_repo, "init")
    _git(tmp_repo, "config", "user.email", "test@example.com")
    _git(tmp_repo, "config", "user.name", "Test")


def _commit_file(tmp_repo: Path, rel: str, content: str, msg: str) -> None:
    p = tmp_repo / Path(*rel.split("/"))
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8", newline="\n")
    _git(tmp_repo, "add", rel)
    _git(tmp_repo, "commit", "-m", msg)


def _build_ctx_for_policy_report(
    *,
    tmp_repo: Path,
    report_storage_ref: str,
    report_id: str,
    required_subcommand: str,
    tier_id: str = "tier-0",
    command_log_mode: str = "strings",
    findings_mode: str = "warn",
    command_exit_code: int = 0,
    waivers_applied: list[str] | None = None,
    commands_executed_override: list[Any] | None = None,
) -> object:
    from belgi.core.hash import sha256_bytes
    from belgi.protocol.pack import get_builtin_protocol_context
    from chain.logic.r_checks.context import RCheckContext

    protocol = get_builtin_protocol_context()
    policy_schema = protocol.read_json("schemas/PolicyReportPayload.schema.json")

    report_path = tmp_repo / Path(*report_storage_ref.split("/"))
    report_bytes = report_path.read_bytes()

    if commands_executed_override is not None:
        commands_executed = commands_executed_override
    elif command_log_mode == "structured":
        commands_executed = [
            {
                "argv": ["belgi", required_subcommand],
                "exit_code": command_exit_code,
                "started_at": "1970-01-01T00:00:00Z",
                "finished_at": "1970-01-01T00:00:00Z",
            }
        ]
    else:
        commands_executed = [f"belgi {required_subcommand}"]

    evidence_manifest = {
        "schema_version": "1.0.0",
        "run_id": "run-test-001",
        "artifacts": [
            {
                "kind": "policy_report",
                "id": report_id,
                "hash": sha256_bytes(report_bytes),
                "media_type": "application/json",
                "storage_ref": report_storage_ref,
                "produced_by": "C1",
            }
        ],
        "commands_executed": commands_executed,
        "envelope_attestation": None,
    }

    return RCheckContext(
        repo_root=tmp_repo,
        protocol=protocol,
        locked_spec_path=tmp_repo / "LockedSpec.json",
        evidence_manifest_path=tmp_repo / "EvidenceManifest.json",
        gate_verdict_path=None,
        locked_spec={
            "run_id": "run-test-001",
            "tier": {"tier_id": tier_id},
            "waivers_applied": list(waivers_applied or []),
        },
        evidence_manifest=evidence_manifest,
        gate_verdict=None,
        tier_params={
            "command_log_mode": command_log_mode,
            "adversarial_policy.findings_mode": findings_mode,
            "waiver_policy.allowed": True,
        },
        evaluated_revision="HEAD",
        upstream_commit_sha="HEAD~1",
        policy_payload_schema=policy_schema,
        test_payload_schema=protocol.read_json("schemas/TestReportPayload.schema.json"),
        required_policy_report_ids=[report_id],
        required_test_report_id="tests.report",
    )


def _assert_policy_report_schema_valid(*, repo_root: Path, report_path: Path) -> None:
    from belgi.core.schema import validate_schema
    from belgi.protocol.pack import get_builtin_protocol_context

    protocol = get_builtin_protocol_context()
    schema = protocol.read_json("schemas/PolicyReportPayload.schema.json")
    obj = json.loads(report_path.read_text(encoding="utf-8", errors="strict"))
    errs = validate_schema(obj, schema, root_schema=schema, path="policy_report")
    assert errs == []


def _write_waiver(
    *,
    tmp_repo: Path,
    relpath: str,
    rule_id: str,
    scope: str,
    expires_at: str,
) -> str:
    waiver_path = tmp_repo / Path(*relpath.split("/"))
    waiver_path.parent.mkdir(parents=True, exist_ok=True)
    waiver_doc = {
        "schema_version": "1.0.0",
        "waiver_id": "waiver-r8-001",
        "gate_id": "R",
        "rule_id": rule_id,
        "scope": scope,
        "justification": "Deterministic waiver for controlled integration test.",
        "mitigation": "Replace unsafe primitive in follow-up patch.",
        "approver": "human:test@example.com",
        "created_at": "1970-01-01T00:00:00Z",
        "expires_at": expires_at,
        "audit_trail_ref": {"id": "audit-001", "storage_ref": "waivers/audit.log"},
        "status": "active",
    }
    waiver_path.write_text(json.dumps(waiver_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8", errors="strict")
    return relpath


class TestR7SupplychainScanIntegration:
    def test_r7_passes_on_clean_repo(self, tmp_path: Path) -> None:
        tmp_repo = tmp_path / "repo"
        tmp_repo.mkdir()
        _init_git_repo(tmp_repo)

        _commit_file(tmp_repo, "README.md", "a\n", "init")
        _commit_file(tmp_repo, "src/x.txt", "b\n", "change")

        from belgi.commands.supplychain_scan import run_supplychain_scan

        out_path = tmp_repo / "out" / "policy-supplychain.json"
        rc = run_supplychain_scan(
            repo=tmp_repo,
            evaluated_revision="HEAD~1",
            out_path=out_path,
            deterministic=True,
            run_id="run-test-001",
        )
        assert rc == 0

        _assert_policy_report_schema_valid(repo_root=tmp_repo, report_path=out_path)

        from chain.logic.r_checks import r7_supplychain_scan as r7

        ctx = _build_ctx_for_policy_report(
            tmp_repo=tmp_repo,
            report_storage_ref="out/policy-supplychain.json",
            report_id="policy.supplychain",
            required_subcommand="supplychain-scan",
        )

        results = r7.run(ctx)
        assert len(results) == 1
        assert results[0].status == "PASS"

    def test_r7_fails_when_report_indicates_failed(self, tmp_path: Path) -> None:
        tmp_repo = tmp_path / "repo"
        tmp_repo.mkdir()
        _init_git_repo(tmp_repo)

        _commit_file(tmp_repo, "README.md", "a\n", "init")
        _commit_file(tmp_repo, "src/x.txt", "b\n", "change")

        # Make repo dirty
        (tmp_repo / "src").mkdir(exist_ok=True)
        (tmp_repo / "src" / "x.txt").write_text("dirty\n", encoding="utf-8", newline="\n")

        from belgi.commands.supplychain_scan import run_supplychain_scan

        out_path = tmp_repo / "out" / "policy-supplychain.json"
        rc = run_supplychain_scan(
            repo=tmp_repo,
            evaluated_revision="HEAD~1",
            out_path=out_path,
            deterministic=True,
            run_id="run-test-001",
        )
        assert rc == 2

        _assert_policy_report_schema_valid(repo_root=tmp_repo, report_path=out_path)

        from chain.logic.r_checks import r7_supplychain_scan as r7

        ctx = _build_ctx_for_policy_report(
            tmp_repo=tmp_repo,
            report_storage_ref="out/policy-supplychain.json",
            report_id="policy.supplychain",
            required_subcommand="supplychain-scan",
        )

        results = r7.run(ctx)
        assert len(results) == 1
        assert results[0].status == "FAIL"
        assert results[0].category == "FR-SUPPLYCHAIN-CHANGE-UNACCOUNTED"


class TestR8AdversarialScanIntegration:
    def test_r8_passes_with_no_findings(self, tmp_path: Path) -> None:
        tmp_repo = tmp_path / "repo"
        tmp_repo.mkdir()
        _init_git_repo(tmp_repo)

        _commit_file(tmp_repo, "src/ok.py", "print('ok')\n", "init")

        from belgi.commands.adversarial_scan import run_adversarial_scan

        out_path = tmp_repo / "out" / "policy-adversarial-scan.json"
        rc = run_adversarial_scan(
            repo=tmp_repo,
            out_path=out_path,
            deterministic=True,
            run_id="run-test-001",
        )
        assert rc == 0

        _assert_policy_report_schema_valid(repo_root=tmp_repo, report_path=out_path)

        from chain.logic.r_checks import r8_adversarial_scan as r8

        ctx = _build_ctx_for_policy_report(
            tmp_repo=tmp_repo,
            report_storage_ref="out/policy-adversarial-scan.json",
            report_id="policy.adversarial_scan",
            required_subcommand="adversarial-scan",
        )

        results = r8.run(ctx)
        assert len(results) == 1
        assert results[0].status == "PASS"

    def test_r8_fails_when_findings_present(self, tmp_path: Path) -> None:
        tmp_repo = tmp_path / "repo"
        tmp_repo.mkdir()
        _init_git_repo(tmp_repo)

        _commit_file(
            tmp_repo,
            "src/bad.py",
            "import pickle\nexec('1')\npickle.loads(b'')\n",
            "init",
        )

        from belgi.commands.adversarial_scan import run_adversarial_scan

        out_path = tmp_repo / "out" / "policy-adversarial-scan.json"
        rc = run_adversarial_scan(
            repo=tmp_repo,
            out_path=out_path,
            deterministic=True,
            run_id="run-test-001",
        )
        assert rc == 2

        _assert_policy_report_schema_valid(repo_root=tmp_repo, report_path=out_path)

        from chain.logic.r_checks import r8_adversarial_scan as r8

        ctx = _build_ctx_for_policy_report(
            tmp_repo=tmp_repo,
            report_storage_ref="out/policy-adversarial-scan.json",
            report_id="policy.adversarial_scan",
            required_subcommand="adversarial-scan",
            tier_id="tier-1",
            command_log_mode="structured",
            findings_mode="fail",
            command_exit_code=2,
        )

        results = r8.run(ctx)
        assert len(results) == 1
        assert results[0].status == "FAIL"
        assert results[0].category == "FR-ADVERSARIAL-DIFF-SUSPECT"
        assert "ADV-EXEC-001" in results[0].message
        assert "ADV-PICKLE-002" in results[0].message

    def test_tier0_passes_with_findings_and_structured_signal(self, tmp_path: Path) -> None:
        tmp_repo = tmp_path / "repo"
        tmp_repo.mkdir()
        _init_git_repo(tmp_repo)
        _commit_file(tmp_repo, "src/bad.py", "exec('1')\n", "init")

        from belgi.commands.adversarial_scan import run_adversarial_scan
        from chain.logic.r_checks import r8_adversarial_scan as r8

        out_path = tmp_repo / "out" / "policy-adversarial-scan.json"
        rc = run_adversarial_scan(repo=tmp_repo, out_path=out_path, deterministic=True, run_id="run-test-001")
        assert rc == 2

        payload = json.loads(out_path.read_text(encoding="utf-8", errors="strict"))
        assert payload["findings_present"] is True
        assert int(payload["finding_count"]) > 0

        ctx = _build_ctx_for_policy_report(
            tmp_repo=tmp_repo,
            report_storage_ref="out/policy-adversarial-scan.json",
            report_id="policy.adversarial_scan",
            required_subcommand="adversarial-scan",
            tier_id="tier-0",
            command_log_mode="strings",
            findings_mode="warn",
        )
        results = r8.run(ctx)
        assert len(results) == 1
        assert results[0].status == "PASS"
        assert "findings_present=true" in results[0].message

    def test_tier1_passes_with_valid_waiver(self, tmp_path: Path) -> None:
        tmp_repo = tmp_path / "repo"
        tmp_repo.mkdir()
        _init_git_repo(tmp_repo)
        _commit_file(tmp_repo, "src/bad.py", "exec('1')\n", "init")

        from belgi.commands.adversarial_scan import run_adversarial_scan
        from chain.logic.r_checks import r8_adversarial_scan as r8

        out_path = tmp_repo / "out" / "policy-adversarial-scan.json"
        rc = run_adversarial_scan(repo=tmp_repo, out_path=out_path, deterministic=True, run_id="run-test-001")
        assert rc == 2

        waiver_ref = _write_waiver(
            tmp_repo=tmp_repo,
            relpath="waivers/r8_exec.json",
            rule_id="ADV-EXEC-001",
            scope="path:src/bad.py",
            expires_at="2099-01-01T00:00:00Z",
        )

        ctx = _build_ctx_for_policy_report(
            tmp_repo=tmp_repo,
            report_storage_ref="out/policy-adversarial-scan.json",
            report_id="policy.adversarial_scan",
            required_subcommand="adversarial-scan",
            tier_id="tier-1",
            command_log_mode="structured",
            findings_mode="fail",
            command_exit_code=2,
            waivers_applied=[waiver_ref],
        )
        results = r8.run(ctx)
        assert len(results) == 1
        assert results[0].status == "PASS"
        assert "waiver:waivers/r8_exec.json" in results[0].pointers

    def test_tier1_fails_closed_with_expired_waiver(self, tmp_path: Path) -> None:
        tmp_repo = tmp_path / "repo"
        tmp_repo.mkdir()
        _init_git_repo(tmp_repo)
        _commit_file(tmp_repo, "src/bad.py", "exec('1')\n", "init")

        from belgi.commands.adversarial_scan import run_adversarial_scan
        from chain.logic.r_checks import r8_adversarial_scan as r8

        out_path = tmp_repo / "out" / "policy-adversarial-scan.json"
        rc = run_adversarial_scan(repo=tmp_repo, out_path=out_path, deterministic=True, run_id="run-test-001")
        assert rc == 2

        waiver_ref = _write_waiver(
            tmp_repo=tmp_repo,
            relpath="waivers/r8_expired.json",
            rule_id="ADV-EXEC-001",
            scope="path:src/bad.py",
            expires_at="1969-01-01T00:00:00Z",
        )

        ctx = _build_ctx_for_policy_report(
            tmp_repo=tmp_repo,
            report_storage_ref="out/policy-adversarial-scan.json",
            report_id="policy.adversarial_scan",
            required_subcommand="adversarial-scan",
            tier_id="tier-1",
            command_log_mode="structured",
            findings_mode="fail",
            command_exit_code=2,
            waivers_applied=[waiver_ref],
        )
        results = r8.run(ctx)
        assert len(results) == 1
        assert results[0].status == "FAIL"
        assert results[0].category == "FR-SCHEMA-ARTIFACT-INVALID"
        assert "expired" in results[0].message
