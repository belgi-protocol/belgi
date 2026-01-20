"""Integration tests: belgi scan outputs satisfy Gate R R7/R8 checks.

These are ENGINE-only tests: we generate real scan artifacts and feed them into
R7/R8 check functions (not just schema validation).
"""

from __future__ import annotations

import subprocess
import sys
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
) -> object:
    from belgi.core.hash import sha256_bytes
    from belgi.protocol.pack import get_builtin_protocol_context
    from chain.logic.r_checks.context import RCheckContext

    protocol = get_builtin_protocol_context()
    policy_schema = protocol.read_json("schemas/PolicyReportPayload.schema.json")

    report_path = tmp_repo / Path(*report_storage_ref.split("/"))
    report_bytes = report_path.read_bytes()

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
        "commands_executed": [f"belgi {required_subcommand}"],
        "envelope_attestation": None,
    }

    return RCheckContext(
        repo_root=tmp_repo,
        protocol=protocol,
        locked_spec_path=tmp_repo / "LockedSpec.json",
        evidence_manifest_path=tmp_repo / "EvidenceManifest.json",
        gate_verdict_path=None,
        locked_spec={"run_id": "run-test-001"},
        evidence_manifest=evidence_manifest,
        gate_verdict=None,
        tier_params={"command_log_mode": "strings"},
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
    obj = __import__("json").loads(report_path.read_text(encoding="utf-8", errors="strict"))
    errs = validate_schema(obj, schema, root_schema=schema, path="policy_report")
    assert errs == []


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

        _commit_file(tmp_repo, "src/bad.py", "eval('1')\n", "init")

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
        )

        results = r8.run(ctx)
        assert len(results) == 1
        assert results[0].status == "FAIL"
        assert results[0].category == "FR-ADVERSARIAL-DIFF-SUSPECT"
