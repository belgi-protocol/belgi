"""Integration tests: tools/belgi_tools.py diff-capture satisfies Gate R R2/R3 checks.

These are ENGINE-only tests: we generate a real diff artifact via the operator CLI
and feed it into R2/R3 check functions.
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


def _git(cwd: Path, *args: str) -> str:
    p = subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)
    return (p.stdout or b"").decode("utf-8", errors="strict").strip()


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


def _run_tool(*, tmp_repo: Path, argv: list[str]) -> None:
    tool = REPO_ROOT / "tools" / "belgi_tools.py"
    subprocess.run([sys.executable, str(tool), *argv], cwd=tmp_repo, check=True, capture_output=True)


def _build_ctx(*, tmp_repo: Path, base_sha: str, head_sha: str, diff_storage_ref: str) -> object:
    from belgi.core.hash import sha256_bytes
    from belgi.protocol.pack import get_builtin_protocol_context
    from chain.logic.r_checks.context import RCheckContext

    protocol = get_builtin_protocol_context()

    diff_path = tmp_repo / Path(*diff_storage_ref.split("/"))
    diff_bytes = diff_path.read_bytes()

    locked_spec = {
        "run_id": "run-test-001",
        "tier": {"tier_id": "tier-1"},
        "constraints": {
            "allowed_paths": ["src/"],
            "forbidden_paths": ["secrets/"],
        },
    }

    evidence_manifest = {
        "schema_version": "1.0.0",
        "run_id": "run-test-001",
        "artifacts": [
            {
                "kind": "diff",
                "id": "diff.unified",
                "hash": sha256_bytes(diff_bytes),
                "media_type": "text/plain",
                "storage_ref": diff_storage_ref,
                "produced_by": "C1",
            }
        ],
        "commands_executed": ["belgi diff-capture"],
        "envelope_attestation": None,
    }

    return RCheckContext(
        repo_root=tmp_repo,
        protocol=protocol,
        locked_spec_path=tmp_repo / "LockedSpec.json",
        evidence_manifest_path=tmp_repo / "EvidenceManifest.json",
        gate_verdict_path=None,
        locked_spec=locked_spec,
        evidence_manifest=evidence_manifest,
        gate_verdict=None,
        tier_params={
            "command_log_mode": "strings",
            "scope_budgets.max_touched_files": 10,
            "scope_budgets.max_loc_delta": 200,
            "scope_budgets.forbidden_paths_enforcement": "strict",
            "waiver_policy.allowed": False,
        },
        evaluated_revision=head_sha,
        upstream_commit_sha=base_sha,
        policy_payload_schema=protocol.read_json("schemas/PolicyReportPayload.schema.json"),
        test_payload_schema=protocol.read_json("schemas/TestReportPayload.schema.json"),
        required_policy_report_ids=[],
        required_test_report_id="tests.report",
    )


class TestR2R3DiffCaptureIntegration:
    def test_r2_r3_pass_on_allowed_change(self, tmp_path: Path) -> None:
        tmp_repo = tmp_path / "repo"
        tmp_repo.mkdir()
        _init_git_repo(tmp_repo)

        _commit_file(tmp_repo, "README.md", "a\n", "init")
        base_sha = _git(tmp_repo, "rev-parse", "HEAD")

        _commit_file(tmp_repo, "src/x.txt", "b\n", "change")
        head_sha = _git(tmp_repo, "rev-parse", "HEAD")

        _run_tool(
            tmp_repo=tmp_repo,
            argv=[
                "diff-capture",
                "--repo",
                str(tmp_repo),
                "--upstream",
                base_sha,
                "--evaluated",
                head_sha,
                "--out",
                "out/diff.patch",
            ],
        )

        # Determinism: capture twice and compare bytes.
        _run_tool(
            tmp_repo=tmp_repo,
            argv=[
                "diff-capture",
                "--repo",
                str(tmp_repo),
                "--upstream",
                base_sha,
                "--evaluated",
                head_sha,
                "--out",
                "out/diff2.patch",
            ],
        )

        b1 = (tmp_repo / "out" / "diff.patch").read_bytes()
        b2 = (tmp_repo / "out" / "diff2.patch").read_bytes()
        assert b1 == b2

        from chain.logic.r_checks import r2_scope_budgets as r2
        from chain.logic.r_checks import r3_policy_invariants as r3

        ctx = _build_ctx(tmp_repo=tmp_repo, base_sha=base_sha, head_sha=head_sha, diff_storage_ref="out/diff.patch")

        r2_results = r2.run(ctx)
        assert len(r2_results) == 1
        assert r2_results[0].status == "PASS"

        r3_results = r3.run(ctx)
        assert len(r3_results) == 1
        assert r3_results[0].status == "PASS"

    def test_r3_fails_on_forbidden_path_change(self, tmp_path: Path) -> None:
        tmp_repo = tmp_path / "repo"
        tmp_repo.mkdir()
        _init_git_repo(tmp_repo)

        _commit_file(tmp_repo, "src/ok.txt", "ok\n", "init")
        base_sha = _git(tmp_repo, "rev-parse", "HEAD")

        _commit_file(tmp_repo, "secrets/token.txt", "nope\n", "forbidden")
        head_sha = _git(tmp_repo, "rev-parse", "HEAD")

        _run_tool(
            tmp_repo=tmp_repo,
            argv=[
                "diff-capture",
                "--repo",
                str(tmp_repo),
                "--upstream",
                base_sha,
                "--evaluated",
                head_sha,
                "--out",
                "out/diff.patch",
            ],
        )

        from chain.logic.r_checks import r3_policy_invariants as r3

        ctx = _build_ctx(tmp_repo=tmp_repo, base_sha=base_sha, head_sha=head_sha, diff_storage_ref="out/diff.patch")
        results = r3.run(ctx)
        assert len(results) == 1
        assert results[0].status == "FAIL"
        assert results[0].category == "FR-POLICY-FORBIDDEN-PATH"
