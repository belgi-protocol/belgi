from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _read_text(relpath: str) -> str:
    return (REPO_ROOT / relpath).read_text(encoding="utf-8", errors="strict")


def _workflow_name(relpath: str) -> str:
    for line in _read_text(relpath).splitlines():
        if line.startswith("name:"):
            return line.split(":", 1)[1].strip().strip('"')
    raise AssertionError(f"missing workflow name in {relpath}")


def test_workflow_files_are_purpose_first_and_old_paths_are_gone() -> None:
    expected = {
        ".github/workflows/repository-verification.yml": "Repository Verification",
        ".github/workflows/pull-request-proof.yml": "Pull Request Proof",
        ".github/workflows/pinned-install-proof.yml": "Pinned Install Proof",
    }

    for relpath, expected_name in expected.items():
        assert (REPO_ROOT / relpath).is_file()
        assert _workflow_name(relpath) == expected_name

    for relpath in (
        ".github/workflows/ci.yml",
        ".github/workflows/proof-tier1.yml",
        ".github/workflows/belgi-tier1-reusable.yml",
    ):
        assert not (REPO_ROOT / relpath).exists()


def test_workflow_docs_define_three_distinct_proof_surfaces() -> None:
    text = _read_text("docs/operations/workflows.md")

    assert "These workflows prove different things under different input and trust models." in text
    assert "Overlap in Tier-0/Tier-1 execution does not make them duplicates." in text
    assert "`Repository Verification` is the repo/package verification surface." in text
    assert "`Pull Request Proof` is the exact PR-head review proof surface." in text
    assert "`Pinned Install Proof` is the reusable/manual pinned-install proof surface." in text
    assert "It is a bounded pinned-install path, not a PR-artifact collector." in text
    assert "Tier-2/Tier-3 remains outside the hosted proof-backed workflow surface in this patch." in text
    assert "`pinned-install-<belgi_ref_short>-<os>-<tier>`" in text
    assert "Proof surfaces and required gate contexts are not the same thing." in text
    assert "GitHub may show additional job-level checks in the UI." in text


def test_workflow_docs_bound_release_boundary_without_overclaiming() -> None:
    text = _read_text("docs/operations/workflows.md")

    assert "BELGI signs/verifies protocol evidence." in text
    assert "The release/publish boundary is currently manual/operator-owned." in text
    assert "Stronger release artifact provenance is future work, not a present claim." in text


def test_workflow_docs_define_stable_required_gate_contexts() -> None:
    text = _read_text("docs/operations/workflows.md")

    assert "Hosted rulesets or branch protection should require these stable gate contexts:" in text
    assert "- `repository-verification-gate`" in text
    assert "- `pull-request-proof-gate`" in text
    assert "`Pinned Install Proof` is not a PR-required context in `v1.4.17`." in text
    assert "Hosted governance should still bind only to the two stable gate contexts above." in text
    assert "Without `proof:full`, that gate remains NO-GO and the exact PR-head proof is not satisfied." in text


def test_workflow_docs_state_current_tracked_branch_model() -> None:
    text = _read_text("docs/operations/workflows.md")

    assert "This surface fits the main-only tracked workflow where short-lived work branches open pull requests directly to `main`." in text
    assert "- Protect `main` with required status checks before merge." in text
    assert "- Use short-lived work branches for tracked work and open pull requests directly to `main`." in text
    assert "- Name work branches as `work/<lisp-case-description>` so the branch still reads like the patch objective." in text
    assert "Protect `main` and `dev` with required status checks before merge." not in text


def test_workflow_files_define_gate_jobs_and_current_topology() -> None:
    repo_text = _read_text(".github/workflows/repository-verification.yml")
    pr_text = _read_text(".github/workflows/pull-request-proof.yml")
    pinned_text = _read_text(".github/workflows/pinned-install-proof.yml")

    assert "install-ruff" not in repo_text
    assert "\n      - name: Ruff lint\n" in repo_text
    assert "vars.BELGI_ENABLE_RUFF" not in repo_text
    assert 'python -m pip install "ruff==0.4.8"' in repo_text
    assert "python -m ruff check belgi chain tools wrapper tests scripts .github/scripts" in repo_text
    assert "\n  wheel-build:\n" in repo_text
    assert "\n  wheel-smoke:\n" in repo_text
    assert "needs: wheel-build" in repo_text
    assert "actions/download-artifact@634f93cb2916e3fdff6788551b99b062d0335ce0" in repo_text
    assert "name: repository-verification-gate" in repo_text
    assert "WHEEL_BUILD_RESULT: ${{ needs.wheel-build.result }}" in repo_text
    assert "WHEEL_SMOKE_RESULT: ${{ needs.wheel-smoke.result }}" in repo_text

    assert "name: pull-request-proof-gate" in pr_text
    assert "PROOF_FULL_LABEL_PRESENT:" in pr_text
    assert "NO-GO: add label proof:full so exact PR-head proof runs and this gate can pass" in pr_text
    assert "WHEEL_RESULT: ${{ needs.wheel-smoke.result }}" in pr_text

    assert "name: pinned-install-proof-gate" in pinned_text
    assert "--no-build-isolation" not in pinned_text


def test_readme_uses_current_workflow_references() -> None:
    text = _read_text("README.md")

    assert "actions/workflows/repository-verification.yml" in text
    assert "docs/operations/workflows.md" in text
    assert "demo_matrix.yml" not in text
    assert "actions/workflows/ci.yml" not in text
    assert "Local workflow checks with Docker + `act` are recommended before pushing workflow changes:" not in text
    assert "`repository-verification-gate` and `pull-request-proof-gate`" not in text
    assert "`Pinned Install Proof` remains manual/reusable and is not a PR-required context in `v1.4.17`." not in text


def test_readme_points_wheel_boundary_to_owner_docs() -> None:
    text = _read_text("README.md")

    assert "CANONICALS.md#wheel-vs-repo-local" in text
    assert "CANONICALS.md#publication-posture" in text
    assert "tools/README.md" in text
    assert "Published wheel (`pip install belgi`) includes:" not in text
    assert "python -m tools.check_drift" not in text


def test_repo_lint_authority_is_active_for_chosen_surface() -> None:
    pyproject = _read_text("pyproject.toml")
    workflows = _read_text("docs/operations/workflows.md")
    readme = _read_text("README.md")
    dev_sync = _read_text("scripts/dev_sync.ps1")

    assert "[tool.ruff]" in pyproject
    assert 'target-version = "py310"' in pyproject
    assert 'line-length = 88' in pyproject
    assert '"F",   # Pyflakes family' in pyproject
    assert '"I",   # import sorting' in pyproject
    assert '"B",   # bugbear' in pyproject
    assert 'fixable = ["ALL"]' in pyproject
    assert 'unfixable = ["B"]' in pyproject
    assert "Tracked `ruff` configuration is active on this surface" in workflows
    assert "repo-maintenance enforcement only" in workflows
    assert "Repo-local maintenance commands and tool contracts: [tools/README.md](tools/README.md)" in readme
    assert "Tracked `ruff` configuration is active as the repo-maintenance lint authority" not in readme
    assert 'Run-Step "Ruff lint"' in dev_sync
    assert 'function Resolve-RuffPython([string]$repoRoot, [hashtable]$fallbackPyInfo)' in dev_sync
    assert 'vars.BELGI_ENABLE_RUFF' not in _read_text(".github/workflows/repository-verification.yml")

    for text in (pyproject, workflows, readme):
        assert "flake8" not in text
