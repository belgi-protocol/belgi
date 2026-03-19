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


def test_workflow_docs_bound_release_boundary_without_overclaiming() -> None:
    text = _read_text("docs/operations/workflows.md")

    assert "BELGI signs/verifies protocol evidence." in text
    assert "The release/publish boundary is currently manual/operator-owned." in text
    assert "Stronger release artifact provenance is future work, not a present claim." in text


def test_readme_uses_current_workflow_references() -> None:
    text = _read_text("README.md")

    assert "actions/workflows/repository-verification.yml" in text
    assert ".github/workflows/repository-verification.yml" in text
    assert "demo_matrix.yml" not in text
    assert "actions/workflows/ci.yml" not in text
