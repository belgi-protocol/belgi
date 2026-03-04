from __future__ import annotations

import json
import shutil
import subprocess
import sys
from importlib.resources import files as resource_files
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
for _k in list(sys.modules.keys()):
    if _k == "belgi" or _k.startswith("belgi."):
        del sys.modules[_k]

from belgi.cli import main as belgi_main


@pytest.fixture(autouse=True)
def _clear_base_revision_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BELGI_BASE_SHA", raising=False)
    monkeypatch.delenv("GITHUB_BASE_SHA", raising=False)


def _init_min_git_repo(tmp_path: Path, *, name: str = "repo") -> Path:
    repo = tmp_path / name
    repo.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True, capture_output=True, text=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True, capture_output=True, text=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test User"], check=True, capture_output=True, text=True)
    (repo / "README.md").write_text("# adopter\n", encoding="utf-8", errors="strict")
    subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True, capture_output=True, text=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "init"], check=True, capture_output=True, text=True)
    return repo


def _builtin_canonical_bytes(name: str) -> bytes:
    return resource_files("belgi").joinpath("canonicals", name).read_bytes()


def _head_sha(repo: Path) -> str:
    cp = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return cp.stdout.strip().lower()


def test_tier0_run_succeeds_without_repo_root_canonical_docs(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = _init_min_git_repo(tmp_path)
    assert not (repo / "CANONICALS.md").exists()
    assert not (repo / "terminology.md").exists()
    assert not (repo / "trust-model.md").exists()

    rc_init = belgi_main(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()

    rc_run = belgi_main(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", _head_sha(repo)])
    captured = capsys.readouterr()
    assert rc_run == 0, captured.err
    assert "missing path in scope" not in captured.err

    machine = json.loads(captured.out.splitlines()[0])
    assert machine["ok"] is True
    assert machine["verdict"] == "GO"


def test_tier0_run_uses_engine_canonicals_when_repo_has_collision(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = _init_min_git_repo(tmp_path)
    (repo / "terminology.md").write_text("ADOPTER COLLISION\n", encoding="utf-8", errors="strict")
    subprocess.run(["git", "-C", str(repo), "add", "terminology.md"], check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-q", "-m", "add conflicting terminology"], check=True, capture_output=True, text=True
    )

    rc_init = belgi_main(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()

    rc_run = belgi_main(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", _head_sha(repo)])
    captured = capsys.readouterr()
    assert rc_run == 0, captured.err

    machine = json.loads(captured.out.splitlines()[0])
    run_key = machine["run_key"]
    attempt_repo = repo / ".belgi" / "store" / "runs" / run_key / "attempt-0001" / "repo"

    staged_term = attempt_repo / ".belgi" / "engine" / "c3_canonicals" / "terminology.md"
    bundled_term = attempt_repo / "out" / "bundle" / "terminology.md"
    assert not staged_term.exists()
    assert bundled_term.is_file()

    engine_bytes = _builtin_canonical_bytes("terminology.md")
    assert bundled_term.read_bytes() == engine_bytes
    assert bundled_term.read_bytes() != b"ADOPTER COLLISION\n"


def test_manual_c3_run_succeeds_without_staged_canonicals_after_belgi_run(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = _init_min_git_repo(tmp_path)

    rc_init = belgi_main(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()

    rc_run = belgi_main(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", _head_sha(repo)])
    captured = capsys.readouterr()
    assert rc_run == 0, captured.err
    machine = json.loads(captured.out.splitlines()[0])
    run_key = machine["run_key"]

    attempt_repo = repo / ".belgi" / "store" / "runs" / run_key / "attempt-0001" / "repo"
    staged_root = attempt_repo / ".belgi" / "engine" / "c3_canonicals"
    if staged_root.exists():
        shutil.rmtree(staged_root)
    assert not staged_root.exists()

    cp_manual = subprocess.run(
        [
            sys.executable,
            "-m",
            "chain.compiler_c3_docs",
            "--repo",
            str(attempt_repo),
            "--locked-spec",
            "out/LockedSpec.json",
            "--gate-q-verdict",
            "out/GateVerdict.Q.json",
            "--gate-r-verdict",
            "out/GateVerdict.R.json",
            "--r-snapshot-manifest",
            "out/EvidenceManifest.r_snapshot.json",
            "--out-final-manifest",
            "out/manual/EvidenceManifest.final.json",
            "--out-log",
            "docs/docs_compilation_log.json",
            "--out-docs",
            "out/manual/docs.md",
            "--out-bundle-dir",
            "out/manual/bundle",
            "--out-bundle-root-sha",
            "out/manual/bundle_root.sha256",
            "--profile",
            "public",
            "--prompt-block-hashes",
            "out/prompt_block_hashes.json",
            "--generated-at",
            "1970-01-01T00:00:00Z",
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    assert cp_manual.returncode == 0, (cp_manual.returncode, cp_manual.stdout, cp_manual.stderr)

    baseline_manifest = json.loads(
        (attempt_repo / "out" / "bundle" / "docs_bundle_manifest.json").read_text(encoding="utf-8", errors="strict")
    )
    manual_manifest = json.loads(
        (attempt_repo / "out" / "manual" / "bundle" / "docs_bundle_manifest.json").read_text(
            encoding="utf-8", errors="strict"
        )
    )
    assert manual_manifest["bundle_sha256"] == baseline_manifest["bundle_sha256"]


def test_manual_c3_rebuilds_stale_staged_cache_for_active_protocol_identity(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = _init_min_git_repo(tmp_path)

    rc_init = belgi_main(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()

    rc_run = belgi_main(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", _head_sha(repo)])
    captured = capsys.readouterr()
    assert rc_run == 0, captured.err
    machine = json.loads(captured.out.splitlines()[0])
    run_key = machine["run_key"]

    attempt_repo = repo / ".belgi" / "store" / "runs" / run_key / "attempt-0001" / "repo"
    baseline_manifest = json.loads(
        (attempt_repo / "out" / "bundle" / "docs_bundle_manifest.json").read_text(encoding="utf-8", errors="strict")
    )
    locked = json.loads((attempt_repo / "out" / "LockedSpec.json").read_text(encoding="utf-8", errors="strict"))
    protocol_pack = locked.get("protocol_pack")
    assert isinstance(protocol_pack, dict)

    staged_root = attempt_repo / ".belgi" / "engine" / "c3_canonicals"
    if staged_root.exists():
        shutil.rmtree(staged_root)
    staged_root.mkdir(parents=True, exist_ok=True)
    (staged_root / "CANONICALS.md").write_text("STALE CACHE\n", encoding="utf-8", errors="strict")
    (staged_root / "terminology.md").write_text("STALE CACHE\n", encoding="utf-8", errors="strict")
    (staged_root / ".cache_meta.json").write_text(
        json.dumps(
            {
                "protocol_pack_id": "0" * 64,
                "protocol_pack_manifest_sha256": "1" * 64,
                "protocol_pack_name": "stale-pack",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        errors="strict",
    )

    cp_manual = subprocess.run(
        [
            sys.executable,
            "-m",
            "chain.compiler_c3_docs",
            "--repo",
            str(attempt_repo),
            "--locked-spec",
            "out/LockedSpec.json",
            "--gate-q-verdict",
            "out/GateVerdict.Q.json",
            "--gate-r-verdict",
            "out/GateVerdict.R.json",
            "--r-snapshot-manifest",
            "out/EvidenceManifest.r_snapshot.json",
            "--out-final-manifest",
            "out/rebuilt/EvidenceManifest.final.json",
            "--out-log",
            "docs/docs_compilation_log.json",
            "--out-docs",
            "out/rebuilt/docs.md",
            "--out-bundle-dir",
            "out/rebuilt/bundle",
            "--out-bundle-root-sha",
            "out/rebuilt/bundle_root.sha256",
            "--profile",
            "public",
            "--prompt-block-hashes",
            "out/prompt_block_hashes.json",
            "--generated-at",
            "1970-01-01T00:00:00Z",
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    assert cp_manual.returncode == 0, (cp_manual.returncode, cp_manual.stdout, cp_manual.stderr)

    rebuilt_manifest = json.loads(
        (attempt_repo / "out" / "rebuilt" / "bundle" / "docs_bundle_manifest.json").read_text(
            encoding="utf-8", errors="strict"
        )
    )
    assert rebuilt_manifest["bundle_sha256"] == baseline_manifest["bundle_sha256"]

    cache_meta = json.loads((staged_root / ".cache_meta.json").read_text(encoding="utf-8", errors="strict"))
    assert cache_meta == {
        "protocol_pack_id": protocol_pack.get("pack_id"),
        "protocol_pack_manifest_sha256": protocol_pack.get("manifest_sha256"),
        "protocol_pack_name": protocol_pack.get("pack_name"),
    }
    assert (staged_root / "terminology.md").read_bytes() == _builtin_canonical_bytes("terminology.md")
