from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
for _k in list(sys.modules.keys()):
    if _k == "belgi" or _k.startswith("belgi."):
        del sys.modules[_k]

import belgi.cli as belgi_cli
from belgi.cli import main as belgi_main


@pytest.mark.parametrize(
    "argv",
    [
        ["stage", "--help"],
        ["stage", "c1", "--help"],
        ["stage", "q", "--help"],
        ["stage", "r", "--help"],
        ["stage", "c3", "--help"],
        ["stage", "s", "--help"],
        ["stage", "s", "seal", "--help"],
        ["stage", "s", "verify", "--help"],
    ],
)
def test_stage_help_surfaces_exit_zero(argv: list[str]) -> None:
    assert belgi_main(argv) == 0


@pytest.mark.parametrize(
    ("argv", "expected_module", "expected_args"),
    [
        (
            ["stage", "c1", "--repo", ".", "--intent-spec", "IntentSpec.core.md", "--out", "out/LockedSpec.json"],
            "chain.compiler_c1_intent",
            ["--repo", ".", "--intent-spec", "IntentSpec.core.md", "--out", "out/LockedSpec.json"],
        ),
        (
            [
                "stage",
                "q",
                "--repo",
                ".",
                "--intent-spec",
                "IntentSpec.core.md",
                "--locked-spec",
                "out/LockedSpec.json",
                "--evidence-manifest",
                "out/EvidenceManifest.json",
                "--out",
                "out/GateVerdict.Q.json",
            ],
            "chain.gate_q_verify",
            [
                "--repo",
                ".",
                "--intent-spec",
                "IntentSpec.core.md",
                "--locked-spec",
                "out/LockedSpec.json",
                "--evidence-manifest",
                "out/EvidenceManifest.json",
                "--out",
                "out/GateVerdict.Q.json",
            ],
        ),
        (
            [
                "stage",
                "r",
                "--repo",
                ".",
                "--locked-spec",
                "out/LockedSpec.json",
                "--gate-q-verdict",
                "out/GateVerdict.Q.json",
                "--evidence-manifest",
                "out/EvidenceManifest.json",
                "--evaluated-revision",
                "0123456789abcdef0123456789abcdef01234567",
                "--out",
                "out/verify_report.R.json",
            ],
            "chain.gate_r_verify",
            [
                "--repo",
                ".",
                "--locked-spec",
                "out/LockedSpec.json",
                "--gate-q-verdict",
                "out/GateVerdict.Q.json",
                "--evidence-manifest",
                "out/EvidenceManifest.json",
                "--evaluated-revision",
                "0123456789abcdef0123456789abcdef01234567",
                "--out",
                "out/verify_report.R.json",
            ],
        ),
        (
            [
                "stage",
                "c3",
                "--repo",
                ".",
                "--locked-spec",
                "out/LockedSpec.json",
                "--gate-q-verdict",
                "out/GateVerdict.Q.json",
                "--gate-r-verdict",
                "out/GateVerdict.R.json",
                "--r-snapshot-manifest",
                "out/EvidenceManifest.R.json",
                "--out-final-manifest",
                "out/EvidenceManifest.json",
                "--out-docs",
                "docs/chain_of_changes.md",
                "--out-log",
                "docs/docs_compilation_log.json",
                "--out-bundle-dir",
                "out/bundle",
                "--out-bundle-root-sha",
                "out/bundle_root.sha256",
                "--prompt-block-hashes",
                "out/prompt_block_hashes.json",
            ],
            "chain.compiler_c3_docs",
            [
                "--repo",
                ".",
                "--locked-spec",
                "out/LockedSpec.json",
                "--gate-q-verdict",
                "out/GateVerdict.Q.json",
                "--gate-r-verdict",
                "out/GateVerdict.R.json",
                "--r-snapshot-manifest",
                "out/EvidenceManifest.R.json",
                "--out-final-manifest",
                "out/EvidenceManifest.json",
                "--out-docs",
                "docs/chain_of_changes.md",
                "--out-log",
                "docs/docs_compilation_log.json",
                "--out-bundle-dir",
                "out/bundle",
                "--out-bundle-root-sha",
                "out/bundle_root.sha256",
                "--prompt-block-hashes",
                "out/prompt_block_hashes.json",
            ],
        ),
        (
            [
                "stage",
                "s",
                "seal",
                "--repo",
                ".",
                "--locked-spec",
                "out/LockedSpec.json",
                "--gate-q-verdict",
                "out/GateVerdict.Q.json",
                "--gate-r-verdict",
                "out/GateVerdict.R.json",
                "--evidence-manifest",
                "out/EvidenceManifest.json",
                "--final-commit-sha",
                "0123456789abcdef0123456789abcdef01234567",
                "--sealed-at",
                "1970-01-01T00:00:00Z",
                "--signer",
                "human:test@example.com",
                "--out",
                "out/SealManifest.json",
            ],
            "chain.seal_bundle",
            [
                "--repo",
                ".",
                "--locked-spec",
                "out/LockedSpec.json",
                "--gate-q-verdict",
                "out/GateVerdict.Q.json",
                "--gate-r-verdict",
                "out/GateVerdict.R.json",
                "--evidence-manifest",
                "out/EvidenceManifest.json",
                "--final-commit-sha",
                "0123456789abcdef0123456789abcdef01234567",
                "--sealed-at",
                "1970-01-01T00:00:00Z",
                "--signer",
                "human:test@example.com",
                "--out",
                "out/SealManifest.json",
            ],
        ),
        (
            [
                "stage",
                "s",
                "verify",
                "--repo",
                ".",
                "--locked-spec",
                "out/LockedSpec.json",
                "--seal-manifest",
                "out/SealManifest.json",
                "--evidence-manifest",
                "out/EvidenceManifest.json",
                "--out",
                "out/GateVerdict.S.json",
            ],
            "chain.gate_s_verify",
            [
                "--repo",
                ".",
                "--locked-spec",
                "out/LockedSpec.json",
                "--seal-manifest",
                "out/SealManifest.json",
                "--evidence-manifest",
                "out/EvidenceManifest.json",
                "--out",
                "out/GateVerdict.S.json",
            ],
        ),
    ],
)
def test_stage_forwarders_invoke_expected_modules(
    monkeypatch: pytest.MonkeyPatch,
    argv: list[str],
    expected_module: str,
    expected_args: list[str],
) -> None:
    calls: list[tuple[str, list[str]]] = []

    def _fake_invoke(module_name: str, forwarded_args: list[str]) -> int:
        calls.append((module_name, list(forwarded_args)))
        return 0

    monkeypatch.setattr(belgi_cli, "_invoke_module_main", _fake_invoke)
    rc = belgi_main(argv)

    assert rc == 0
    assert calls == [(expected_module, expected_args)]


@pytest.mark.parametrize(
    ("module_rc", "expected_cli_rc"),
    [
        (0, 0),
        (10, 10),
        (2, 20),
        (20, 20),
        (30, 30),
        (3, 20),
        (99, 30),
    ],
)
def test_stage_forwarder_exit_code_normalization(
    monkeypatch: pytest.MonkeyPatch,
    module_rc: int,
    expected_cli_rc: int,
) -> None:
    monkeypatch.setattr(belgi_cli, "_invoke_module_main", lambda _m, _a: module_rc)

    rc = belgi_main(["stage", "q", "--repo", "."])
    assert rc == expected_cli_rc


def test_stage_missing_args_is_user_error_with_help_pointer(capsys: pytest.CaptureFixture[str]) -> None:
    rc = belgi_main(["stage", "r"])
    captured = capsys.readouterr()

    assert rc == 20
    lines = captured.out.splitlines()
    assert lines, "expected machine result output"
    payload = json.loads(lines[0])
    assert payload["verdict"] == "NO-GO"
    assert "belgi stage r --help" in str(payload["primary_reason"])


def test_stage_rc2_prints_help_remediation(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(belgi_cli, "_invoke_module_main", lambda _m, _a: 2)

    rc = belgi_main(["stage", "q", "--repo", "."])
    captured = capsys.readouterr()

    assert rc == 20
    assert "[belgi stage q] Remediation: run `belgi stage q --help`." in captured.err


def test_stage_missing_chain_module_is_user_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def _raise_missing(_module_name: str) -> object:
        raise ModuleNotFoundError("No module named 'chain'")

    monkeypatch.setattr(belgi_cli.importlib, "import_module", _raise_missing)

    rc = belgi_main(["stage", "q", "--repo", "."])
    captured = capsys.readouterr()

    assert rc == 20
    lines = captured.out.splitlines()
    assert lines, "expected machine result output"
    payload = json.loads(lines[0])
    assert isinstance(payload.get("primary_reason"), str)
    assert "repo-local stage module missing" in payload["primary_reason"]
    assert "python -m chain." in payload["primary_reason"]
