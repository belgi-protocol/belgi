from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1] / ".github" / "scripts" / "check_external_action_pins.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location("check_external_action_pins_script", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_guard_accepts_sha_pinned_external_refs_and_local_refs(tmp_path: Path) -> None:
    module = _load_module()
    workflow = tmp_path / ".github" / "workflows" / "example.yml"
    action = tmp_path / ".github" / "actions" / "demo" / "action.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    action.parent.mkdir(parents=True, exist_ok=True)

    workflow.write_text(
        "\n".join(
            [
                "jobs:",
                "  test:",
                "    steps:",
                "      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
                "      - uses: actions/download-artifact@fa0a91b85d4f404e444e00e005971372dc801d16",
                "      - uses: ./.github/actions/demo",
                "      - uses: owner/repo/.github/workflows/reusable.yml@0123456789abcdef0123456789abcdef01234567",
            ]
        )
        + "\n",
        encoding="utf-8",
        errors="strict",
    )
    action.write_text(
        "runs:\n  using: composite\n  steps:\n    - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065\n",
        encoding="utf-8",
        errors="strict",
    )

    assert module.find_floating_external_action_refs(tmp_path) == []


def test_guard_rejects_floating_external_refs(tmp_path: Path) -> None:
    module = _load_module()
    workflow = tmp_path / ".github" / "workflows" / "example.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(
        "\n".join(
            [
                "jobs:",
                "  test:",
                "    steps:",
                "      - uses: actions/checkout@v4",
                "      - uses: actions/download-artifact@v4",
                "      - uses: actions/upload-artifact@main",
                "      - uses: docker://alpine:3.20",
            ]
        )
        + "\n",
        encoding="utf-8",
        errors="strict",
    )

    assert module.find_floating_external_action_refs(tmp_path) == [
        (".github/workflows/example.yml", 4, "actions/checkout@v4"),
        (".github/workflows/example.yml", 5, "actions/download-artifact@v4"),
        (".github/workflows/example.yml", 6, "actions/upload-artifact@main"),
    ]
