from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read_text(relpath: str) -> str:
    return (REPO_ROOT / relpath).read_text(encoding="utf-8", errors="strict")


def test_promptbundle_template_removes_tier_pack_exact_bytes_claim() -> None:
    text_lc = _read_text("belgi/templates/PromptBundle.blocks.md").lower()
    assert "`../../tiers/tier-packs.json` as exact bytes at the evaluated repo revision." not in text_lc
    assert "c1 determinism must not depend on raw `tiers/tier-packs.json` byte identity." in text_lc


def test_docscompiler_template_routes_per_file_hashes_to_manifest() -> None:
    text_lc = _read_text("belgi/templates/DocsCompiler.template.md").lower()
    assert "for each file: normalized output hash" not in text_lc
    assert (
        "per-file normalized output hashes are published via `bundle/docs_bundle_manifest.json` (`files[]`"
        " path+sha256); they are not required as direct fields in the `docs_compilation_log` payload."
    ) in text_lc


def test_running_belgi_docs_require_canonical_out_log_path() -> None:
    text_lc = _read_text("docs/operations/running-belgi.md").lower()
    assert "`--out-log` must be exactly `docs/docs_compilation_log.json`." in text_lc
    assert "this fixed path is required for deterministic discovery and evidence indexability." in text_lc
