from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read_text(relpath: str) -> str:
    return (REPO_ROOT / relpath).read_text(encoding="utf-8", errors="strict")


def test_promptbundle_template_removes_tier_pack_exact_bytes_claim() -> None:
    text = _read_text("belgi/templates/PromptBundle.blocks.md")
    text_lc = text.lower()
    assert "`../../tiers/tier-packs.json` as exact bytes at the evaluated repo revision." not in text_lc
    assert "resolved from `../../tiers/tier-packs.json`" not in text_lc

    a31_start = text_lc.index("### a3.1")
    a32_start = text_lc.index("### a3.2")
    a31 = text_lc[a31_start:a32_start]
    assert "tier policy values are selected by `lockedspec.tier.tier_id`" in a31
    assert (
        "c1 determinism must not depend on reading `tiers/tier-packs.json` from the evaluated repo revision."
        in a31
    )
    tier_lines = [ln.strip() for ln in a31.splitlines() if "tiers/tier-packs.json" in ln]
    assert tier_lines == [
        "- c1 determinism must not depend on reading `tiers/tier-packs.json` from the evaluated repo revision."
    ]


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


def test_prompt_hash_contract_explicitly_requires_c1_rendered_bytes_hashes() -> None:
    required_a = "Each hash MUST equal `sha256(C1_rendered_block_bytes)` for the selected prompt blocks."
    required_b = "C3 recomputes expected hashes by rendering the selected prompt blocks and rejects mismatches."

    running_docs = _read_text("docs/operations/running-belgi.md")
    mirror_docs = _read_text("belgi/canonicals/docs/operations/running-belgi.md")
    c3_template = _read_text("belgi/templates/DocsCompiler.template.md")

    for text in (running_docs, mirror_docs, c3_template):
        assert required_a in text
        assert required_b in text
