from __future__ import annotations

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
for _k in list(sys.modules.keys()):
    if _k == "belgi" or _k.startswith("belgi."):
        del sys.modules[_k]

from belgi.core.hash import sha256_bytes
from chain.compiler_c3_docs import _compute_bundle_root_sha256, _compute_bundle_sha256


def _fixture_bundled_files(*, manifest_entry_sha: str) -> list[dict[str, object]]:
    return [
        {
            "path": "zeta.md",
            "sha256": "f" * 64,
            "size_bytes": 7,
            "media_type": "text/markdown; charset=utf-8",
        },
        {
            "path": "docs_bundle_manifest.json",
            "sha256": manifest_entry_sha,
            "size_bytes": 11,
            "media_type": "application/json",
        },
        {
            "path": "alpha.md",
            "sha256": "1" * 64,
            "size_bytes": 8,
            "media_type": "text/markdown; charset=utf-8",
        },
        {
            "path": "TOC.md",
            "sha256": "2" * 64,
            "size_bytes": 9,
            "media_type": "text/markdown; charset=utf-8",
        },
    ]


def test_c3_bundle_sha256_fixture_contract_is_sorted_and_non_circular() -> None:
    bundled_files = _fixture_bundled_files(manifest_entry_sha="0" * 64)
    got = _compute_bundle_sha256(bundled_files=bundled_files)

    expected_payload = (
        "TOC.md\n"
        + ("2" * 64)
        + "\n"
        + "alpha.md\n"
        + ("1" * 64)
        + "\n"
        + "zeta.md\n"
        + ("f" * 64)
        + "\n"
    ).encode("utf-8", errors="strict")
    expected = sha256_bytes(expected_payload)
    assert got == expected

    # Manifest-entry hash changes must not affect bundle_sha256.
    bundled_files_manifest_changed = _fixture_bundled_files(manifest_entry_sha="9" * 64)
    assert _compute_bundle_sha256(bundled_files=bundled_files_manifest_changed) == got


def test_c3_bundle_root_sha256_fixture_contract() -> None:
    bundle_sha256 = _compute_bundle_sha256(bundled_files=_fixture_bundled_files(manifest_entry_sha="0" * 64))
    manifest_sha256 = "a" * 64

    got = _compute_bundle_root_sha256(
        docs_bundle_manifest_sha256=manifest_sha256,
        bundle_sha256=bundle_sha256,
    )

    expected_payload = f"manifest\n{manifest_sha256}\nbundle\n{bundle_sha256}\n".encode(
        "utf-8", errors="strict"
    )
    assert got == sha256_bytes(expected_payload)


def test_docs_compiler_template_hash_contract_guard() -> None:
    template = (REPO_ROOT / "belgi" / "templates" / "DocsCompiler.template.md").read_text(
        encoding="utf-8", errors="strict"
    )
    template_lc = template.lower()

    required_claims = [
        'path == "docs_bundle_manifest.json"` from `bundle_sha256` computation.',
        "Build UTF-8 payload as exact concatenation of `<path>\\n<sha256>\\n` for each sorted entry.",
        '`bundle_root_sha256 = sha256("manifest\\n" + docs_bundle_manifest_sha256 + "\\nbundle\\n" + bundle_sha256 + "\\n")`.',
    ]
    for claim in required_claims:
        assert claim.lower() in template_lc

    stale_claims = [
        "for each file in order: `<sha256>  <path>\\n`",
        'followed by `"MANIFEST\\n" + sha256(manifest_bytes) + "\\n"`',
        "The manifest file itself is part of the bundle and must be included in the file list and hash computation.",
    ]
    for claim in stale_claims:
        assert claim.lower() not in template_lc
