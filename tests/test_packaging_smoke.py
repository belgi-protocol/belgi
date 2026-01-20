"""Packaging smoke tests: verify protocol pack and assets ship correctly in installed package.

These tests verify that:
1. get_builtin_protocol_context() works without repo files
2. Protocol pack files are readable and correctly structured
3. Schemas, gates, and tiers are all present and loadable
4. Critical failure taxonomy categories exist
5. Templates are readable (for C3 compiler)
6. No repo shadowing when run from temp dir

Note: These tests run against the installed package (or editable install).
For full wheel verification, use the wheel-smoke CI job or build locally.

IMPORTANT: These tests should pass when run from ANY directory, including
a temp directory with no access to the repo. This proves the package is
self-contained.
"""
from __future__ import annotations

import os
import pathlib
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
for _k in list(sys.modules.keys()):
    if _k == "belgi" or _k.startswith("belgi."):
        del sys.modules[_k]

from belgi.protocol.pack import get_builtin_protocol_context


def test_no_repo_shadowing() -> None:
    """Verify belgi is not loaded from repo when CI env is set."""
    if os.getenv("BELGI_ENFORCE_NO_SHADOWING") != "1":
        pytest.skip("shadowing check enforced only in wheel-smoke")

    import belgi
    
    belgi_path = pathlib.Path(belgi.__file__).resolve()
    workspace = os.environ.get("GITHUB_WORKSPACE", "")
    
    # Only enforce in CI (when GITHUB_WORKSPACE is set)
    if workspace:
        workspace_path = pathlib.Path(workspace).resolve()
        assert workspace_path not in belgi_path.parents, (
            f"belgi loaded from repo (shadowing detected): {belgi_path}"
        )


def test_builtin_protocol_context_loads() -> None:
    """Verify builtin protocol context loads successfully."""
    ctx = get_builtin_protocol_context()

    assert ctx.pack_id, "pack_id must not be empty"
    assert len(ctx.pack_id) == 64, "pack_id must be 64 hex chars"
    assert ctx.manifest_sha256, "manifest_sha256 must not be empty"
    assert len(ctx.manifest_sha256) == 64, "manifest_sha256 must be 64 hex chars"
    assert ctx.pack_name == "belgi-protocol-pack-v1", f"unexpected pack_name: {ctx.pack_name}"
    assert ctx.source == "builtin", f"unexpected source: {ctx.source}"


def test_protocol_pack_manifest_structure() -> None:
    """Verify manifest has expected structure."""
    ctx = get_builtin_protocol_context()
    manifest = ctx.manifest

    assert isinstance(manifest, dict), "manifest must be a dict"
    assert manifest.get("pack_format_version") == 1
    assert manifest.get("pack_name") == "belgi-protocol-pack-v1"
    assert isinstance(manifest.get("files"), list), "manifest.files must be a list"
    assert len(manifest["files"]) > 0, "manifest.files must not be empty"
    
    # Verify files list structure
    for f in manifest["files"]:
        assert isinstance(f.get("relpath"), str), "file.relpath must be string"
        assert isinstance(f.get("sha256"), str), "file.sha256 must be string"
        assert len(f.get("sha256", "")) == 64, "file.sha256 must be 64 hex chars"
        assert isinstance(f.get("size_bytes"), int), "file.size_bytes must be int"


def test_all_schemas_loadable() -> None:
    """Verify all schema files in manifest are loadable JSON."""
    ctx = get_builtin_protocol_context()

    schema_files = [
        "schemas/IntentSpec.schema.json",
        "schemas/LockedSpec.schema.json",
        "schemas/EvidenceManifest.schema.json",
        "schemas/GateVerdict.schema.json",
        "schemas/SealManifest.schema.json",
        "schemas/Waiver.schema.json",
        "schemas/HOTLApproval.schema.json",
        "schemas/PolicyReportPayload.schema.json",
        "schemas/TestReportPayload.schema.json",
        "schemas/EnvAttestationPayload.schema.json",
        "schemas/DocsCompilationLogPayload.schema.json",
        "schemas/GenesisSealPayload.schema.json",
    ]
    
    for schema_path in schema_files:
        schema = ctx.read_json(schema_path)
        assert isinstance(schema, dict), f"{schema_path} must be a JSON object"
        assert "$schema" in schema or "type" in schema, f"{schema_path} must have $schema or type"


def test_failure_taxonomy_has_required_categories() -> None:
    """Verify failure taxonomy has all required protocol identity categories."""
    ctx = get_builtin_protocol_context()
    taxonomy = ctx.read_text("gates/failure-taxonomy.md")

    # Protocol identity mismatch categories (added in pack-truth implementation)
    required_categories = [
        "FQ-PROTOCOL-IDENTITY-MISMATCH",
        "FR-PROTOCOL-IDENTITY-MISMATCH",
        "FS-PROTOCOL-IDENTITY-MISMATCH",
    ]
    
    for cat in required_categories:
        assert cat in taxonomy, f"failure-taxonomy.md missing category: {cat}"


def test_tier_packs_loadable() -> None:
    """Verify tier-packs.md is readable."""
    ctx = get_builtin_protocol_context()
    tiers = ctx.read_text("tiers/tier-packs.md")
    
    assert "tier-0" in tiers.lower() or "tier 0" in tiers.lower(), "tier-packs.md must mention tier-0"
    assert len(tiers) > 100, "tier-packs.md seems too short"


def test_tier_packs_json_loadable() -> None:
    """Verify tier-packs.json (canonical SSOT) is readable."""
    ctx = get_builtin_protocol_context()
    data = ctx.read_text("tiers/tier-packs.json")
    # Cheap structural smoke checks (not schema validation).
    assert "\"tier-0\"" in data and "\"tier-3\"" in data, "tier-packs.json must include tier ids"
    assert "\"tiers\"" in data, "tier-packs.json must include tiers map"

def test_gate_docs_loadable() -> None:
    """Verify all gate documentation files are readable."""
    ctx = get_builtin_protocol_context()
    
    gate_docs = [
        "gates/GATE_Q.md",
        "gates/GATE_R.md",
        "gates/GATE_S.md",
    ]
    
    for doc in gate_docs:
        content = ctx.read_text(doc)
        assert len(content) > 100, f"{doc} seems too short"


def test_lockedspec_schema_has_protocol_pack_field() -> None:
    """Verify LockedSpec schema requires protocol_pack field."""
    ctx = get_builtin_protocol_context()
    schema = ctx.read_json("schemas/LockedSpec.schema.json")
    
    required = schema.get("required", [])
    assert "protocol_pack" in required, "LockedSpec.schema.json must require protocol_pack field"
    
    props = schema.get("properties", {})
    assert "protocol_pack" in props, "LockedSpec.schema.json must define protocol_pack property"
    
    pp_props = props["protocol_pack"].get("properties", {})
    assert "pack_id" in pp_props, "protocol_pack must have pack_id property"
    assert "manifest_sha256" in pp_props, "protocol_pack must have manifest_sha256 property"
    assert "pack_name" in pp_props, "protocol_pack must have pack_name property"
    assert "source" in pp_props, "protocol_pack must have source property"


def test_templates_readable() -> None:
    """Verify templates under belgi/templates are readable (used by C3 compiler)."""
    from importlib.resources import as_file, files
    
    templates_traversable = files("belgi").joinpath("templates")
    
    required_templates = [
        "DocsCompiler.template.md",
        "IntentSpec.core.template.md",
    ]
    
    with as_file(templates_traversable) as templates_root:
        for tpl in required_templates:
            content = (templates_root / tpl).read_bytes().decode("utf-8")
            assert len(content) > 50, f"{tpl} seems too short"


def test_builtin_manifest_validates_against_tree() -> None:
    """Verify builtin pack manifest validates against its file tree.
    
    This is the core integrity check: the manifest must match the actual
    files shipped in the wheel.
    
    Uses as_file() to get a real Path that works with validate_manifest_bytes,
    which is robust for both filesystem and zip-based resource loaders.
    """
    from importlib.resources import as_file, files

    from belgi.protocol.pack import MANIFEST_FILENAME, validate_manifest_bytes
    
    pack_traversable = files("belgi").joinpath("_protocol_packs", "v1")
    with as_file(pack_traversable) as pack_root:
        manifest_bytes = (pack_root / MANIFEST_FILENAME).read_bytes()
        # This will raise if manifest doesn't match tree
        validate_manifest_bytes(pack_root=pack_root, manifest_bytes=manifest_bytes)


def test_cli_module_importable() -> None:
    """Verify belgi.cli module is importable (console_scripts entrypoint)."""
    from belgi import cli
    
    assert hasattr(cli, "main"), "belgi.cli must have main() function"
    assert callable(cli.main), "belgi.cli.main must be callable"
