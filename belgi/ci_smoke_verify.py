from __future__ import annotations

import os
import pathlib
import sys


def _fail(msg: str) -> int:
    print(msg, file=sys.stderr)
    return 1


def check_no_shadowing() -> int:
    import belgi

    belgi_path = pathlib.Path(belgi.__file__).resolve()
    workspace = os.environ.get("GITHUB_WORKSPACE", "")

    if workspace:
        workspace_path = pathlib.Path(workspace).resolve()
        if workspace_path in belgi_path.parents:
            return _fail(f"FAIL: belgi loaded from repo (shadowing): {belgi_path}")

    print(f"OK: belgi loaded from: {belgi_path}")
    return 0


def verify_builtin_pack() -> int:
    from importlib.resources import as_file, files

    from belgi.protocol.pack import (
        MANIFEST_FILENAME,
        get_builtin_protocol_context,
        validate_manifest_bytes,
    )

    ctx = get_builtin_protocol_context()

    if not ctx.pack_id:
        return _fail("FAIL: pack_id empty")
    if not ctx.manifest_sha256:
        return _fail("FAIL: manifest_sha256 empty")
    if ctx.pack_name != "belgi-protocol-pack-v1":
        return _fail(f"FAIL: unexpected pack_name: {ctx.pack_name}")
    if ctx.source != "builtin":
        return _fail(f"FAIL: unexpected source: {ctx.source}")

    taxonomy = ctx.read_text("gates/failure-taxonomy.md")
    if "FQ-PROTOCOL-IDENTITY-MISMATCH" not in taxonomy:
        return _fail("FAIL: taxonomy missing FQ-PROTOCOL-IDENTITY-MISMATCH")

    pack_traversable = files("belgi").joinpath("_protocol_packs", "v1")
    with as_file(pack_traversable) as pack_root:
        manifest_bytes = (pack_root / MANIFEST_FILENAME).read_bytes()
        validate_manifest_bytes(pack_root=pack_root, manifest_bytes=manifest_bytes)

    print(f"OK: builtin pack verified (pack_id={ctx.pack_id[:16]}...)")
    return 0


def verify_templates() -> int:
    from importlib.resources import as_file, files

    templates_traversable = files("belgi").joinpath("templates")
    with as_file(templates_traversable) as templates_root:
        for tpl in ["DocsCompiler.template.md", "IntentSpec.core.template.md"]:
            content = (templates_root / tpl).read_bytes()
            if len(content) <= 50:
                return _fail(f"FAIL: {tpl} too short or missing")

    print("OK: templates verified")
    return 0


def main() -> int:
    rc = check_no_shadowing()
    if rc:
        return rc
    rc = verify_builtin_pack()
    if rc:
        return rc
    rc = verify_templates()
    if rc:
        return rc
    print("OK: wheel smoke test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
