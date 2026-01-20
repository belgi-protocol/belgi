from __future__ import annotations

import ast
import copy
import json
from pathlib import Path
import sys

import pytest

pytestmark = pytest.mark.repo_local


def _import_local_core() -> tuple[object, object]:
    """Force imports to resolve from this repo, not site-packages."""

    root = _repo_root()
    sys.path.insert(0, str(root))
    # If an installed 'belgi' is already imported, nuke it so local wins.
    sys.modules.pop("belgi", None)

    from belgi.core.jail import normalize_repo_rel, normalize_repo_rel_path  # type: ignore
    from belgi.core.schema import parse_rfc3339, validate_schema  # type: ignore

    return (
        (normalize_repo_rel, normalize_repo_rel_path),
        (parse_rfc3339, validate_schema),
    )


def _repo_root() -> Path:
    # tests/ lives at repo_root/tests
    return Path(__file__).resolve().parents[1]


def test_protocol_pack_is_data_only_no_py() -> None:
    root = _repo_root()
    pack_root = root / "belgi" / "_protocol_packs"
    assert pack_root.exists() and pack_root.is_dir()

    offenders: list[str] = []
    for p in sorted(pack_root.rglob("*.py")):
        offenders.append(p.relative_to(root).as_posix())

    assert offenders == [], f"Protocol pack must be data-only; found python files: {offenders}"


def test_no_canonical_imports_from_chain_logic_base() -> None:
    root = _repo_root()

    banned = {
        "parse_rfc3339",
        "validate_schema",
        "sha256_bytes",
        "safe_relpath",
        "resolve_storage_ref",
        "normalize_repo_rel",
        "normalize_repo_rel_path",
        "resolve_repo_rel_path",
        "is_under_prefix",
    }

    offenders: list[str] = []

    for p in sorted(root.rglob("*.py")):
        rel = p.relative_to(root).as_posix()
        if rel.startswith((
            "build/",
            "belgi.egg-info/",
            ".venv/",
            ".venv_packtest/",
            "venv/",
        )) or "/site-packages/" in rel:
            continue

        src = p.read_text(encoding="utf-8")
        try:
            tree = ast.parse(src, filename=rel)
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "chain.logic.base":
                for alias in node.names:
                    if alias.name in banned:
                        line = getattr(node, "lineno", "?")
                        offenders.append(f"{rel}:{line} imports {alias.name} from chain.logic.base")

    assert offenders == [], "\n".join(offenders)


@pytest.mark.parametrize(
    "dt",
    [
        "2024-01-02T03:04:05Z",
        "2024-01-02T03:04:05.1Z",
        "2024-01-02T03:04:05.123456789+01:30",
        "2024-12-31T23:59:59-00:00",
    ],
)
def test_parse_rfc3339_accepts_strict(dt: str) -> None:
    _, (parse_rfc3339, _validate_schema) = _import_local_core()
    parse_rfc3339(dt)


@pytest.mark.parametrize(
    "dt",
    [
        "2024-01-02 03:04:05Z",  # space separator
        "2024-01-02T03:04Z",  # missing seconds
        "2024-01-02T03:04:05+0100",  # missing colon in offset
        "2024-01-02T03:04:05",  # missing timezone
        "2024-01-02T03:04:05Z ",  # trailing whitespace
    ],
)
def test_parse_rfc3339_rejects_invalid(dt: str) -> None:
    _, (parse_rfc3339, _validate_schema) = _import_local_core()
    with pytest.raises(ValueError):
        parse_rfc3339(dt)


def test_normalize_repo_rel_rejects_dot_and_double_slash() -> None:
    (normalize_repo_rel, _), (_parse_rfc3339, _validate_schema) = _import_local_core()
    with pytest.raises(ValueError):
        normalize_repo_rel("./a", allow_backslashes=False)
    with pytest.raises(ValueError):
        normalize_repo_rel("a//b", allow_backslashes=False)
    with pytest.raises(ValueError):
        normalize_repo_rel("a/./b", allow_backslashes=False)


def test_normalize_repo_rel_path_strict_policy() -> None:
    (_, normalize_repo_rel_path), (_parse_rfc3339, _validate_schema) = _import_local_core()
    assert normalize_repo_rel_path("a/b/c.txt") == "a/b/c.txt"

    for bad in ["/abs", "a\\b", "a/*", "a:?", "a://b", "a//b", "./a", "a/../b", "a/./b"]:
        with pytest.raises(ValueError):
            normalize_repo_rel_path(bad)


def test_exactly_one_implementation_locations() -> None:
    root = _repo_root()

    def find_def_files(func_name: str) -> list[str]:
        hits: list[str] = []
        for p in sorted(root.rglob("*.py")):
            rel = p.relative_to(root).as_posix()
            if rel.startswith((
                "build/",
                "belgi.egg-info/",
                ".venv/",
                ".venv_packtest/",
                "venv/",
            )) or "/site-packages/" in rel:
                continue
            src = p.read_text(encoding="utf-8", errors="strict")
            try:
                tree = ast.parse(src, filename=rel)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name == func_name:
                    hits.append(rel)
                    break
        return hits

    assert find_def_files("normalize_repo_rel_path") == ["belgi/core/jail.py"]
    assert find_def_files("parse_rfc3339") == ["belgi/core/schema.py"]


def test_schema_strictness_additional_properties_rejected() -> None:
    """Unknown fields MUST fail for schemas with additionalProperties=false."""

    root = _repo_root()
    _, (_parse_rfc3339, validate_schema) = _import_local_core()

    schema = json.loads((root / "schemas" / "EvidenceManifest.schema.json").read_text(encoding="utf-8"))
    em = json.loads(
        (root / "policy" / "fixtures" / "public" / "gate_r" / "r_pass_tier1" / "EvidenceManifest.json").read_text(
            encoding="utf-8"
        )
    )

    assert validate_schema(em, schema, root_schema=schema, path="EvidenceManifest") == []

    em_extra = copy.deepcopy(em)
    assert isinstance(em_extra, dict)
    em_extra["_unexpected"] = "boom"

    errs = validate_schema(em_extra, schema, root_schema=schema, path="EvidenceManifest")
    assert any(e.message == "additionalProperties not allowed" for e in errs), errs


def test_schema_strictness_sha256_pattern_enforced() -> None:
    """Hash formats MUST be enforced (sha256 hex)."""

    root = _repo_root()
    _, (_parse_rfc3339, validate_schema) = _import_local_core()

    schema = json.loads((root / "schemas" / "EvidenceManifest.schema.json").read_text(encoding="utf-8"))
    em = json.loads(
        (root / "policy" / "fixtures" / "public" / "gate_r" / "r_pass_tier1" / "EvidenceManifest.json").read_text(
            encoding="utf-8"
        )
    )

    em_bad = copy.deepcopy(em)
    assert isinstance(em_bad, dict)
    artifacts = em_bad.get("artifacts")
    assert isinstance(artifacts, list) and len(artifacts) >= 1
    assert isinstance(artifacts[0], dict)
    artifacts[0]["hash"] = "not-a-sha"

    errs = validate_schema(em_bad, schema, root_schema=schema, path="EvidenceManifest")
    assert any("pattern mismatch" in e.message for e in errs), errs


def test_schema_strictness_datetime_format_enforced() -> None:
    """Timestamp formats MUST be enforced (RFC3339 + schema pattern)."""

    root = _repo_root()
    _, (_parse_rfc3339, validate_schema) = _import_local_core()

    schema = json.loads((root / "schemas" / "GateVerdict.schema.json").read_text(encoding="utf-8"))
    gv = json.loads(
        (root / "policy" / "fixtures" / "public" / "gate_s" / "s_pass_tier1_unsigned" / "GateVerdict.R.json").read_text(
            encoding="utf-8"
        )
    )
    assert validate_schema(gv, schema, root_schema=schema, path="GateVerdict") == []

    gv_bad = copy.deepcopy(gv)
    assert isinstance(gv_bad, dict)
    gv_bad["evaluated_at"] = "2000-01-01"  # missing time + timezone

    errs = validate_schema(gv_bad, schema, root_schema=schema, path="GateVerdict")
    assert any(("pattern mismatch" in e.message) or ("invalid date-time" in e.message) for e in errs), errs


def test_schema_strictness_gate_verdict_additional_properties_rejected() -> None:
    """GateVerdict is strict: unknown fields MUST fail."""

    root = _repo_root()
    _, (_parse_rfc3339, validate_schema) = _import_local_core()

    schema = json.loads((root / "schemas" / "GateVerdict.schema.json").read_text(encoding="utf-8"))
    gv = json.loads(
        (root / "policy" / "fixtures" / "public" / "gate_s" / "s_pass_tier1_unsigned" / "GateVerdict.R.json").read_text(
            encoding="utf-8"
        )
    )

    gv_extra = copy.deepcopy(gv)
    assert isinstance(gv_extra, dict)
    gv_extra["_unexpected"] = True

    errs = validate_schema(gv_extra, schema, root_schema=schema, path="GateVerdict")
    assert any(e.message == "additionalProperties not allowed" for e in errs), errs
