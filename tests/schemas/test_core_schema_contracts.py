from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from tests.helpers.repo_imports import import_fresh_core_surface

pytestmark = pytest.mark.repo_local


def _import_local_core() -> tuple[object, object]:
    core = import_fresh_core_surface()
    return (
        (core.normalize_repo_rel, core.normalize_repo_rel_path),
        (core.parse_rfc3339, core.validate_schema),
    )


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _sample_evidence_manifest() -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "run_id": "sample-run",
        "artifacts": [
            {
                "kind": "diff",
                "id": "repo.diff",
                "hash": "a" * 64,
                "media_type": "text/x-diff",
                "produced_by": "C2",
                "storage_ref": "out/repo.diff.patch",
            }
        ],
        "commands_executed": [],
        "envelope_attestation": None,
    }


def _sample_gate_verdict() -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "run_id": "sample-run",
        "gate_id": "R",
        "verdict": "GO",
        "failure_category": None,
        "failures": [],
        "evidence_manifest_ref": {
            "id": "evidence",
            "hash": "b" * 64,
            "storage_ref": "out/EvidenceManifest.json",
        },
        "evaluated_at": "1970-01-01T00:00:00Z",
        "evaluator": "chain/gate_r_verify.py",
    }


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
        "2024-01-02 03:04:05Z",
        "2024-01-02T03:04Z",
        "2024-01-02T03:04:05+0100",
        "2024-01-02T03:04:05",
        "2024-01-02T03:04:05Z ",
    ],
)
def test_parse_rfc3339_rejects_invalid(dt: str) -> None:
    _, (parse_rfc3339, _validate_schema) = _import_local_core()
    with pytest.raises(ValueError):
        parse_rfc3339(dt)


def test_schema_strictness_additional_properties_rejected() -> None:
    root = _repo_root()
    _, (_parse_rfc3339, validate_schema) = _import_local_core()

    schema = json.loads((root / "schemas" / "EvidenceManifest.schema.json").read_text(encoding="utf-8"))
    em = _sample_evidence_manifest()

    assert validate_schema(em, schema, root_schema=schema, path="EvidenceManifest") == []

    em_extra = copy.deepcopy(em)
    assert isinstance(em_extra, dict)
    em_extra["_unexpected"] = "boom"

    errs = validate_schema(em_extra, schema, root_schema=schema, path="EvidenceManifest")
    assert any(e.message == "additionalProperties not allowed" for e in errs), errs


def test_schema_strictness_sha256_pattern_enforced() -> None:
    root = _repo_root()
    _, (_parse_rfc3339, validate_schema) = _import_local_core()

    schema = json.loads((root / "schemas" / "EvidenceManifest.schema.json").read_text(encoding="utf-8"))
    em = _sample_evidence_manifest()

    em_bad = copy.deepcopy(em)
    assert isinstance(em_bad, dict)
    artifacts = em_bad.get("artifacts")
    assert isinstance(artifacts, list) and len(artifacts) >= 1
    assert isinstance(artifacts[0], dict)
    artifacts[0]["hash"] = "not-a-sha"

    errs = validate_schema(em_bad, schema, root_schema=schema, path="EvidenceManifest")
    assert any("pattern mismatch" in e.message for e in errs), errs


def test_schema_strictness_datetime_format_enforced() -> None:
    root = _repo_root()
    _, (_parse_rfc3339, validate_schema) = _import_local_core()

    schema = json.loads((root / "schemas" / "GateVerdict.schema.json").read_text(encoding="utf-8"))
    gv = _sample_gate_verdict()
    assert validate_schema(gv, schema, root_schema=schema, path="GateVerdict") == []

    gv_bad = copy.deepcopy(gv)
    assert isinstance(gv_bad, dict)
    gv_bad["evaluated_at"] = "2000-01-01"

    errs = validate_schema(gv_bad, schema, root_schema=schema, path="GateVerdict")
    assert any(("pattern mismatch" in e.message) or ("invalid date-time" in e.message) for e in errs), errs


def test_schema_strictness_gate_verdict_additional_properties_rejected() -> None:
    root = _repo_root()
    _, (_parse_rfc3339, validate_schema) = _import_local_core()

    schema = json.loads((root / "schemas" / "GateVerdict.schema.json").read_text(encoding="utf-8"))
    gv = _sample_gate_verdict()

    gv_extra = copy.deepcopy(gv)
    assert isinstance(gv_extra, dict)
    gv_extra["_unexpected"] = True

    errs = validate_schema(gv_extra, schema, root_schema=schema, path="GateVerdict")
    assert any(e.message == "additionalProperties not allowed" for e in errs), errs
