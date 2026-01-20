"""Tests for repo-root jail and command logging.

These tests verify:
- Path validation rejects escapes, symlinks, absolute paths, NUL bytes, traversal
- Command logging works correctly in both strings and structured modes
- Command matching (command_satisfied) is deterministic and strict
- Behavior is consistent across all validation functions
"""

from __future__ import annotations

import json
import pytest

pytestmark = pytest.mark.repo_local

import os
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
for _k in list(sys.modules.keys()):
    if _k == "belgi" or _k.startswith("belgi."):
        del sys.modules[_k]

from belgi.core.command_log import (
    CommandRecord,
    append_command_to_manifest,
    command_record_to_dict,
    detect_command_log_mode,
    format_command_string,
    make_command_record,
)
from belgi.core.diff_parse import extract_changed_paths_from_diff_bytes
from belgi.core.jail import (
    _is_symlink_or_has_symlink_parent,
    ensure_within_root,
    normalize_repo_rel,
    resolve_repo_rel_path,
    resolve_storage_ref,
)

from chain.logic.base import (
    command_satisfied,
    find_artifacts_by_kind,
    find_artifacts_by_kind_id,
    load_json,
    stable_unique,
)


# ---------------------------------------------------------------------------
# Path jail tests
# ---------------------------------------------------------------------------

class TestNormalizeRepoRel:
    """Tests for normalize_repo_rel path validation."""

    def test_valid_simple_path(self) -> None:
        assert normalize_repo_rel("foo/bar.txt", allow_backslashes=False) == "foo/bar.txt"

    def test_valid_nested_path(self) -> None:
        assert normalize_repo_rel("a/b/c/d.json", allow_backslashes=False) == "a/b/c/d.json"

    def test_backslash_rejected_when_not_allowed(self) -> None:
        with pytest.raises(ValueError, match="separators"):
            normalize_repo_rel("foo\\bar.txt", allow_backslashes=False)

    def test_backslash_converted_when_allowed(self) -> None:
        assert normalize_repo_rel("foo\\bar.txt", allow_backslashes=True) == "foo/bar.txt"

    def test_absolute_path_rejected(self) -> None:
        with pytest.raises(ValueError, match="absolute"):
            normalize_repo_rel("/etc/passwd", allow_backslashes=False)

    def test_drive_path_rejected(self) -> None:
        with pytest.raises(ValueError, match="drive"):
            normalize_repo_rel("C:\\Windows", allow_backslashes=True)

    def test_traversal_rejected(self) -> None:
        with pytest.raises(ValueError, match="\\.\\."):
            normalize_repo_rel("foo/../etc/passwd", allow_backslashes=False)

    def test_nul_byte_rejected(self) -> None:
        with pytest.raises(ValueError, match="NUL"):
            normalize_repo_rel("foo\x00bar", allow_backslashes=False)

    def test_empty_path_rejected(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            normalize_repo_rel("", allow_backslashes=False)

    def test_colon_rejected(self) -> None:
        with pytest.raises(ValueError, match=r"(:|//)"):
            normalize_repo_rel("http://evil.com/file", allow_backslashes=False)

    def test_scheme_rejected(self) -> None:
        with pytest.raises(ValueError, match=r"(:|//)"):
            normalize_repo_rel("file:///etc/passwd", allow_backslashes=False)


class TestResolveRepoRelPath:
    """Tests for resolve_repo_rel_path with symlink hardening."""

    def test_valid_path_resolves(self, tmp_path: Path) -> None:
        (tmp_path / "test.txt").write_text("content")
        result = resolve_repo_rel_path(
            tmp_path, "test.txt",
            must_exist=True, must_be_file=True,
            allow_backslashes=False, forbid_symlinks=True
        )
        assert result.exists()
        assert result.is_file()

    def test_missing_path_fails_when_required(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="missing"):
            resolve_repo_rel_path(
                tmp_path, "nonexistent.txt",
                must_exist=True, must_be_file=True,
                allow_backslashes=False, forbid_symlinks=True
            )

    def test_traversal_escape_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="\\.\\."):
            resolve_repo_rel_path(
                tmp_path, "../escape.txt",
                must_exist=False, allow_backslashes=False, forbid_symlinks=True
            )

    @pytest.mark.skipif(os.name == "nt", reason="Symlink test requires Unix or admin on Windows")
    def test_symlink_rejected(self, tmp_path: Path) -> None:
        target = tmp_path / "target.txt"
        target.write_text("real content")
        link = tmp_path / "link.txt"
        try:
            link.symlink_to(target)
        except OSError:
            pytest.skip("Cannot create symlinks on this system")

        with pytest.raises(ValueError, match="symlink"):
            resolve_repo_rel_path(
                tmp_path, "link.txt",
                must_exist=True, must_be_file=True,
                allow_backslashes=False, forbid_symlinks=True
            )


class TestResolveStorageRef:
    """Tests for resolve_storage_ref (EvidenceManifest storage_ref resolution)."""

    def test_valid_storage_ref(self, tmp_path: Path) -> None:
        (tmp_path / "evidence").mkdir()
        (tmp_path / "evidence" / "report.json").write_text("{}")
        result = resolve_storage_ref(tmp_path, "evidence/report.json")
        assert result.exists()

    def test_absolute_storage_ref_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="repo-relative"):
            resolve_storage_ref(tmp_path, "/etc/passwd")

    def test_traversal_storage_ref_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="\\.\\."):
            resolve_storage_ref(tmp_path, "foo/../../../etc/passwd")

    def test_dot_slash_storage_ref_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="\\./"):
            resolve_storage_ref(tmp_path, "./foo/bar")

    def test_backslash_storage_ref_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="backslash"):
            resolve_storage_ref(tmp_path, "foo\\bar")

    def test_scheme_storage_ref_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="scheme"):
            resolve_storage_ref(tmp_path, "http://evil.com/file")


class TestEnsureWithinRoot:
    """Tests for ensure_within_root boundary enforcement."""

    def test_path_within_root_passes(self, tmp_path: Path) -> None:
        child = tmp_path / "subdir" / "file.txt"
        # Should not raise
        ensure_within_root(tmp_path, child)

    def test_path_escape_fails(self, tmp_path: Path) -> None:
        escape = tmp_path.parent / "escape.txt"
        with pytest.raises(ValueError, match="escapes"):
            ensure_within_root(tmp_path, escape)


# ---------------------------------------------------------------------------
# Command logging tests
# ---------------------------------------------------------------------------

class TestCommandSatisfied:
    """Tests for command_satisfied matching rule."""

    def test_strings_mode_exact_match(self) -> None:
        commands = ["belgi invariant-eval", "belgi run-tests"]
        assert command_satisfied(commands, mode="strings", subcommand="invariant-eval") is True
        assert command_satisfied(commands, mode="strings", subcommand="run-tests") is True
        assert command_satisfied(commands, mode="strings", subcommand="verify-attestation") is False

    def test_strings_mode_no_substring_gaming(self) -> None:
        # Should NOT match substring
        commands = ["belgi invariant-eval-extended"]
        assert command_satisfied(commands, mode="strings", subcommand="invariant-eval") is False

    def test_strings_mode_no_prefix_gaming(self) -> None:
        commands = ["sudo belgi invariant-eval"]
        assert command_satisfied(commands, mode="strings", subcommand="invariant-eval") is False

    def test_structured_mode_exact_match(self) -> None:
        commands = [
            {"argv": ["belgi", "invariant-eval"], "exit_code": 0, "started_at": "1970-01-01T00:00:00Z", "finished_at": "1970-01-01T00:00:00Z"},
            {"argv": ["belgi", "run-tests"], "exit_code": 0, "started_at": "1970-01-01T00:00:00Z", "finished_at": "1970-01-01T00:00:00Z"},
        ]
        assert command_satisfied(commands, mode="structured", subcommand="invariant-eval") is True
        assert command_satisfied(commands, mode="structured", subcommand="run-tests") is True
        assert command_satisfied(commands, mode="structured", subcommand="verify-attestation") is False

    def test_structured_mode_nonzero_exit_fails(self) -> None:
        commands = [
            {"argv": ["belgi", "invariant-eval"], "exit_code": 1, "started_at": "1970-01-01T00:00:00Z", "finished_at": "1970-01-01T00:00:00Z"},
        ]
        assert command_satisfied(commands, mode="structured", subcommand="invariant-eval") is False

    def test_structured_mode_wrong_argv0_fails(self) -> None:
        commands = [
            {"argv": ["python", "invariant-eval"], "exit_code": 0, "started_at": "1970-01-01T00:00:00Z", "finished_at": "1970-01-01T00:00:00Z"},
        ]
        assert command_satisfied(commands, mode="structured", subcommand="invariant-eval") is False

    def test_invalid_mode_returns_false(self) -> None:
        assert command_satisfied(["belgi test"], mode="invalid", subcommand="test") is False

    def test_non_list_returns_false(self) -> None:
        assert command_satisfied("not a list", mode="strings", subcommand="test") is False
        assert command_satisfied(None, mode="structured", subcommand="test") is False


class TestFormatCommandString:
    """Tests for format_command_string."""

    def test_belgi_command_format(self) -> None:
        assert format_command_string(["belgi", "invariant-eval"]) == "belgi invariant-eval"

    def test_empty_argv(self) -> None:
        assert format_command_string([]) == ""

    def test_multi_arg_command(self) -> None:
        assert format_command_string(["belgi", "run-tests", "--verbose"]) == "belgi run-tests --verbose"


class TestMakeCommandRecord:
    """Tests for make_command_record factory."""

    def test_creates_valid_record(self) -> None:
        record = make_command_record(["belgi", "test"], 0)
        assert record.argv == ["belgi", "test"]
        assert record.exit_code == 0
        assert record.started_at == "1970-01-01T00:00:00Z"
        assert record.finished_at == "1970-01-01T00:00:00Z"

    def test_custom_timestamp(self) -> None:
        record = make_command_record(["belgi", "test"], 0, timestamp="2026-01-11T12:00:00Z")
        assert record.started_at == "2026-01-11T12:00:00Z"

    def test_invalid_timestamp_raises(self) -> None:
        with pytest.raises(ValueError):
            make_command_record(["belgi", "test"], 0, timestamp="not-a-timestamp")


class TestCommandRecordToDict:
    """Tests for command_record_to_dict serialization."""

    def test_converts_to_dict(self) -> None:
        record = make_command_record(["belgi", "test"], 0)
        d = command_record_to_dict(record)
        assert d["argv"] == ["belgi", "test"]
        assert d["exit_code"] == 0
        assert "started_at" in d
        assert "finished_at" in d


class TestAppendCommandToManifest:
    """Tests for append_command_to_manifest."""

    def test_append_strings_mode(self) -> None:
        existing = ["belgi c1-compile"]
        result = append_command_to_manifest(
            existing, mode="strings",
            argv=["belgi", "invariant-eval"], exit_code=0
        )
        assert len(result) == 2
        assert result[1] == "belgi invariant-eval"
        # Original not mutated
        assert len(existing) == 1

    def test_append_structured_mode(self) -> None:
        existing = [
            {"argv": ["belgi", "c1"], "exit_code": 0, "started_at": "1970-01-01T00:00:00Z", "finished_at": "1970-01-01T00:00:00Z"}
        ]
        result = append_command_to_manifest(
            existing, mode="structured",
            argv=["belgi", "test"], exit_code=0
        )
        assert len(result) == 2
        assert result[1]["argv"] == ["belgi", "test"]
        # Original not mutated
        assert len(existing) == 1

    def test_invalid_mode_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid"):
            append_command_to_manifest([], mode="invalid", argv=["test"], exit_code=0)

    def test_mode_mismatch_strings_raises(self) -> None:
        # Trying to append in strings mode to a structured list
        existing = [{"argv": ["belgi", "c1"], "exit_code": 0, "started_at": "x", "finished_at": "x"}]
        with pytest.raises(ValueError, match="non-string"):
            append_command_to_manifest(existing, mode="strings", argv=["test"], exit_code=0)

    def test_mode_mismatch_structured_raises(self) -> None:
        # Trying to append in structured mode to a strings list
        existing = ["belgi c1"]
        with pytest.raises(ValueError, match="non-dict"):
            append_command_to_manifest(existing, mode="structured", argv=["test"], exit_code=0)


class TestDetectCommandLogMode:
    """Tests for detect_command_log_mode."""

    def test_detects_strings_mode(self) -> None:
        commands = ["belgi c1", "belgi test"]
        assert detect_command_log_mode(commands) == "strings"

    def test_detects_structured_mode(self) -> None:
        commands = [
            {"argv": ["belgi", "c1"], "exit_code": 0, "started_at": "x", "finished_at": "x"}
        ]
        assert detect_command_log_mode(commands) == "structured"

    def test_empty_list_returns_none(self) -> None:
        assert detect_command_log_mode([]) is None

    def test_mixed_list_returns_none(self) -> None:
        commands = ["belgi c1", {"argv": ["belgi", "test"], "exit_code": 0, "started_at": "x", "finished_at": "x"}]
        assert detect_command_log_mode(commands) is None

    def test_non_list_returns_none(self) -> None:
        assert detect_command_log_mode("not a list") is None
        assert detect_command_log_mode(None) is None

# ---------------------------------------------------------------------------
# R3 waiver path resolution jail consistency tests
# ---------------------------------------------------------------------------

class TestR3WaiverPathJail:
    """Tests for R3 waiver path resolution using resolve_storage_ref (jail-safe).

    R3 must use the same resolve_storage_ref as Q6 to prevent jail bypass when
    loading waiver documents from LockedSpec.waivers_applied[].
    """

    def test_r3_waiver_path_backslash_rejected(self, tmp_path: Path) -> None:
        """Backslash in waiver path should be rejected by resolve_storage_ref."""
        with pytest.raises(ValueError):
            resolve_storage_ref(tmp_path, "waivers\\waiver-001.json")

    def test_r3_waiver_path_traversal_rejected(self, tmp_path: Path) -> None:
        """Path traversal in waiver path should be rejected."""
        with pytest.raises(ValueError):
            resolve_storage_ref(tmp_path, "waivers/../../../etc/passwd")

    def test_r3_waiver_path_absolute_rejected(self, tmp_path: Path) -> None:
        """Absolute paths should be rejected."""
        with pytest.raises(ValueError):
            resolve_storage_ref(tmp_path, "/etc/passwd")

    def test_r3_waiver_path_valid_posix(self, tmp_path: Path) -> None:
        """Valid POSIX path should resolve correctly."""
        (tmp_path / "waivers").mkdir()
        (tmp_path / "waivers" / "waiver-001.json").write_text('{"status": "active"}')
        result = resolve_storage_ref(tmp_path, "waivers/waiver-001.json")
        assert result.exists()
        assert result.name == "waiver-001.json"

    def test_r3_waiver_allows_path_uses_resolve_storage_ref(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """R3 waiver resolution must go through resolve_storage_ref (regression guard)."""
        from types import SimpleNamespace
        from chain.logic.r_checks import r3_policy_invariants as r3

        (tmp_path / "waivers").mkdir()
        waiver_doc = {
            "schema_version": "1.0.0",
            "waiver_id": "waiver-001",
            "gate_id": "R",
            "rule_id": "R3.forbidden_paths",
            "scope": "src",
            "justification": "test",
            "approver": "human:test@example.com",
            "created_at": "2024-01-01T00:00:00Z",
            "expires_at": "2099-01-01T00:00:00Z",
            "audit_trail_ref": {"id": "audit-001", "storage_ref": "audit/log.json"},
            "status": "active",
        }
        waiver_path = tmp_path / "waivers" / "waiver-001.json"
        waiver_path.write_text(json.dumps(waiver_doc), encoding="utf-8")

        called = {"count": 0}
        real_resolve = r3.resolve_storage_ref

        # Assert R3 uses resolve_storage_ref to bind waiver paths to repo_root.
        def _spy_resolve(repo_root: Path, storage_ref: str) -> Path:
            called["count"] += 1
            return real_resolve(repo_root, storage_ref)

        monkeypatch.setattr(r3, "resolve_storage_ref", _spy_resolve)

        class _StubProtocol:
            def __init__(self, root: Path) -> None:
                self._root = root

            def read_json(self, rel: str) -> dict:
                return load_json(self._root / rel)

        ctx = SimpleNamespace(
            repo_root=tmp_path,
            protocol=_StubProtocol(REPO_ROOT),
            locked_spec={"waivers_applied": ["waivers/waiver-001.json"]},
        )

        assert r3._waiver_allows_path(ctx, "src/file.txt") is True
        assert called["count"] >= 1

    def test_r3_waiver_allows_path_unsafe_ref_fails_closed(self, tmp_path: Path) -> None:
        """Unsafe waiver refs must fail-closed (no silent skip)."""
        from types import SimpleNamespace
        from chain.logic.r_checks import r3_policy_invariants as r3

        class _StubProtocol:
            def __init__(self, root: Path) -> None:
                self._root = root

            def read_json(self, rel: str) -> dict:
                return load_json(self._root / rel)

        ctx = SimpleNamespace(
            repo_root=tmp_path,
            protocol=_StubProtocol(REPO_ROOT),
            locked_spec={"waivers_applied": ["waivers\\waiver-001.json"]},
        )

        with pytest.raises(r3.UnsafeWaiverStorageRef) as exc:
            r3._waiver_allows_path(ctx, "src/file.txt")
        assert exc.value.idx == 0
        assert exc.value.storage_ref == "waivers\\waiver-001.json"

    def test_r3_waiver_invalid_json_fails_closed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Invalid waiver JSON must be a deterministic FAIL with index pointer."""
        from types import SimpleNamespace
        from belgi.core.hash import sha256_bytes
        from chain.logic.r_checks import r3_policy_invariants as r3

        (tmp_path / "waivers").mkdir()
        bad_ref = "waivers/bad.json"
        (tmp_path / bad_ref).write_text("{not-json", encoding="utf-8")

        diff_path = tmp_path / "repo.diff.patch"
        diff_bytes = b"diff --git a/src/private/file.txt b/src/private/file.txt\n"
        diff_path.write_bytes(diff_bytes)

        class _StubProtocol:
            def __init__(self, root: Path) -> None:
                self._root = root

            def read_json(self, rel: str) -> dict:
                return load_json(self._root / rel)

        locked_spec = {
            "constraints": {"allowed_paths": ["src"], "forbidden_paths": ["src/private"]},
            "waivers_applied": [bad_ref],
        }
        evidence_manifest = {
            "artifacts": [
                {
                    "kind": "diff",
                    "storage_ref": "repo.diff.patch",
                    "hash": sha256_bytes(diff_bytes),
                }
            ]
        }

        ctx = SimpleNamespace(
            repo_root=tmp_path,
            protocol=_StubProtocol(REPO_ROOT),
            locked_spec_path=tmp_path / "LockedSpec.json",
            evidence_manifest_path=tmp_path / "EvidenceManifest.json",
            gate_verdict_path=None,
            locked_spec=locked_spec,
            evidence_manifest=evidence_manifest,
            gate_verdict=None,
            tier_params={
                "scope_budgets.forbidden_paths_enforcement": "relaxed",
                "waiver_policy.allowed": True,
            },
            evaluated_revision="HEAD",
            upstream_commit_sha="HEAD~1",
            policy_payload_schema={},
            test_payload_schema={},
            required_policy_report_ids=[],
            required_test_report_id="",
        )

        monkeypatch.setattr(r3, "git_changed_paths", lambda *_args, **_kwargs: ["src/private/file.txt"])

        with pytest.raises(r3.InvalidWaiverDocument) as exc:
            r3._waiver_allows_path(ctx, "src/private/file.txt")
        assert exc.value.idx == 0
        assert exc.value.storage_ref == bad_ref

        results = r3.run(ctx)
        assert len(results) == 1
        assert results[0].status == "FAIL"
        assert results[0].pointers == ["LockedSpec.json#/waivers_applied/0"]
        assert "Invalid waiver document" in results[0].message
        assert bad_ref in results[0].message
