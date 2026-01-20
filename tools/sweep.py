#!/usr/bin/env python3
"""Unified sweeper entrypoint.

This file is the canonical sweep CLI.

Commands:
- consistency: generate policy/consistency_sweep.json (canonical)
- fixtures-q: run Gate Q fixtures only
- fixtures-r: run Gate R fixtures only
- fixtures-qr: run Gate Q+R fixtures
- fixtures-s: run Gate S verifier fixtures
- fixtures-seal: run Seal producer fixtures
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
from logging import root
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Sequence


EVALUATED_AT = "1970-01-01T00:00:00Z"

CANONICAL_SWEEP_OUT = "policy/consistency_sweep.json"
CANONICAL_SWEEP_SUMMARY = "policy/consistency_sweep.summary.md"
ZERO_SHA256 = "0" * 64

CONSISTENCY_SPEC_DOC = "docs/operations/consistency-sweep.md"

REPO_ROOT = Path(__file__).resolve().parents[1]

# Allow running from outside the repo by pinning imports to this repo root.
repo_root_str = str(REPO_ROOT)
if repo_root_str in sys.path:
    sys.path.remove(repo_root_str)
sys.path.insert(0, repo_root_str)

from belgi.core.jail import normalize_repo_rel as _normalize_repo_rel
from belgi.core.jail import resolve_repo_rel_path as _resolve_repo_rel_path


class _UserInputError(RuntimeError):
    pass


def _validate_repo_rel(rel: str) -> str:
    try:
        return _normalize_repo_rel(rel, allow_backslashes=True)
    except ValueError as e:
        raise _UserInputError(str(e)) from e


def _resolve_repo_path(
    repo_root: Path,
    rel: str,
    *,
    must_exist: bool,
    must_be_file: bool | None = None,
) -> Path:
    rel_posix = _validate_repo_rel(rel)
    try:
        return _resolve_repo_rel_path(
            repo_root,
            rel_posix,
            must_exist=must_exist,
            must_be_file=must_be_file,
            allow_backslashes=False,
            forbid_symlinks=True,
        )
    except ValueError as e:
        raise _UserInputError(str(e)) from e


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp.sweep")
    with tmp.open("wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(str(tmp), str(path))


def _atomic_write_text(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".tmp.sweep")
    with tmp.open("w", encoding="utf-8", errors="strict", newline="\n") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(str(tmp), str(path))


def _atomic_write_json(path: Path, obj: object) -> None:
    _atomic_write_text(path, json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def _canonical_json_bytes(obj: object) -> bytes:
    s = json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n"
    return s.encode("utf-8", errors="strict")


def _atomic_write_canonical_json(path: Path, obj: object) -> None:
    _atomic_write_bytes(path, _canonical_json_bytes(obj))


# Seal/Gate S fixture regen policy (centralized; deterministic)
_SEAL_PAYLOAD_FILENAMES: tuple[str, ...] = (
    "SealManifest.json",
    "SealManifest.out.json",
    "SealManifest.signed.json",
)

_REGEN_SEALS_REMEDIATION_TEXT = (
    "Seal-related fixture SealManifest drift detected after --fix-fixtures. "
    "Remediation: run `python -m tools.sweep consistency --repo . --fix-fixtures --regen-seals`."
)


# ----------------------------
# Consistency sweep (embedded)
# ----------------------------

def utc_now_rfc3339() -> str:
    """Deterministic timestamp.

    The sweep report is a hashed policy artifact often indexed into EvidenceManifest.
    Runtime timestamps would make the artifact non-reproducible for identical inputs.
    """

    return EVALUATED_AT


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="strict")


def find_fenced_blocks(md: str, fence_lang: str | None = None) -> List[str]:
    """Returns content of fenced code blocks.

    If fence_lang is provided, only returns blocks where opening fence is ```<lang>.
    """

    blocks: List[str] = []
    pattern = r"^```([a-zA-Z0-9_-]*)\s*$"
    lines = md.splitlines()
    i = 0
    in_block = False
    buf: List[str] | None = []
    while i < len(lines):
        m = re.match(pattern, lines[i])
        if not in_block and m:
            lang = (m.group(1) or "").strip()
            if fence_lang is None or lang.lower() == fence_lang.lower():
                in_block = True
                buf = []
            else:
                in_block = True
                buf = None
            i += 1
            continue

        if in_block and lines[i].strip() == "```":
            if buf is not None:
                blocks.append("\n".join(buf))
            in_block = False
            buf = []
            i += 1
            continue

        if in_block and buf is not None:
            buf.append(lines[i])

        i += 1
    return blocks


def strip_code_blocks_and_tables(md: str) -> List[str]:
    """Exclude fenced code blocks and table rows (lines starting with '|')."""

    lines = md.splitlines()
    out: List[str] = []
    in_code = False
    for line in lines:
        if line.startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            continue
        if line.lstrip().startswith("|"):
            continue
        out.append(line)
    return out


def load_json(path: Path) -> Any:
    return json.loads(read_text(path))


def json_pointer(doc: Any, pointer: str) -> Any:
    """Resolve an in-document RFC6901 JSON Pointer (only '#/a/b' form)."""

    if not pointer.startswith("#/"):
        raise ValueError("Only in-document JSON Pointers are supported")
    cur: Any = doc
    for part in pointer[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, list):
            cur = cur[int(part)]
        else:
            cur = cur[part]
    return cur


def repo_path(root: Path, rel: str) -> Path:
    # Backwards-compat shim for internal callers.
    return _resolve_repo_path(root, rel, must_exist=False)


def _git_head_sha(repo_root: Path) -> str:
    try:
        out = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(repo_root))
    except Exception as e:
        raise _UserInputError("git rev-parse HEAD failed") from e
    s = out.decode("utf-8", errors="strict").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", s):
        raise _UserInputError(f"unexpected git HEAD sha: {s!r}")
    return s


def _run_git(
    repo_root: Path,
    args: Sequence[str],
    *,
    env: dict[str, str] | None = None,
    input_bytes: bytes | None = None,
) -> str:
    cmd = ["git", *args]
    if input_bytes is None:
        cp = subprocess.run(cmd, cwd=str(repo_root), env=env, capture_output=True, text=True)
        if cp.returncode != 0:
            raise _UserInputError(f"git {' '.join(args)} failed: {cp.stderr.strip()}")
        return cp.stdout

    cp = subprocess.run(cmd, cwd=str(repo_root), env=env, input=input_bytes, capture_output=True)
    if cp.returncode != 0:
        stderr = cp.stderr.decode("utf-8", errors="strict") if cp.stderr else ""
        raise _UserInputError(f"git {' '.join(args)} failed: {stderr.strip()}")
    return cp.stdout.decode("utf-8", errors="strict")


def _git_tree_sha(repo_root: Path) -> str:
    try:
        out = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=str(repo_root))
    except Exception as e:
        raise _UserInputError("git rev-parse HEAD^{tree} failed") from e
    s = out.decode("utf-8", errors="strict").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", s):
        raise _UserInputError(f"unexpected git tree sha: {s!r}")
    return s


def _git_tree_sha_excluding(
    repo_root: Path,
    exclude_paths: Sequence[str],
    *,
    blob_overrides: dict[str, bytes] | None = None,
) -> str:
    @contextlib.contextmanager
    def _temp_git_index_dir() -> Iterable[Path]:
        # Windows + Python 3.13: os.mkdir(path, 0o700) can produce an unreadable directory,
        # and tempfile.TemporaryDirectory() uses 0o700. Avoid mode=0o700 on Windows.
        if os.name != "nt":
            with tempfile.TemporaryDirectory() as td:
                yield Path(td)
            return

        base = repo_root / "temp" / "_git_index_tmp"
        base.mkdir(parents=True, exist_ok=True)
        for _ in range(100):
            td = base / f"tmp{uuid.uuid4().hex}"
            try:
                os.mkdir(td)
            except FileExistsError:
                continue
            try:
                yield td
            finally:
                shutil.rmtree(td, ignore_errors=True)
            return
        raise _UserInputError("failed to create temporary directory for git index")

    exclude_set = {_validate_repo_rel(p) for p in (exclude_paths or [])}
    override_bytes = {_validate_repo_rel(k): v for k, v in (blob_overrides or {}).items()}

    if not exclude_set and not override_bytes:
        return _git_tree_sha(repo_root)

    for rel in override_bytes.keys():
        if rel in exclude_set:
            raise _UserInputError(f"override path is excluded: {rel}")

    with _temp_git_index_dir() as td:
        index_path = str(td / "index")
        env = dict(os.environ)
        env["GIT_INDEX_FILE"] = index_path

        # IMPORTANT:
        # We intentionally write objects into the repo's object database here.
        # Callers/tests may run plain `git ls-tree <sha>` without our env, so the tree must exist in repo objects.
        _run_git(repo_root, ["read-tree", "HEAD"], env=env)

        for rel in sorted(exclude_set):
            ls = _run_git(repo_root, ["ls-files", "--stage", "--", rel], env=env).strip()
            if not ls:
                continue
            _run_git(repo_root, ["update-index", "--remove", "--force-remove", "--", rel], env=env)

        for rel, data in sorted(override_bytes.items()):
            ls = _run_git(repo_root, ["ls-files", "--stage", "--", rel], env=env).strip()
            if not ls:
                raise _UserInputError(f"override path not found in HEAD: {rel}")
            mode = ls.split(" ", 1)[0]
            if mode not in ("100644", "100755"):
                raise _UserInputError(f"override path is not a regular file blob: {rel}")

            # Write override blob into repo objects (required so the resulting tree is resolvable by plain git commands).
            oid = _run_git(repo_root, ["hash-object", "-w", "--stdin"], env=env, input_bytes=data).strip()
            if not re.fullmatch(r"[0-9a-f]{40}", oid):
                raise _UserInputError(f"unexpected git blob sha: {oid!r}")

            _run_git(
                repo_root,
                ["update-index", "--add", "--cacheinfo", mode, oid, rel],
                env=env,
            )

        s = _run_git(repo_root, ["write-tree"], env=env).strip()
        if not re.fullmatch(r"[0-9a-f]{40}", s):
            raise _UserInputError(f"unexpected git tree sha: {s!r}")
        return s


def _ev006_normalized_manifest_bytes(em_obj: dict[str, Any]) -> bytes:
    # Deterministic fixed-point normalization for CS-EV-006.
    # Treat policy.consistency_sweep as present with ZERO_SHA256, independent of whether fixtures
    # include it (and independent of its original position/duplicates).
    em_norm = json.loads(json.dumps(em_obj, ensure_ascii=False))
    artifacts = em_norm.get("artifacts")
    if not isinstance(artifacts, list):
        artifacts = []

    # Remove any existing entries to make output independent of presence/position/duplicates.
    kept: list[Any] = []
    for a in artifacts:
        if isinstance(a, dict) and a.get("kind") == "policy_report" and a.get("id") == "policy.consistency_sweep":
            continue
        kept.append(a)

    canonical = {
        "kind": "policy_report",
        "id": "policy.consistency_sweep",
        "hash": ZERO_SHA256,
        "media_type": "application/json",
        "storage_ref": CANONICAL_SWEEP_OUT,
        "produced_by": "C1",
    }

    # Stable insertion: after last policy_report, else at end.
    insert_at = 0
    for i, a in enumerate(kept):
        if isinstance(a, dict) and a.get("kind") == "policy_report":
            insert_at = i + 1
    kept.insert(insert_at, canonical)

    em_norm["artifacts"] = kept
    return _canonical_json_bytes(em_norm)


def _ev006_manifest_paths_for_normalization(root: Path) -> list[str]:
    cases_path = _resolve_repo_path(root, "policy/fixtures/public/gate_r/cases.json", must_exist=True, must_be_file=True)
    try:
        cases_obj = load_json(cases_path)
    except Exception as e:
        raise _UserInputError(f"failed to load governed cases.json for EV-006 normalization: {e}") from e
    if not isinstance(cases_obj, dict) or not isinstance(cases_obj.get("cases"), list):
        raise _UserInputError("invalid governed cases.json shape for EV-006 normalization (expected object with cases: list)")

    out: list[str] = []
    cases = [c for c in cases_obj["cases"] if isinstance(c, dict)]
    cases.sort(key=lambda c: str(c.get("case_id") or "").strip())
    for c in cases:
        if c.get("expected_exit_code") != 0:
            continue
        paths = c.get("paths")
        if not isinstance(paths, dict):
            raise _UserInputError(f"EV-006 normalization requires paths object for PASS case_id={c.get('case_id')!r}")
        ls_rel = paths.get("locked_spec")
        em_rel = paths.get("evidence_manifest")
        if not isinstance(ls_rel, str) or not isinstance(em_rel, str):
            raise _UserInputError(f"EV-006 normalization requires paths.locked_spec and paths.evidence_manifest strings for case_id={c.get('case_id')!r}")
        try:
            ls_path = _resolve_repo_path(root, ls_rel, must_exist=True, must_be_file=True)
            em_path = _resolve_repo_path(root, em_rel, must_exist=True, must_be_file=True)
        except _UserInputError as e:
            raise _UserInputError(f"EV-006 normalization failed to resolve governed fixture paths for case_id={c.get('case_id')!r}: {e}") from e
        try:
            ls_obj = load_json(ls_path)
            em_obj = load_json(em_path)
        except Exception as e:
            raise _UserInputError(f"EV-006 normalization failed to parse governed fixture JSON for case_id={c.get('case_id')!r}: {e}") from e
        if not isinstance(ls_obj, dict) or not isinstance(em_obj, dict):
            raise _UserInputError(f"EV-006 normalization requires LockedSpec/EvidenceManifest objects for case_id={c.get('case_id')!r}")
        if not _manifest_claims_tier_ge_1(ls_obj, em_obj):
            continue
        out.append(em_rel)

    return sorted(set(_validate_repo_rel(p) for p in out))


def _ev006_blob_overrides_for_normalization(root: Path) -> dict[str, bytes]:
    overrides: dict[str, bytes] = {}
    for em_rel in _ev006_manifest_paths_for_normalization(root):
        em_path = _resolve_repo_path(root, em_rel, must_exist=True, must_be_file=True)
        try:
            em_obj = load_json(em_path)
        except Exception as e:
            raise _UserInputError(f"EV-006 normalization failed to load EvidenceManifest JSON at {em_rel}: {e}") from e
        if not isinstance(em_obj, dict):
            raise _UserInputError(f"EV-006 normalization requires EvidenceManifest to be a JSON object: {em_rel}")
        overrides[em_rel] = _ev006_normalized_manifest_bytes(em_obj)
    return overrides


@dataclass
class InvariantResult:
    invariant_id: str
    status: str  # PASS/FAIL
    evidence: List[str]
    remediation: str
    details: dict[str, Any] | None = None


_SPEC_INVARIANT_ID_RE = re.compile(r"(?m)^\s*-\s*invariant_id:\s*(CS-[A-Z0-9_-]+)\s*$")


def _extract_spec_invariant_ids(repo_root: Path) -> list[str]:
    """Extract invariant IDs from the canonical consistency sweep spec.

    Deterministic and fail-closed: empty or duplicate IDs are NO-GO.
    """

    spec_path = _resolve_repo_path(repo_root, CONSISTENCY_SPEC_DOC, must_exist=True, must_be_file=True)
    txt = read_text(spec_path)
    ids = _SPEC_INVARIANT_ID_RE.findall(txt)
    if not ids:
        raise _UserInputError(f"no invariant_id entries found in {CONSISTENCY_SPEC_DOC}")

    seen: set[str] = set()
    dups: list[str] = []
    for inv in ids:
        if inv in seen and inv not in dups:
            dups.append(inv)
        seen.add(inv)

    if dups:
        raise _UserInputError(f"duplicate invariant_id entries in {CONSISTENCY_SPEC_DOC}: {sorted(dups)}")

    return sorted(seen)


def _missing_needles(haystack: str, needles: Sequence[str]) -> list[str]:
    """Return needles missing from haystack.

    Contract: returns a list[str] (empty means "all present"); this is NOT a boolean.
    """

    return [n for n in needles if n not in haystack]


def check_cs_can_004(root: Path) -> InvariantResult:
    """CS-CAN-004 — No duplicate non-canonical spec trees."""

    p_gates = root / "belgi" / "gates"
    p_schemas = root / "belgi" / "schemas"

    def has_any_file(p: Path) -> bool:
        if not p.exists():
            return False
        for _, _, files in os.walk(p):
            if files:
                return True
        return False

    if has_any_file(p_gates) or has_any_file(p_schemas):
        return InvariantResult(
            "CS-CAN-004",
            "FAIL",
            ["docs/operations/consistency-sweep.md#cs-can-004--no-duplicate-non-canonical-spec-trees"],
            "Remove non-canonical duplicates under belgi/gates/ and/or belgi/schemas/ and rerun sweep.",
        )

    return InvariantResult(
        "CS-CAN-004",
        "PASS",
        ["docs/operations/consistency-sweep.md#cs-can-004--no-duplicate-non-canonical-spec-trees"],
        "",
    )


def check_cs_can_002(root: Path) -> InvariantResult:
    """CS-CAN-002 — Canonical chain matches everywhere."""

    chain = "P → C1 → Q → C2 → R → C3 → S"
    files = [
        "CANONICALS.md",
        "docs/operations/running-belgi.md",
    ]

    missing: List[str] = []
    mismatched: List[str] = []
    for f in files:
        p = repo_path(root, f)
        if not p.exists():
            missing.append(f)
            continue
        txt = read_text(p)
        if chain not in txt:
            mismatched.append(f)

    if missing:
        return InvariantResult("CS-CAN-002", "FAIL", [], f"Missing required file(s): {', '.join(missing)}.")
    if mismatched:
        return InvariantResult(
            "CS-CAN-002",
            "FAIL",
            [],
            f"Canonical chain string not found exactly in: {', '.join(mismatched)}. Ensure exact '{chain}'.",
        )

    return InvariantResult("CS-CAN-002", "PASS", list(files), "")


def check_cs_can_003(root: Path) -> InvariantResult:
    """CS-CAN-003 — Publication posture is enforced in public-safe docs."""

    can = repo_path(root, "CANONICALS.md")
    sec = repo_path(root, "docs/operations/security.md")
    pb = repo_path(root, "belgi/templates/PromptBundle.blocks.md")
    dc = repo_path(root, "belgi/templates/DocsCompiler.template.md")

    missing_files = [
        rel
        for rel, p in [
            ("CANONICALS.md", can),
            ("docs/operations/security.md", sec),
            ("belgi/templates/PromptBundle.blocks.md", pb),
            ("belgi/templates/DocsCompiler.template.md", dc),
        ]
        if not p.exists()
    ]
    if missing_files:
        return InvariantResult(
            "CS-CAN-003",
            "FAIL",
            ["docs/operations/consistency-sweep.md#cs-can-003--publication-posture-is-enforced-in-public-safe-docs"],
            f"Missing required file(s): {', '.join(missing_files)}.",
        )

    can_txt = read_text(can)
    sec_txt = read_text(sec)
    pb_txt = read_text(pb)
    dc_txt = read_text(dc)

    can_needles = [
        "Publication Posture",
        "MUST NOT publish exploit signatures",
        "evasion thresholds",
        "only categories",
    ]
    sec_needles = [
        "public-safe",
        "MUST NOT include exploit signatures",
        "bypass",
    ]
    pb_needles = [
        "Public release redaction policy",
        "bypass-oriented rule details",
        "exploit signatures",
    ]
    dc_needles = [
        "public-safe",
        "Prohibited non-determinism",
        "No bypass-friendly",
    ]

    missing: list[str] = []
    missing.extend([f"CANONICALS.md: {m}" for m in _missing_needles(can_txt, can_needles)])
    missing.extend([f"security.md: {m}" for m in _missing_needles(sec_txt, sec_needles)])
    missing.extend([f"PromptBundle.blocks.md: {m}" for m in _missing_needles(pb_txt, pb_needles)])
    missing.extend([f"DocsCompiler.template.md: {m}" for m in _missing_needles(dc_txt, dc_needles)])

    if missing:
        return InvariantResult(
            "CS-CAN-003",
            "FAIL",
            [
                "CANONICALS.md#8-publication-posture-canonical",
                "docs/operations/security.md#security-public-safe-posture",
                "belgi/templates/PromptBundle.blocks.md#a4-public-release-redaction-policy",
                "belgi/templates/DocsCompiler.template.md#b22-repository-documentation-inputs-public-safe-categories",
            ],
            "Add/restore public-safe publication posture prohibitions across canonicals/ops/templates and rerun sweep.",
        )

    return InvariantResult(
        "CS-CAN-003",
        "PASS",
        [
            "CANONICALS.md#8-publication-posture-canonical",
            "docs/operations/security.md#security-public-safe-posture",
            "belgi/templates/PromptBundle.blocks.md#a4-public-release-redaction-policy",
            "belgi/templates/DocsCompiler.template.md#b22-repository-documentation-inputs-public-safe-categories",
        ],
        "",
    )


def check_cs_can_001(root: Path) -> InvariantResult:
    """CS-CAN-001 — Terminology is pointers-only (best-effort)."""

    term_path = repo_path(root, "terminology.md")
    if not term_path.exists():
        return InvariantResult("CS-CAN-001", "FAIL", [], "terminology.md missing.")

    md = read_text(term_path)

    rule_ok = ("MUST NOT define" in md) or ("MUST NOT define or redefine" in md)
    if not rule_ok:
        return InvariantResult(
            "CS-CAN-001",
            "FAIL",
            ["terminology.md"],
            "Add explicit Rule of Use statement: terminology.md MUST NOT define or redefine canonical terms.",
        )

    term_map_match = re.search(r"(?is)#+\s*(?:\d+(?:\.\d+)*\.?\s*)?Term Map\b(.*?)(\n#+\s|\Z)", md)
    if term_map_match:
        term_map = term_map_match.group(1)
        links = re.findall(r"\[[^\]]+\]\(([^)]+)\)", term_map)
        bad_links = [l for l in links if not l.startswith("CANONICALS.md#")]
        if bad_links:
            return InvariantResult(
                "CS-CAN-001",
                "FAIL",
                ["terminology.md#term-map"],
                f"Term Map has non-canonical links (must start with CANONICALS.md#): {bad_links[:5]}",
            )
    else:
        return InvariantResult(
            "CS-CAN-001",
            "FAIL",
            ["terminology.md"],
            "Add a 'Term Map' section whose entries link to CANONICALS.md#<anchor>.",
        )

    remaining_lines = strip_code_blocks_and_tables(md)
    rx = re.compile(r"^.+ is (the|a) .+", re.IGNORECASE)
    offenders = [ln for ln in remaining_lines if rx.match(ln.strip())]
    if offenders:
        return InvariantResult(
            "CS-CAN-001",
            "FAIL",
            ["terminology.md"],
            "Remove non-pointer definitions from terminology.md (found definitional sentences of the form 'X is the/a Y').",
        )

    return InvariantResult(
        "CS-CAN-001",
        "PASS",
        ["terminology.md#0-rule-of-use-canonical-pointer", "terminology.md#term-map"],
        "",
    )


def check_intentspec_yaml_single_block(root: Path) -> InvariantResult:
    """CS-IS-001 — IntentSpec core template is machine-parseable and field-complete."""

    p = repo_path(root, "belgi/templates/IntentSpec.core.template.md")
    if not p.exists():
        return InvariantResult("CS-IS-001", "FAIL", [], "Missing belgi/templates/IntentSpec.core.template.md.")

    md = read_text(p)
    blocks = find_fenced_blocks(md, fence_lang="yaml")
    if len(blocks) != 1:
        return InvariantResult(
            "CS-IS-001",
            "FAIL",
            ["belgi/templates/IntentSpec.core.template.md"],
            "IntentSpec.core.template.md must contain exactly one ```yaml fenced block.",
        )

    yaml_text = blocks[0]
    required_keys = ["intent_id", "title", "goal", "scope", "acceptance", "tier", "doc_impact"]
    missing = [k for k in required_keys if re.search(rf"(?m)^\s*{re.escape(k)}\s*:", yaml_text) is None]
    if missing:
        return InvariantResult(
            "CS-IS-001",
            "FAIL",
            ["belgi/templates/IntentSpec.core.template.md"],
            f"Missing key(s) in YAML block: {', '.join(missing)}.",
        )

    return InvariantResult("CS-IS-001", "PASS", ["belgi/templates/IntentSpec.core.template.md"], "")


def check_cs_is_002(root: Path) -> InvariantResult:
    """CS-IS-002 — IntentSpec schema matches required fields and note-on-empty rule."""

    p = repo_path(root, "schemas/IntentSpec.schema.json")
    if not p.exists():
        return InvariantResult("CS-IS-002", "FAIL", [], "Missing schemas/IntentSpec.schema.json.")

    try:
        schema = load_json(p)
        req = set(schema.get("required", []))
        required_fields = {"intent_id", "title", "goal", "scope", "acceptance", "tier", "doc_impact"}
        if not required_fields.issubset(req):
            missing = sorted(required_fields - req)
            return InvariantResult(
                "CS-IS-002",
                "FAIL",
                ["schemas/IntentSpec.schema.json#/required"],
                f"Add required fields to IntentSpec schema: {missing}",
            )

        di = schema.get("properties", {}).get("doc_impact", {})
        if not isinstance(di, dict):
            raise ValueError("doc_impact not object")
        all_of = di.get("allOf", [])
        has_note_on_empty = False
        if isinstance(all_of, list):
            for entry in all_of:
                if not isinstance(entry, dict):
                    continue
                cond = entry.get("if", {}).get("properties", {}).get("required_paths", {})
                if cond.get("maxItems") == 0:
                    then_req = entry.get("then", {}).get("required", [])
                    if isinstance(then_req, list) and "note_on_empty" in then_req:
                        has_note_on_empty = True
                        break
        if not has_note_on_empty:
            return InvariantResult(
                "CS-IS-002",
                "FAIL",
                ["schemas/IntentSpec.schema.json#/properties/doc_impact/allOf"],
                "Add note-on-empty enforcement: when doc_impact.required_paths is empty [], require non-empty note_on_empty.",
            )

        # Wildcard/path safety: RepoRelPathPrefix must forbid '*' and '?'.
        rpp = schema.get("$defs", {}).get("RepoRelPathPrefix", {})
        patt = rpp.get("pattern") if isinstance(rpp, dict) else None
        if not isinstance(patt, str) or ("\\*" not in patt) or ("\\?" not in patt):
            return InvariantResult(
                "CS-IS-002",
                "FAIL",
                ["schemas/IntentSpec.schema.json#/$defs/RepoRelPathPrefix/pattern"],
                "Ensure RepoRelPathPrefix forbids '*' and '?' wildcards via pattern.",
            )
    except Exception as e:
        return InvariantResult("CS-IS-002", "FAIL", ["schemas/IntentSpec.schema.json"], f"Fix IntentSpec schema error ({e}).")

    return InvariantResult(
        "CS-IS-002",
        "PASS",
        [
            "schemas/IntentSpec.schema.json#/required",
            "schemas/IntentSpec.schema.json#/properties/doc_impact/allOf",
            "schemas/IntentSpec.schema.json#/$defs/RepoRelPathPrefix/pattern",
        ],
        "",
    )


def check_cs_is_003(root: Path) -> InvariantResult:
    """CS-IS-003 — Gate Q enforces IntentSpec parse/validate/compile deterministically."""

    q = repo_path(root, "gates/GATE_Q.md")
    if not q.exists():
        return InvariantResult("CS-IS-003", "FAIL", [], "Missing gates/GATE_Q.md.")
    txt = read_text(q)

    must = [
        "Q-INTENT-001",
        "Q-INTENT-002",
        "Q-INTENT-003",
        "IntentSpec.core.md",
        "belgi/templates/IntentSpec.core.template.md",
        "schemas/IntentSpec.schema.json",
        "schemas/LockedSpec.schema.json",
    ]
    missing_must = _missing_needles(txt, must)
    if missing_must:
        return InvariantResult(
            "CS-IS-003",
            "FAIL",
            ["gates/GATE_Q.md#q-intent-001--intentspec-file-present-and-yaml-block-parseable"],
            "Ensure Gate Q defines Q-INTENT-001/002/003 with deterministic parse, schema validate, and explicit mapping into LockedSpec fields.",
        )

    return InvariantResult(
        "CS-IS-003",
        "PASS",
        [
            "gates/GATE_Q.md#q-intent-001--intentspec-file-present-and-yaml-block-parseable",
            "gates/GATE_Q.md#q-intent-002--intentspec-validates-against-intentspecschemajson",
            "gates/GATE_Q.md#q-intent-003--deterministic-mapping-rules-from-intentspec--lockedspec-inputs",
        ],
        "",
    )


def check_cs_is_004(root: Path) -> InvariantResult:
    """CS-IS-004 — IntentSpec is consistently referenced across docs."""

    targets = {
        "gates/GATE_Q.md": ["belgi/templates/IntentSpec.core.template.md", "schemas/IntentSpec.schema.json"],
        "docs/operations/running-belgi.md": ["belgi/templates/IntentSpec.core.template.md", "schemas/IntentSpec.schema.json", "IntentSpec.core.md"],
        "schemas/README.md": ["IntentSpec.schema.json", "IntentSpec.core.md"],
        "belgi/templates/IntentSpec.core.template.md": ["```yaml", "doc_impact"],
    }

    missing: list[str] = []
    for rel, needles in targets.items():
        p = repo_path(root, rel)
        if not p.exists():
            missing.append(f"missing file: {rel}")
            continue
        txt = read_text(p)
        for n in needles:
            if n not in txt:
                missing.append(f"{rel}: missing '{n}'")

    if missing:
        return InvariantResult(
            "CS-IS-004",
            "FAIL",
            ["docs/operations/consistency-sweep.md#cs-is-004--intentspec-is-consistently-referenced-across-gates-schemas-docs-runbook-and-templates-new"],
            "Align IntentSpec references across Gate Q, runbook, schemas docs, and template (canonical filenames and IntentSpec.core.md naming).",
        )

    return InvariantResult(
        "CS-IS-004",
        "PASS",
        [
            "gates/GATE_Q.md#1-inputs-and-outputs",
            "docs/operations/running-belgi.md#step-2--prepare-intentspeccoremd",
            "schemas/README.md#index",
            "belgi/templates/IntentSpec.core.template.md#intentspec-core--template-core-intent-contract-v1",
        ],
        "",
    )


def check_cs_gs_001(root: Path) -> InvariantResult:
    """CS-GS-001 — GateVerdict GO/NO-GO semantics match schema and gate specs."""

    p = repo_path(root, "schemas/GateVerdict.schema.json")
    if not p.exists():
        return InvariantResult("CS-GS-001", "FAIL", [], "Missing schemas/GateVerdict.schema.json.")

    try:
        schema = load_json(p)
        all_of = schema.get("allOf", [])
        if not isinstance(all_of, list):
            raise ValueError("allOf not list")

        def has_go_rule() -> bool:
            for entry in all_of:
                if not isinstance(entry, dict):
                    continue
                if entry.get("if", {}).get("properties", {}).get("verdict", {}).get("const") != "GO":
                    continue
                then = entry.get("then", {})
                props = then.get("properties", {})
                if props.get("failure_category", {}).get("const") is not None:
                    continue
                failures = props.get("failures", {})
                if failures.get("maxItems") != 0:
                    continue
                if then.get("not", {}).get("required") != ["remediation"]:
                    continue
                return True
            return False

        def has_nogo_rule() -> bool:
            for entry in all_of:
                if not isinstance(entry, dict):
                    continue
                if entry.get("if", {}).get("properties", {}).get("verdict", {}).get("const") != "NO-GO":
                    continue
                then = entry.get("then", {})
                if "remediation" not in (then.get("required") or []):
                    continue
                props = then.get("properties", {})
                if props.get("failure_category", {}).get("type") != "string":
                    continue
                failures = props.get("failures", {})
                if failures.get("minItems") != 1:
                    continue
                return True
            return False

        if not has_go_rule() or not has_nogo_rule():
            return InvariantResult(
                "CS-GS-001",
                "FAIL",
                ["schemas/GateVerdict.schema.json#/allOf"],
                "Ensure GateVerdict.schema.json encodes GO/NO-GO constraints via allOf if/then rules (GO => failure_category null, failures empty, remediation absent; NO-GO => remediation required, failure_category string, failures non-empty).",
            )
    except Exception as e:
        return InvariantResult(
            "CS-GS-001",
            "FAIL",
            ["schemas/GateVerdict.schema.json"],
            f"Fix GateVerdict schema parse/shape error ({e}), then rerun sweep.",
        )

    q = repo_path(root, "gates/GATE_Q.md")
    r = repo_path(root, "gates/GATE_R.md")
    if not q.exists() or not r.exists():
        return InvariantResult("CS-GS-001", "FAIL", [], "Missing gates/GATE_Q.md and/or gates/GATE_R.md.")
    q_md = read_text(q)
    r_md = read_text(r)

    q_needles = ["GO semantics", "failure_category = null", "failures = []", "`remediation` MUST be absent"]
    r_needles = ["GO / NO-GO semantics", "failure_category = null", "failures = []", "`remediation` MUST be absent"]
    missing_q = _missing_needles(q_md, q_needles)
    missing_r = _missing_needles(r_md, r_needles)
    if missing_q or missing_r:
        return InvariantResult(
            "CS-GS-001",
            "FAIL",
            ["gates/GATE_Q.md#31-gateverdict-gate_id--q", "gates/GATE_R.md#31-go--no-go-semantics-schema-enforced"],
            "Update gate docs to restate GateVerdict GO/NO-GO semantics exactly as schema-enforced.",
        )

    return InvariantResult(
        "CS-GS-001",
        "PASS",
        ["schemas/GateVerdict.schema.json#/allOf", "gates/GATE_Q.md#31-gateverdict-gate_id--q", "gates/GATE_R.md#31-go--no-go-semantics-schema-enforced"],
        "",
    )


def check_cs_gs_002(root: Path) -> InvariantResult:
    """CS-GS-002 — Remediation instruction format is consistent."""

    gv = repo_path(root, "schemas/GateVerdict.schema.json")
    ft = repo_path(root, "gates/failure-taxonomy.md")
    q = repo_path(root, "gates/GATE_Q.md")
    r = repo_path(root, "gates/GATE_R.md")
    for rel, p in [
        ("schemas/GateVerdict.schema.json", gv),
        ("gates/failure-taxonomy.md", ft),
        ("gates/GATE_Q.md", q),
        ("gates/GATE_R.md", r),
    ]:
        if not p.exists():
            return InvariantResult("CS-GS-002", "FAIL", [], f"Missing {rel}.")

    try:
        schema = load_json(gv)
        patt = schema["properties"]["remediation"]["properties"]["next_instruction"]["pattern"]
        if patt != "^Do .+ then re-run (Q|R|S)\\.$":
            return InvariantResult(
                "CS-GS-002",
                "FAIL",
                ["schemas/GateVerdict.schema.json#/properties/remediation/properties/next_instruction/pattern"],
                "Align GateVerdict remediation.next_instruction pattern to '^Do .+ then re-run (Q|R|S)\\.$' and update docs accordingly.",
            )
    except Exception as e:
        return InvariantResult("CS-GS-002", "FAIL", ["schemas/GateVerdict.schema.json"], f"Fix schema parse error ({e}).")

    ft_txt = read_text(ft).lower()
    if ("must start with `do" not in ft_txt and "must start with do" not in ft_txt) or ("then re-run" not in ft_txt):
        return InvariantResult(
            "CS-GS-002",
            "FAIL",
            ["gates/failure-taxonomy.md#11-remediation-string-constraints-schema-aligned"],
            "Update failure-taxonomy remediation format section to restate the machine-parseable remediation instruction constraints.",
        )

    if ("then re-run q." not in read_text(q).lower()) or ("then re-run r." not in read_text(r).lower()):
        return InvariantResult(
            "CS-GS-002",
            "FAIL",
            ["gates/GATE_Q.md#31-gateverdict-gate_id--q", "gates/GATE_R.md#31-go--no-go-semantics-schema-enforced"],
            "Ensure gate docs remediation templates end with 'then re-run Q.' and 'then re-run R.' as appropriate.",
        )

    return InvariantResult(
        "CS-GS-002",
        "PASS",
        [
            "schemas/GateVerdict.schema.json#/properties/remediation/properties/next_instruction/pattern",
            "gates/failure-taxonomy.md#11-remediation-string-constraints-schema-aligned",
            "gates/GATE_Q.md#31-gateverdict-gate_id--q",
            "gates/GATE_R.md#31-go--no-go-semantics-schema-enforced",
        ],
        "",
    )


def check_cs_gs_003(root: Path) -> InvariantResult:
    """CS-GS-003 — Failure category tokens used by gates exist in failure taxonomy."""

    q = repo_path(root, "gates/GATE_Q.md")
    r = repo_path(root, "gates/GATE_R.md")
    ft = repo_path(root, "gates/failure-taxonomy.md")
    if not q.exists() or not r.exists() or not ft.exists():
        return InvariantResult("CS-GS-003", "FAIL", [], "Missing gates/GATE_Q.md, gates/GATE_R.md, or gates/failure-taxonomy.md.")

    gate_txt = read_text(q) + "\n" + read_text(r)
    tokens = sorted(set(re.findall(r"\bF[QR]-[A-Z0-9_.-]+\b", gate_txt)))
    tax_txt = read_text(ft)
    defined = set(re.findall(r"(?m)^\s*-\s*category_id:\s*`?(F[QR]-[A-Z0-9_.-]+)`?\s*$", tax_txt))

    missing = [t for t in tokens if t not in defined]
    if missing:
        return InvariantResult(
            "CS-GS-003",
            "FAIL",
            ["gates/failure-taxonomy.md#1-category-ids-stable"],
            f"Define missing failure category tokens in failure-taxonomy.md (category_id): {missing[:8]}",
        )

    return InvariantResult(
        "CS-GS-003",
        "PASS",
        ["gates/GATE_Q.md#deterministic-selection-rule-for-gateverdictfailure_category", "gates/GATE_R.md#deterministic-selection-rule-for-gateverdictfailure_category", "gates/failure-taxonomy.md#1-category-ids-stable"],
        "",
    )


def check_cs_gs_004(root: Path) -> InvariantResult:
    """CS-GS-004 — doc_impact contract is schema- and gate-consistent."""

    p = repo_path(root, "schemas/LockedSpec.schema.json")
    if not p.exists():
        return InvariantResult("CS-GS-004", "FAIL", [], "Missing schemas/LockedSpec.schema.json.")

    try:
        schema = load_json(p)
        props = schema.get("properties", {})
        if "doc_impact" not in props:
            raise KeyError("properties.doc_impact")
        di = props["doc_impact"]
        if not isinstance(di, dict):
            raise ValueError("doc_impact not object")
        di_props = di.get("properties", {})
        if "required_paths" not in di_props or "note_on_empty" not in di_props:
            return InvariantResult(
                "CS-GS-004",
                "FAIL",
                ["schemas/LockedSpec.schema.json#/properties/doc_impact"],
                "doc_impact must define required_paths and note_on_empty.",
            )

        # Tier-2/3 requirement surface.
        all_of = schema.get("allOf", [])
        tier_requires_doc_impact = False
        if isinstance(all_of, list):
            for entry in all_of:
                if not isinstance(entry, dict):
                    continue
                cond = entry.get("if", {}).get("properties", {}).get("tier", {}).get("properties", {}).get("tier_id", {})
                if cond.get("enum") == ["tier-2", "tier-3"]:
                    req = entry.get("then", {}).get("required", [])
                    if isinstance(req, list) and ("doc_impact" in req):
                        tier_requires_doc_impact = True
                        break
        if not tier_requires_doc_impact:
            return InvariantResult(
                "CS-GS-004",
                "FAIL",
                ["schemas/LockedSpec.schema.json#/allOf"],
                "Ensure LockedSpec.schema.json requires doc_impact for tier-2 and tier-3 via an allOf if/then rule.",
            )
    except Exception as e:
        return InvariantResult("CS-GS-004", "FAIL", ["schemas/LockedSpec.schema.json"], f"Fix LockedSpec schema error ({e}).")

    q = repo_path(root, "gates/GATE_Q.md")
    r = repo_path(root, "gates/GATE_R.md")
    if not q.exists() or not r.exists():
        return InvariantResult("CS-GS-004", "FAIL", [], "Missing gates/GATE_Q.md and/or gates/GATE_R.md.")
    q_txt = read_text(q)
    r_txt = read_text(r)

    required_q = ["Q-DOC-001", "Q-DOC-002", "note_on_empty"]
    required_r = ["R-DOC-001", "note_on_empty", "required_paths"]
    missing_q = _missing_needles(q_txt, required_q)
    missing_r = _missing_needles(r_txt, required_r)
    if missing_q or missing_r:
        return InvariantResult(
            "CS-GS-004",
            "FAIL",
            ["gates/GATE_Q.md#q-doc-001--doc_impact-shape--path-normalization", "gates/GATE_Q.md#q-doc-002--doc_impact-tier-enforcement--note-on-empty", "gates/GATE_R.md#r-doc-001--doc_impact-enforced-with-diff"],
            "Ensure gate docs define Q-DOC-001/Q-DOC-002 and R-DOC-001 with note-on-empty semantics aligned to LockedSpec.schema.json.",
        )

    return InvariantResult(
        "CS-GS-004",
        "PASS",
        [
            "schemas/LockedSpec.schema.json#/properties/doc_impact",
            "schemas/LockedSpec.schema.json#/allOf",
            "gates/GATE_Q.md#q-doc-002--doc_impact-tier-enforcement--note-on-empty",
            "gates/GATE_R.md#r-doc-001--doc_impact-enforced-with-diff",
        ],
        "",
    )


def check_cs_gs_005(root: Path) -> InvariantResult:
    """CS-GS-005 — No spec fiction: doc_impact claimed implies schema field exists."""

    schema_path = repo_path(root, "schemas/LockedSpec.schema.json")
    if not schema_path.exists():
        return InvariantResult("CS-GS-005", "FAIL", [], "Missing schemas/LockedSpec.schema.json.")

    q = repo_path(root, "gates/GATE_Q.md")
    r = repo_path(root, "gates/GATE_R.md")
    tiers = repo_path(root, "tiers/tier-packs.md")
    for rel, p in [("gates/GATE_Q.md", q), ("gates/GATE_R.md", r), ("tiers/tier-packs.md", tiers)]:
        if not p.exists():
            return InvariantResult("CS-GS-005", "FAIL", [], f"Missing {rel}.")

    any_claim = any("doc_impact" in read_text(p) for p in (q, r, tiers))
    if not any_claim:
        return InvariantResult(
            "CS-GS-005",
            "PASS",
            ["docs/operations/consistency-sweep.md#cs-gs-005--no-spec-fiction-doc_impact-claimed-implies-schema-field-exists"],
            "",
        )

    try:
        schema = load_json(schema_path)
        if "doc_impact" not in (schema.get("properties") or {}):
            return InvariantResult(
                "CS-GS-005",
                "FAIL",
                ["schemas/LockedSpec.schema.json#/properties"],
                "Define LockedSpec.properties.doc_impact in schemas/LockedSpec.schema.json.",
            )
    except Exception as e:
        return InvariantResult("CS-GS-005", "FAIL", ["schemas/LockedSpec.schema.json"], f"Fix LockedSpec schema parse error ({e}).")

    return InvariantResult(
        "CS-GS-005",
        "PASS",
        ["schemas/LockedSpec.schema.json#/properties/doc_impact", "tiers/tier-packs.md#27-doc_impact_required"],
        "",
    )


def check_cs_ev_001(root: Path) -> InvariantResult:
    """CS-EV-001 — Evidence kind enum is the single allowed vocabulary."""

    em_path = repo_path(root, "schemas/EvidenceManifest.schema.json")
    if not em_path.exists():
        return InvariantResult("CS-EV-001", "FAIL", [], "Missing schemas/EvidenceManifest.schema.json.")

    docs = [
        "docs/operations/evidence-bundles.md",
        "tiers/tier-packs.md",
        "docs/operations/running-belgi.md",
        "belgi/templates/DocsCompiler.template.md",
    ]

    try:
        schema = load_json(em_path)
        kinds = schema["properties"]["artifacts"]["items"]["properties"]["kind"]["enum"]
        if not isinstance(kinds, list) or not all(isinstance(k, str) for k in kinds):
            raise ValueError("kind enum missing")
        kind_set = set(kinds)
    except Exception as e:
        return InvariantResult("CS-EV-001", "FAIL", ["schemas/EvidenceManifest.schema.json"], f"Fix EvidenceManifest schema parse error ({e}).")

    observed: set[str] = set()
    for rel in docs:
        p = repo_path(root, rel)
        if not p.exists():
            return InvariantResult("CS-EV-001", "FAIL", [], f"Missing {rel}.")
        txt = read_text(p)
        for tok in re.findall(r"`([a-z][a-z0-9_]+)`", txt):
            if tok in kind_set or tok.endswith("_log") or tok.endswith("_report") or tok.endswith("_validation") or tok.endswith("_approval"):
                observed.add(tok)

    unknown = sorted([k for k in observed if k not in kind_set])
    if unknown:
        return InvariantResult(
            "CS-EV-001",
            "FAIL",
            ["schemas/EvidenceManifest.schema.json#/properties/artifacts/items/properties/kind/enum"],
            f"Remove or define unknown evidence kind(s) (must be in schema enum): {unknown[:8]}",
        )

    return InvariantResult(
        "CS-EV-001",
        "PASS",
        [
            "schemas/EvidenceManifest.schema.json#/properties/artifacts/items/properties/kind/enum",
            "docs/operations/evidence-bundles.md#21-allowed-evidence-kinds-schema-enum",
            "tiers/tier-packs.md#21-required_evidence_kinds",
        ],
        "",
    )


def check_cs_ev_002(root: Path) -> InvariantResult:
    """CS-EV-002 — Gate Q minimum required evidence kinds are consistent."""

    q = repo_path(root, "gates/GATE_Q.md")
    em = repo_path(root, "schemas/EvidenceManifest.schema.json")
    if not q.exists() or not em.exists():
        return InvariantResult("CS-EV-002", "FAIL", [], "Missing gates/GATE_Q.md and/or schemas/EvidenceManifest.schema.json.")

    q_txt = read_text(q)
    must = ["Minimum required evidence kinds at Q", "`command_log`", "`policy_report`", "`schema_validation`"]
    missing_must = _missing_needles(q_txt, must)
    if missing_must:
        return InvariantResult(
            "CS-EV-002",
            "FAIL",
            ["gates/GATE_Q.md#33-evidencemanifest-reference"],
            "Update Gate Q to explicitly require command_log, policy_report, and schema_validation at minimum.",
        )

    try:
        schema = load_json(em)
        kinds = set(schema["properties"]["artifacts"]["items"]["properties"]["kind"]["enum"])
    except Exception as e:
        return InvariantResult("CS-EV-002", "FAIL", ["schemas/EvidenceManifest.schema.json"], f"Fix schema parse error ({e}).")

    required = {"command_log", "policy_report", "schema_validation"}
    if not required.issubset(kinds):
        return InvariantResult(
            "CS-EV-002",
            "FAIL",
            ["schemas/EvidenceManifest.schema.json#/properties/artifacts/items/properties/kind/enum"],
            "Ensure EvidenceManifest kind enum includes command_log, policy_report, and schema_validation.",
        )

    return InvariantResult(
        "CS-EV-002",
        "PASS",
        ["gates/GATE_Q.md#33-evidencemanifest-reference", "schemas/EvidenceManifest.schema.json#/properties/artifacts/items/properties/kind/enum"],
        "",
    )


def check_cs_ev_003(root: Path) -> InvariantResult:
    """CS-EV-003 — Gate R evidence sufficiency rule is tier-driven."""

    r = repo_path(root, "gates/GATE_R.md")
    tiers = repo_path(root, "tiers/tier-packs.md")
    if not r.exists() or not tiers.exists():
        return InvariantResult("CS-EV-003", "FAIL", [], "Missing gates/GATE_R.md and/or tiers/tier-packs.md.")

    r_txt = read_text(r).lower()
    t_txt = read_text(tiers).lower()
    must_r = ["evidence sufficiency rule", "required_evidence_kinds", "evidencemanifest"]
    must_t = ["required_evidence_kinds", "tier 0", "tier 1", "tier 2", "tier 3"]
    missing_r = _missing_needles(r_txt, must_r)
    missing_t = _missing_needles(t_txt, must_t)
    if missing_r or missing_t:
        return InvariantResult(
            "CS-EV-003",
            "FAIL",
            ["gates/GATE_R.md#4-evidence-sufficiency-rule-deterministic", "tiers/tier-packs.md#21-required_evidence_kinds"],
            "Ensure Gate R derives evidence sufficiency from tier required_evidence_kinds and tier-packs defines the parameter set.",
        )

    return InvariantResult(
        "CS-EV-003",
        "PASS",
        ["gates/GATE_R.md#4-evidence-sufficiency-rule-deterministic", "tiers/tier-packs.md#21-required_evidence_kinds"],
        "",
    )


def check_cs_ev_004(root: Path) -> InvariantResult:
    """CS-EV-004 — Post-R evidence must be append-only and preserve the R-snapshot."""

    eb = repo_path(root, "docs/operations/evidence-bundles.md")
    rb = repo_path(root, "docs/operations/running-belgi.md")
    dc = repo_path(root, "belgi/templates/DocsCompiler.template.md")
    for rel, p in [
        ("docs/operations/evidence-bundles.md", eb),
        ("docs/operations/running-belgi.md", rb),
        ("belgi/templates/DocsCompiler.template.md", dc),
    ]:
        if not p.exists():
            return InvariantResult("CS-EV-004", "FAIL", [], f"Missing {rel}.")

    eb_txt = read_text(eb)
    rb_txt = read_text(rb)
    dc_txt = read_text(dc)

    need = ["append-only", "R-Snapshot"]
    if (not all(s in eb_txt for s in need)) or ("append-only" not in rb_txt) or ("append-only" not in dc_txt):
        return InvariantResult(
            "CS-EV-004",
            "FAIL",
            [
                "docs/operations/evidence-bundles.md#evidence-mutability-r-snapshot-and-replay-integrity-normative",
                "docs/operations/running-belgi.md#step-5--run-c3-docs-compiler",
                "belgi/templates/DocsCompiler.template.md#b5-verification-expectations-gate-r--replay",
            ],
            "Align docs to state R-Snapshot immutability and append-only Final EvidenceManifest extension semantics.",
        )

    return InvariantResult(
        "CS-EV-004",
        "PASS",
        [
            "docs/operations/evidence-bundles.md#evidence-mutability-r-snapshot-and-replay-integrity-normative",
            "docs/operations/running-belgi.md#step-5--run-c3-docs-compiler",
            "belgi/templates/DocsCompiler.template.md#b5-verification-expectations-gate-r--replay",
        ],
        "",
    )


def check_cs_ev_005(root: Path) -> InvariantResult:
    """CS-EV-005 — Seal binds the core replay set (including waivers)."""

    sm = repo_path(root, "schemas/SealManifest.schema.json")
    eb = repo_path(root, "docs/operations/evidence-bundles.md")
    can = repo_path(root, "CANONICALS.md")
    if not sm.exists() or not eb.exists() or not can.exists():
        return InvariantResult("CS-EV-005", "FAIL", [], "Missing SealManifest schema and/or required docs.")

    try:
        schema = load_json(sm)
        req = set(schema.get("required", []))
        must_req = {"locked_spec_ref", "gate_q_verdict_ref", "gate_r_verdict_ref", "evidence_manifest_ref", "waivers"}
        if not must_req.issubset(req):
            return InvariantResult(
                "CS-EV-005",
                "FAIL",
                ["schemas/SealManifest.schema.json#/required"],
                "SealManifest must require locked_spec_ref, gate_q_verdict_ref, gate_r_verdict_ref, evidence_manifest_ref, and waivers.",
            )
        waivers = schema.get("properties", {}).get("waivers", {})
        if not isinstance(waivers, dict) or waivers.get("type") != "array":
            return InvariantResult(
                "CS-EV-005",
                "FAIL",
                ["schemas/SealManifest.schema.json#/properties/waivers"],
                "SealManifest.waivers must be an array of ObjectRef items (may be empty).",
            )
    except Exception as e:
        return InvariantResult("CS-EV-005", "FAIL", ["schemas/SealManifest.schema.json"], f"Fix SealManifest schema error ({e}).")

    if ("mandatory artifacts" not in read_text(eb).lower()) or ("waiver" not in read_text(can).lower()):
        return InvariantResult(
            "CS-EV-005",
            "FAIL",
            ["docs/operations/evidence-bundles.md#11-mandatory-artifacts-minimum-replay-set", "CANONICALS.md#waivers"],
            "Ensure evidence-bundles and CANONICALS require seal binding of the core replay set and applied waivers.",
        )

    return InvariantResult(
        "CS-EV-005",
        "PASS",
        [
            "schemas/SealManifest.schema.json#/required",
            "schemas/SealManifest.schema.json#/properties/waivers",
            "docs/operations/evidence-bundles.md#11-mandatory-artifacts-minimum-replay-set",
            "CANONICALS.md#waivers",
        ],
        "",
    )


def check_cs_tier_001(root: Path) -> InvariantResult:
    """CS-TIER-001 — Tier IDs are consistent and bounded."""

    allowed = {"tier-0", "tier-1", "tier-2", "tier-3"}
    tiers = repo_path(root, "tiers/tier-packs.md")
    q = repo_path(root, "gates/GATE_Q.md")
    pb = repo_path(root, "belgi/templates/PromptBundle.blocks.md")
    for rel, p in [("tiers/tier-packs.md", tiers), ("gates/GATE_Q.md", q), ("belgi/templates/PromptBundle.blocks.md", pb)]:
        if not p.exists():
            return InvariantResult("CS-TIER-001", "FAIL", [], f"Missing {rel}.")

    tier_txt = read_text(tiers) + "\n" + read_text(q) + "\n" + read_text(pb)
    used = sorted(set(re.findall(r"\btier-[0-9]+\b", tier_txt)))
    bad = [t for t in used if t not in allowed]
    if bad:
        return InvariantResult(
            "CS-TIER-001",
            "FAIL",
            ["tiers/tier-packs.md#1-tier-ids", "gates/GATE_Q.md#q7--tier-id-supported"],
            f"Remove or correct unsupported tier_id token(s): {bad}",
        )

    for t in sorted(allowed):
        if t not in tier_txt:
            return InvariantResult(
                "CS-TIER-001",
                "FAIL",
                ["tiers/tier-packs.md#1-tier-ids"],
                "Ensure all supported tier IDs tier-0..tier-3 are documented in tier-packs and referenced consistently.",
            )

    return InvariantResult(
        "CS-TIER-001",
        "PASS",
        ["tiers/tier-packs.md#1-tier-ids", "gates/GATE_Q.md#q7--tier-id-supported", "belgi/templates/PromptBundle.blocks.md#fm-pb-001--unknown-or-unsupported-tier_id"],
        "",
    )


def check_cs_tier_002(root: Path) -> InvariantResult:
    """CS-TIER-002 — Tier required_evidence_kinds are consistent across docs."""

    tiers = repo_path(root, "tiers/tier-packs.md")
    eb = repo_path(root, "docs/operations/evidence-bundles.md")
    rb = repo_path(root, "docs/operations/running-belgi.md")
    for rel, p in [("tiers/tier-packs.md", tiers), ("docs/operations/evidence-bundles.md", eb), ("docs/operations/running-belgi.md", rb)]:
        if not p.exists():
            return InvariantResult("CS-TIER-002", "FAIL", [], f"Missing {rel}.")

    t_txt = read_text(tiers)
    eb_txt = read_text(eb)
    rb_txt = read_text(rb)

    tier0 = ["diff", "command_log", "schema_validation", "policy_report"]
    tier1 = ["diff", "command_log", "schema_validation", "policy_report", "test_report", "env_attestation"]

    def doc_mentions_all(doc: str, toks: list[str]) -> bool:
        return all(f"`{t}`" in doc or t in doc for t in toks)

    if not doc_mentions_all(t_txt, tier0) or not doc_mentions_all(t_txt, tier1):
        return InvariantResult(
            "CS-TIER-002",
            "FAIL",
            ["tiers/tier-packs.md#3-tier-parameter-sets"],
            "Ensure tier-packs.md lists required_evidence_kinds for tier-0 and tier-1..3 exactly as specified.",
        )
    if not doc_mentions_all(eb_txt, tier0) or not doc_mentions_all(eb_txt, tier1):
        return InvariantResult(
            "CS-TIER-002",
            "FAIL",
            ["docs/operations/evidence-bundles.md#22-tier-driven-minimums-gate-r-evidence-sufficiency"],
            "Ensure evidence-bundles.md matches the tier required_evidence_kinds sets.",
        )
    if not doc_mentions_all(rb_txt, tier0) or not doc_mentions_all(rb_txt, tier1):
        return InvariantResult(
            "CS-TIER-002",
            "FAIL",
            ["docs/operations/running-belgi.md#step-4--run-gate-r-verify"],
            "Ensure running-belgi.md matches the tier required_evidence_kinds sets.",
        )

    return InvariantResult(
        "CS-TIER-002",
        "PASS",
        [
            "tiers/tier-packs.md#3-tier-parameter-sets",
            "docs/operations/evidence-bundles.md#22-tier-driven-minimums-gate-r-evidence-sufficiency",
            "docs/operations/running-belgi.md#step-4--run-gate-r-verify",
        ],
        "",
    )


def check_cs_tier_003(root: Path) -> InvariantResult:
    """CS-TIER-003 — docs_compilation_log exists but is not a Gate R requirement."""

    em = repo_path(root, "schemas/EvidenceManifest.schema.json")
    tiers = repo_path(root, "tiers/tier-packs.md")
    eb = repo_path(root, "docs/operations/evidence-bundles.md")
    if not em.exists() or not tiers.exists() or not eb.exists():
        return InvariantResult("CS-TIER-003", "FAIL", [], "Missing EvidenceManifest schema and/or required docs.")

    try:
        schema = load_json(em)
        kinds = set(schema["properties"]["artifacts"]["items"]["properties"]["kind"]["enum"])
        if "docs_compilation_log" not in kinds:
            return InvariantResult(
                "CS-TIER-003",
                "FAIL",
                ["schemas/EvidenceManifest.schema.json#/properties/artifacts/items/properties/kind/enum"],
                "Add docs_compilation_log to EvidenceManifest kind enum.",
            )
    except Exception as e:
        return InvariantResult("CS-TIER-003", "FAIL", ["schemas/EvidenceManifest.schema.json"], f"Fix schema parse error ({e}).")

    if "MUST NOT require" not in read_text(tiers) or "docs_compilation_log" not in read_text(tiers):
        return InvariantResult(
            "CS-TIER-003",
            "FAIL",
            ["tiers/tier-packs.md#21-required_evidence_kinds"],
            "Ensure tier-packs.md states Gate R MUST NOT require docs_compilation_log.",
        )
    if "MUST NOT require" not in read_text(eb) or "docs_compilation_log" not in read_text(eb):
        return InvariantResult(
            "CS-TIER-003",
            "FAIL",
            ["docs/operations/evidence-bundles.md#23-evidence-kinds-used-by-specific-gate-checks"],
            "Ensure evidence-bundles.md reiterates docs_compilation_log is post-R and not required by Gate R.",
        )

    return InvariantResult(
        "CS-TIER-003",
        "PASS",
        [
            "schemas/EvidenceManifest.schema.json#/properties/artifacts/items/properties/kind/enum",
            "tiers/tier-packs.md#21-required_evidence_kinds",
            "docs/operations/evidence-bundles.md#23-evidence-kinds-used-by-specific-gate-checks",
        ],
        "",
    )


def check_cs_tier_004(root: Path) -> InvariantResult:
    """CS-TIER-004 — command_log_mode is enforceable with the current schema."""

    tiers = repo_path(root, "tiers/tier-packs.md")
    r = repo_path(root, "gates/GATE_R.md")
    em = repo_path(root, "schemas/EvidenceManifest.schema.json")
    if not tiers.exists() or not r.exists() or not em.exists():
        return InvariantResult("CS-TIER-004", "FAIL", [], "Missing tiers/tier-packs.md, gates/GATE_R.md, or schemas/EvidenceManifest.schema.json.")

    try:
        schema = load_json(em)
        one_of = schema["properties"]["commands_executed"]["oneOf"]
        if not isinstance(one_of, list) or len(one_of) != 2:
            raise ValueError("commands_executed.oneOf unexpected")
    except Exception as e:
        return InvariantResult(
            "CS-TIER-004",
            "FAIL",
            ["schemas/EvidenceManifest.schema.json#/properties/commands_executed/oneOf"],
            f"Fix EvidenceManifest.commands_executed oneOf shape ({e}).",
        )

    if "command_log_mode" not in read_text(tiers):
        return InvariantResult(
            "CS-TIER-004",
            "FAIL",
            ["tiers/tier-packs.md#25-command_log_mode"],
            "Document tier command_log_mode and its supported values in tier-packs.md.",
        )
    r_txt = read_text(r)
    must = ["command_log_mode", "commands_executed", "matching rule"]
    missing_must = _missing_needles(r_txt, must)
    if missing_must:
        return InvariantResult(
            "CS-TIER-004",
            "FAIL",
            ["gates/GATE_R.md#51-command-matching-rule-used-by-r1r5r6r7r8"],
            "Define deterministic command matching rules for both commands_executed representations and tie them to tier command_log_mode.",
        )

    return InvariantResult(
        "CS-TIER-004",
        "PASS",
        [
            "schemas/EvidenceManifest.schema.json#/properties/commands_executed/oneOf",
            "tiers/tier-packs.md#25-command_log_mode",
            "gates/GATE_R.md#51-command-matching-rule-used-by-r1r5r6r7r8",
        ],
        "",
    )


def check_cs_tier_005(root: Path) -> InvariantResult:
    """CS-TIER-005 — doc_impact_required parameter is consistent across docs."""

    tiers = repo_path(root, "tiers/tier-packs.md")
    q = repo_path(root, "gates/GATE_Q.md")
    r = repo_path(root, "gates/GATE_R.md")
    rb = repo_path(root, "docs/operations/running-belgi.md")
    for rel, p in [("tiers/tier-packs.md", tiers), ("gates/GATE_Q.md", q), ("gates/GATE_R.md", r), ("docs/operations/running-belgi.md", rb)]:
        if not p.exists():
            return InvariantResult("CS-TIER-005", "FAIL", [], f"Missing {rel}.")

    t_txt = read_text(tiers)
    required_lines = ["doc_impact_required", "tier-0", "tier-1", "tier-2", "tier-3"]
    missing_required_lines = _missing_needles(t_txt, required_lines)
    if missing_required_lines:
        return InvariantResult(
            "CS-TIER-005",
            "FAIL",
            ["tiers/tier-packs.md#27-doc_impact_required"],
            "Ensure tier-packs.md defines doc_impact_required and the tier-0..tier-3 mapping.",
        )

    if "doc_impact_required" not in read_text(q) or "doc_impact_required" not in read_text(r):
        return InvariantResult(
            "CS-TIER-005",
            "FAIL",
            ["gates/GATE_Q.md#q-doc-002--doc_impact-tier-enforcement--note-on-empty", "gates/GATE_R.md#r-doc-001--doc_impact-enforced-with-diff"],
            "Ensure Gate Q Q-DOC-002 and Gate R R-DOC-001 reference doc_impact_required parameter.",
        )

    rb_txt = read_text(rb)
    if "Tier 2" not in rb_txt or "Tier 3" not in rb_txt or "doc_impact" not in rb_txt:
        return InvariantResult(
            "CS-TIER-005",
            "FAIL",
            ["docs/operations/running-belgi.md#23-doc_impact-operator-requirement-for-tier-23"],
            "Ensure running-belgi.md states Tier 2–3 require doc_impact and describes the empty required_paths + note_on_empty rule.",
        )

    return InvariantResult(
        "CS-TIER-005",
        "PASS",
        [
            "tiers/tier-packs.md#27-doc_impact_required",
            "gates/GATE_Q.md#q-doc-002--doc_impact-tier-enforcement--note-on-empty",
            "gates/GATE_R.md#r-doc-001--doc_impact-enforced-with-diff",
            "docs/operations/running-belgi.md#23-doc_impact-operator-requirement-for-tier-23",
        ],
        "",
    )


def check_cs_wvr_001(root: Path) -> InvariantResult:
    """CS-WVR-001 — Waivers are human-controlled (LLM-closed)."""

    can = repo_path(root, "CANONICALS.md")
    ops = repo_path(root, "docs/operations/waivers.md")
    ws = repo_path(root, "schemas/Waiver.schema.json")
    for rel, p in [("CANONICALS.md", can), ("docs/operations/waivers.md", ops), ("schemas/Waiver.schema.json", ws)]:
        if not p.exists():
            return InvariantResult("CS-WVR-001", "FAIL", [], f"Missing {rel}.")

    if "MUST NOT" not in read_text(can) or "LLM" not in read_text(can):
        return InvariantResult(
            "CS-WVR-001",
            "FAIL",
            ["CANONICALS.md#waivers"],
            "Ensure CANONICALS waiver policy forbids LLM-created/edited/applied waivers.",
        )
    if "forbidden" not in read_text(ops).lower() or "c2" not in read_text(ops).lower():
        return InvariantResult(
            "CS-WVR-001",
            "FAIL",
            ["docs/operations/waivers.md#24-proposer-llm--forbidden"],
            "Ensure waivers.md explicitly forbids proposer/LLM (C2) from waiver actions.",
        )

    try:
        schema = load_json(ws)
        req = set(schema.get("required", []))
        if "approver" not in req:
            return InvariantResult(
                "CS-WVR-001",
                "FAIL",
                ["schemas/Waiver.schema.json#/required"],
                "Ensure Waiver schema requires approver.",
            )
        approver = schema.get("properties", {}).get("approver", {})
        desc = approver.get("description") if isinstance(approver, dict) else None
        if not isinstance(desc, str) or "human" not in desc.lower():
            return InvariantResult(
                "CS-WVR-001",
                "FAIL",
                ["schemas/Waiver.schema.json#/properties/approver/description"],
                "Describe Waiver.approver as a human identity class in schema.",
            )
    except Exception as e:
        return InvariantResult("CS-WVR-001", "FAIL", ["schemas/Waiver.schema.json"], f"Fix Waiver schema error ({e}).")

    return InvariantResult(
        "CS-WVR-001",
        "PASS",
        ["CANONICALS.md#waivers", "docs/operations/waivers.md#24-proposer-llm--forbidden", "schemas/Waiver.schema.json#/properties/approver"],
        "",
    )


def check_cs_wvr_002(root: Path) -> InvariantResult:
    """CS-WVR-002 — Waivers are time-bounded and auditable."""

    ws = repo_path(root, "schemas/Waiver.schema.json")
    q = repo_path(root, "gates/GATE_Q.md")
    ops = repo_path(root, "docs/operations/waivers.md")
    for rel, p in [("schemas/Waiver.schema.json", ws), ("gates/GATE_Q.md", q), ("docs/operations/waivers.md", ops)]:
        if not p.exists():
            return InvariantResult("CS-WVR-002", "FAIL", [], f"Missing {rel}.")

    try:
        schema = load_json(ws)
        req = set(schema.get("required", []))
        if not {"expires_at", "audit_trail_ref"}.issubset(req):
            return InvariantResult(
                "CS-WVR-002",
                "FAIL",
                ["schemas/Waiver.schema.json#/required"],
                "Ensure Waiver schema requires expires_at and audit_trail_ref.",
            )
    except Exception as e:
        return InvariantResult("CS-WVR-002", "FAIL", ["schemas/Waiver.schema.json"], f"Fix Waiver schema error ({e}).")

    q_txt = read_text(q)
    missing_q = _missing_needles(q_txt, ["Q6", "status == \"active\"", "expires_at", "evaluated_at"])
    if missing_q:
        return InvariantResult(
            "CS-WVR-002",
            "FAIL",
            ["gates/GATE_Q.md#q6--waivers-validity-if-present"],
            "Ensure Gate Q Q6 enforces waiver status active and expires_at after evaluated_at.",
        )
    if "expires_at" not in read_text(ops) or "audit_trail_ref" not in read_text(ops):
        return InvariantResult(
            "CS-WVR-002",
            "FAIL",
            ["docs/operations/waivers.md#34-apply-to-a-run-lockedspecwaivers_applied"],
            "Ensure waivers.md documents expires_at and audit_trail_ref requirements and application point.",
        )

    return InvariantResult(
        "CS-WVR-002",
        "PASS",
        ["schemas/Waiver.schema.json#/required", "gates/GATE_Q.md#q6--waivers-validity-if-present", "docs/operations/waivers.md#34-apply-to-a-run-lockedspecwaivers_applied"],
        "",
    )


def check_cs_wvr_003(root: Path) -> InvariantResult:
    """CS-WVR-003 — Tier waiver policy is consistent and enforced."""

    tiers = repo_path(root, "tiers/tier-packs.md")
    q = repo_path(root, "gates/GATE_Q.md")
    ops = repo_path(root, "docs/operations/waivers.md")
    for rel, p in [("tiers/tier-packs.md", tiers), ("gates/GATE_Q.md", q), ("docs/operations/waivers.md", ops)]:
        if not p.exists():
            return InvariantResult("CS-WVR-003", "FAIL", [], f"Missing {rel}.")

    t_txt = read_text(tiers)
    missing_t = _missing_needles(t_txt, ["waiver_policy", "max_active_waivers", "tier-3"])
    if missing_t:
        return InvariantResult(
            "CS-WVR-003",
            "FAIL",
            ["tiers/tier-packs.md#24-waiver_policy"],
            "Ensure tier-packs defines waiver_policy.allowed and max_active_waivers per tier (tier-3 disallows waivers).",
        )

    if "max_active_waivers" not in read_text(q) or "Verify tier allows waivers" not in read_text(q):
        return InvariantResult(
            "CS-WVR-003",
            "FAIL",
            ["gates/GATE_Q.md#q6--waivers-validity-if-present"],
            "Ensure Gate Q Q6 references tier waiver_policy and enforces allowance and max_active_waivers.",
        )

    ops_txt = read_text(ops).lower()
    if "limits per tier" not in ops_txt or ("tier 3" not in ops_txt and "tier-3" not in ops_txt):
        return InvariantResult(
            "CS-WVR-003",
            "FAIL",
            ["docs/operations/waivers.md#51-limits-per-tier"],
            "Ensure waivers.md repeats the tier waiver limits and disallows waivers for tier-3.",
        )

    return InvariantResult(
        "CS-WVR-003",
        "PASS",
        ["tiers/tier-packs.md#24-waiver_policy", "gates/GATE_Q.md#q6--waivers-validity-if-present", "docs/operations/waivers.md#51-limits-per-tier"],
        "",
    )


def check_cs_wvr_004(root: Path) -> InvariantResult:
    """CS-WVR-004 — Waivers are visible in sealing and replay bundles."""

    eb = repo_path(root, "docs/operations/evidence-bundles.md")
    sm = repo_path(root, "schemas/SealManifest.schema.json")
    ops = repo_path(root, "docs/operations/waivers.md")
    for rel, p in [("docs/operations/evidence-bundles.md", eb), ("schemas/SealManifest.schema.json", sm), ("docs/operations/waivers.md", ops)]:
        if not p.exists():
            return InvariantResult("CS-WVR-004", "FAIL", [], f"Missing {rel}.")

    if "waivers" not in read_text(eb).lower():
        return InvariantResult(
            "CS-WVR-004",
            "FAIL",
            ["docs/operations/evidence-bundles.md#11-mandatory-artifacts-minimum-replay-set"],
            "Ensure evidence-bundles mandates including waiver documents when LockedSpec.waivers_applied is non-empty.",
        )

    try:
        schema = load_json(sm)
        if "waivers" not in (schema.get("properties") or {}):
            return InvariantResult(
                "CS-WVR-004",
                "FAIL",
                ["schemas/SealManifest.schema.json#/properties"],
                "Ensure SealManifest schema defines waivers[] ObjectRefs.",
            )
    except Exception as e:
        return InvariantResult("CS-WVR-004", "FAIL", ["schemas/SealManifest.schema.json"], f"Fix SealManifest schema error ({e}).")

    if "visible in sealing" not in read_text(ops).lower():
        return InvariantResult(
            "CS-WVR-004",
            "FAIL",
            ["docs/operations/waivers.md#15-waivers-must-be-visible-in-sealing"],
            "Ensure waivers.md states waivers must be visible in sealing.",
        )

    return InvariantResult(
        "CS-WVR-004",
        "PASS",
        [
            "docs/operations/evidence-bundles.md#11-mandatory-artifacts-minimum-replay-set",
            "schemas/SealManifest.schema.json#/properties/waivers",
            "docs/operations/waivers.md#15-waivers-must-be-visible-in-sealing",
        ],
        "",
    )


def check_cs_wvr_005(root: Path) -> InvariantResult:
    """CS-WVR-005 — doc_impact enforcement does not introduce a waiver bypass."""

    q = repo_path(root, "gates/GATE_Q.md")
    r = repo_path(root, "gates/GATE_R.md")
    tiers = repo_path(root, "tiers/tier-packs.md")
    for rel, p in [("gates/GATE_Q.md", q), ("gates/GATE_R.md", r), ("tiers/tier-packs.md", tiers)]:
        if not p.exists():
            return InvariantResult("CS-WVR-005", "FAIL", [], f"Missing {rel}.")

    q_txt = read_text(q)
    r_txt = read_text(r)

    # Fail if doc_impact checks mention waivers (no bypass branches).
    if re.search(r"(?im)^###\s+Q-DOC-001\b[\s\S]{0,1600}\bwaiver\b", q_txt) or re.search(
        r"(?im)^###\s+Q-DOC-002\b[\s\S]{0,1600}\bwaiver\b", q_txt
    ):
        return InvariantResult(
            "CS-WVR-005",
            "FAIL",
            ["gates/GATE_Q.md#q-doc-002--doc_impact-tier-enforcement--note-on-empty"],
            "Remove waiver-based bypass logic from Q-DOC-001/Q-DOC-002 doc_impact enforcement.",
        )
    if re.search(r"(?im)^###\s+R-DOC-001\b[\s\S]{0,1600}\bwaiver\b", r_txt):
        return InvariantResult(
            "CS-WVR-005",
            "FAIL",
            ["gates/GATE_R.md#r-doc-001--doc_impact-enforced-with-diff"],
            "Remove waiver-based bypass logic from R-DOC-001 doc_impact enforcement.",
        )

    t_txt = read_text(tiers)
    if "tier-3" not in t_txt or "waiver_policy" not in t_txt or "allowed" not in t_txt:
        return InvariantResult(
            "CS-WVR-005",
            "FAIL",
            ["tiers/tier-packs.md#24-waiver_policy"],
            "Ensure tier waiver policy remains unchanged and tier-3 disallows waivers.",
        )

    return InvariantResult(
        "CS-WVR-005",
        "PASS",
        [
            "gates/GATE_Q.md#q-doc-002--doc_impact-tier-enforcement--note-on-empty",
            "gates/GATE_R.md#r-doc-001--doc_impact-enforced-with-diff",
            "tiers/tier-packs.md#24-waiver_policy",
        ],
        "",
    )


def check_cs_tpl_001(root: Path) -> InvariantResult:
    """CS-TPL-001 — PromptBundle policy_report payload includes required hashes and block identifiers."""

    pb = repo_path(root, "belgi/templates/PromptBundle.blocks.md")
    em = repo_path(root, "schemas/EvidenceManifest.schema.json")
    if not pb.exists() or not em.exists():
        return InvariantResult("CS-TPL-001", "FAIL", [], "Missing PromptBundle template and/or EvidenceManifest schema.")

    pb_txt = read_text(pb)
    must = ["A5.1", "block_ids", "block_hashes", "prompt_bundle_manifest_hash", "prompt_bundle_bytes_hash"]
    missing_must = _missing_needles(pb_txt, must)
    if missing_must:
        return InvariantResult(
            "CS-TPL-001",
            "FAIL",
            ["belgi/templates/PromptBundle.blocks.md#a51-required-evidence-artifact-policy_report"],
            "Ensure PromptBundle.blocks.md A5.1 lists required policy_report payload fields (block_ids/block_hashes and prompt_bundle hashes).",
        )

    try:
        schema = load_json(em)
        req = set(schema["properties"]["artifacts"]["items"]["required"])
        need = {"kind", "id", "hash", "media_type", "storage_ref", "produced_by"}
        if not need.issubset(req):
            return InvariantResult(
                "CS-TPL-001",
                "FAIL",
                ["schemas/EvidenceManifest.schema.json#/properties/artifacts/items/required"],
                "Ensure EvidenceManifest.artifacts[] supports indexing via kind/id/hash/media_type/storage_ref/produced_by without schema extension.",
            )
    except Exception as e:
        return InvariantResult("CS-TPL-001", "FAIL", ["schemas/EvidenceManifest.schema.json"], f"Fix EvidenceManifest schema error ({e}).")

    return InvariantResult(
        "CS-TPL-001",
        "PASS",
        [
            "belgi/templates/PromptBundle.blocks.md#a51-required-evidence-artifact-policy_report",
            "belgi/templates/PromptBundle.blocks.md#a34-canonical-promptbundle-hash",
            "schemas/EvidenceManifest.schema.json#/properties/artifacts/items/required",
        ],
        "",
    )


def check_cs_tpl_002(root: Path) -> InvariantResult:
    """CS-TPL-002 — PromptBundle integrity binds LockedSpec.prompt_bundle_ref."""

    pb = repo_path(root, "belgi/templates/PromptBundle.blocks.md")
    ls = repo_path(root, "schemas/LockedSpec.schema.json")
    if not pb.exists() or not ls.exists():
        return InvariantResult("CS-TPL-002", "FAIL", [], "Missing PromptBundle template and/or LockedSpec schema.")

    if "LockedSpec.prompt_bundle_ref" not in read_text(pb) and "prompt_bundle_ref" not in read_text(pb):
        return InvariantResult(
            "CS-TPL-002",
            "FAIL",
            ["belgi/templates/PromptBundle.blocks.md#a52-relationship-to-lockedspecprompt_bundle_ref"],
            "Ensure PromptBundle.blocks.md defines the relationship to LockedSpec.prompt_bundle_ref and deterministic integrity checks.",
        )

    try:
        schema = load_json(ls)
        if "prompt_bundle_ref" not in (schema.get("required") or []):
            return InvariantResult(
                "CS-TPL-002",
                "FAIL",
                ["schemas/LockedSpec.schema.json#/required"],
                "Ensure LockedSpec schema requires prompt_bundle_ref.",
            )
    except Exception as e:
        return InvariantResult("CS-TPL-002", "FAIL", ["schemas/LockedSpec.schema.json"], f"Fix LockedSpec schema error ({e}).")

    return InvariantResult(
        "CS-TPL-002",
        "PASS",
        [
            "belgi/templates/PromptBundle.blocks.md#a52-relationship-to-lockedspecprompt_bundle_ref",
            "belgi/templates/PromptBundle.blocks.md#fm-pb-004--hash-mismatch-between-declared-and-produced-artifacts",
            "schemas/LockedSpec.schema.json#/properties/prompt_bundle_ref",
        ],
        "",
    )


def check_cs_tpl_003(root: Path) -> InvariantResult:
    """CS-TPL-003 — DocsCompiler emits docs_compilation_log via existing schema fields."""

    dc = repo_path(root, "belgi/templates/DocsCompiler.template.md")
    em = repo_path(root, "schemas/EvidenceManifest.schema.json")
    if not dc.exists() or not em.exists():
        return InvariantResult("CS-TPL-003", "FAIL", [], "Missing DocsCompiler template and/or EvidenceManifest schema.")

    if "docs_compilation_log" not in read_text(dc):
        return InvariantResult(
            "CS-TPL-003",
            "FAIL",
            ["belgi/templates/DocsCompiler.template.md#b42-required-evidence-artifact-docs_compilation_log"],
            "Ensure DocsCompiler.template.md requires a docs_compilation_log artifact and specifies EvidenceManifest indexing.",
        )

    try:
        schema = load_json(em)
        kinds = set(schema["properties"]["artifacts"]["items"]["properties"]["kind"]["enum"])
        produced = set(schema["properties"]["artifacts"]["items"]["properties"]["produced_by"]["enum"])
        if "docs_compilation_log" not in kinds:
            return InvariantResult(
                "CS-TPL-003",
                "FAIL",
                ["schemas/EvidenceManifest.schema.json#/properties/artifacts/items/properties/kind/enum"],
                "Add docs_compilation_log to EvidenceManifest kind enum.",
            )
        if "C3" not in produced:
            return InvariantResult(
                "CS-TPL-003",
                "FAIL",
                ["schemas/EvidenceManifest.schema.json#/properties/artifacts/items/properties/produced_by/enum"],
                "Add C3 to EvidenceManifest.produced_by enum.",
            )
    except Exception as e:
        return InvariantResult("CS-TPL-003", "FAIL", ["schemas/EvidenceManifest.schema.json"], f"Fix EvidenceManifest schema error ({e}).")

    return InvariantResult(
        "CS-TPL-003",
        "PASS",
        [
            "belgi/templates/DocsCompiler.template.md#b42-required-evidence-artifact-docs_compilation_log",
            "schemas/EvidenceManifest.schema.json#/properties/artifacts/items/properties/kind/enum",
            "schemas/EvidenceManifest.schema.json#/properties/artifacts/items/properties/produced_by/enum",
        ],
        "",
    )


def check_cs_tpl_004(root: Path) -> InvariantResult:
    """CS-TPL-004 — Gate R obligations rely on existing evidence artifact indexing (no new schema fields)."""

    r = repo_path(root, "gates/GATE_R.md")
    em = repo_path(root, "schemas/EvidenceManifest.schema.json")
    if not r.exists() or not em.exists():
        return InvariantResult("CS-TPL-004", "FAIL", [], "Missing gates/GATE_R.md and/or schemas/EvidenceManifest.schema.json.")

    r_txt = read_text(r)
    must = [
        "policy report",
        "commands_executed",
        "Resolve bytes via the artifact’s `storage_ref`",
        "Compute `sha256(bytes)`",
        "PolicyReportPayload.schema.json",
        "TestReportPayload.schema.json",
        "MUST match **exactly one**",
    ]
    if any(m.lower() not in r_txt.lower() for m in must):
        return InvariantResult(
            "CS-TPL-004",
            "FAIL",
            ["gates/GATE_R.md#521-required-report-artifact-integrity--payload-validation-required"],
            "Ensure Gate R specifies required policy_report obligations satisfied via EvidenceManifest indexing + storage_ref bytes->hash verification + payload schema validation.",
        )

    try:
        schema = load_json(em)
        _ = schema["properties"]["artifacts"]["items"]["required"]
        _ = schema["properties"]["commands_executed"]["oneOf"]
    except Exception as e:
        return InvariantResult("CS-TPL-004", "FAIL", ["schemas/EvidenceManifest.schema.json"], f"Fix EvidenceManifest schema error ({e}).")

    return InvariantResult(
        "CS-TPL-004",
        "PASS",
        [
            "gates/GATE_R.md#52-policy-report-naming-convention-used-by-r1r7r8",
            "gates/GATE_R.md#51-command-matching-rule-used-by-r1r5r6r7r8",
            "gates/GATE_R.md#521-required-report-artifact-integrity--payload-validation-required",
            "schemas/EvidenceManifest.schema.json#/properties/artifacts/items/required",
            "schemas/EvidenceManifest.schema.json#/properties/commands_executed/oneOf",
        ],
        "",
    )


def check_cs_tpl_005(root: Path) -> InvariantResult:
    """CS-TPL-005 — Docs compilation does not change verification outcomes."""

    dc = repo_path(root, "belgi/templates/DocsCompiler.template.md")
    can = repo_path(root, "CANONICALS.md")
    tiers = repo_path(root, "tiers/tier-packs.md")
    for rel, p in [("belgi/templates/DocsCompiler.template.md", dc), ("CANONICALS.md", can), ("tiers/tier-packs.md", tiers)]:
        if not p.exists():
            return InvariantResult("CS-TPL-005", "FAIL", [], f"Missing {rel}.")

    dc_txt = read_text(dc)
    if "post-verification" not in dc_txt.lower() or "must not change verification outcomes" not in dc_txt.lower():
        return InvariantResult(
            "CS-TPL-005",
            "FAIL",
            ["belgi/templates/DocsCompiler.template.md#b1-purpose"],
            "Ensure DocsCompiler.template.md states C3 is post-verification and must not change Gate R outcomes.",
        )
    if "MUST NOT require" not in read_text(tiers) or "docs_compilation_log" not in read_text(tiers):
        return InvariantResult(
            "CS-TPL-005",
            "FAIL",
            ["tiers/tier-packs.md#21-required_evidence_kinds"],
            "Ensure tier-packs note states Gate R MUST NOT require docs_compilation_log.",
        )
    if "C3" not in read_text(can) or "Docs Compiler" not in read_text(can):
        return InvariantResult(
            "CS-TPL-005",
            "FAIL",
            ["CANONICALS.md#c3-docs-compiler"],
            "Ensure CANONICALS describes C3 as deterministic documentation from the verified state.",
        )

    return InvariantResult(
        "CS-TPL-005",
        "PASS",
        [
            "belgi/templates/DocsCompiler.template.md#b5-verification-expectations-gate-r--replay",
            "tiers/tier-packs.md#21-required_evidence_kinds",
            "CANONICALS.md#c3-docs-compiler",
        ],
        "",
    )


def check_cs_gv_001(root: Path) -> InvariantResult:
    """CS-GV-001 — GateVerdict schema requires run_id."""

    p = repo_path(root, "schemas/GateVerdict.schema.json")
    if not p.exists():
        return InvariantResult("CS-GV-001", "FAIL", [], "Missing schemas/GateVerdict.schema.json.")

    schema = load_json(p)
    req = set(schema.get("required", []))
    props = schema.get("properties", {})
    run_prop = props.get("run_id", {}) if isinstance(props, dict) else {}

    if "run_id" not in req:
        return InvariantResult(
            "CS-GV-001",
            "FAIL",
            ["schemas/GateVerdict.schema.json#/required"],
            "Add run_id to GateVerdict required list.",
        )
    if not isinstance(run_prop, dict) or run_prop.get("type") != "string" or int(run_prop.get("minLength", 0) or 0) < 1:
        return InvariantResult(
            "CS-GV-001",
            "FAIL",
            ["schemas/GateVerdict.schema.json#/properties/run_id"],
            "Define GateVerdict.run_id as non-empty string.",
        )

    return InvariantResult("CS-GV-001", "PASS", ["schemas/GateVerdict.schema.json#/properties/run_id"], "")


def check_cs_ls_001(root: Path) -> InvariantResult:
    """CS-LS-001 — LockedSpec constraints items enforce RepoRelPathPrefix normalization."""

    p = repo_path(root, "schemas/LockedSpec.schema.json")
    if not p.exists():
        return InvariantResult("CS-LS-001", "FAIL", [], "Missing schemas/LockedSpec.schema.json.")

    schema = load_json(p)
    try:
        constraints_props = schema["properties"]["constraints"]["properties"]
        items_allowed = constraints_props["allowed_paths"]["items"]
        items_forbidden = constraints_props["forbidden_paths"]["items"]
    except Exception:
        return InvariantResult(
            "CS-LS-001",
            "FAIL",
            ["schemas/LockedSpec.schema.json#/properties/constraints"],
            "LockedSpec.constraints missing allowed_paths/forbidden_paths items.",
        )

    def get_pattern(item_schema: Any) -> str | None:
        if isinstance(item_schema, dict) and "pattern" in item_schema:
            return item_schema.get("pattern")
        if isinstance(item_schema, dict) and "$ref" in item_schema:
            ref = item_schema["$ref"]
            if isinstance(ref, str) and ref.startswith("#/"):
                target = json_pointer(schema, ref)
                if isinstance(target, dict) and "pattern" in target:
                    return target.get("pattern")
        return None

    patt_a = get_pattern(items_allowed)
    patt_f = get_pattern(items_forbidden)
    if not patt_a or not patt_f:
        return InvariantResult(
            "CS-LS-001",
            "FAIL",
            [
                "schemas/LockedSpec.schema.json#/properties/constraints/properties/allowed_paths/items",
                "schemas/LockedSpec.schema.json#/properties/constraints/properties/forbidden_paths/items",
            ],
            "Ensure constraints.allowed_paths[].items and forbidden_paths[].items enforce RepoRelPathPrefix via pattern (inline or $ref).",
        )

    def forbids_dotdot(patt: str) -> bool:
        return (".." in patt) or ("\\.\\." in patt)

    must_tokens = ["(?!/)", "(?!.*\\\\)", "(?!.*\\*)", "(?!.*\\?)", "(?!.*//)", "(?!\\./)"]
    if not forbids_dotdot(patt_a) or not forbids_dotdot(patt_f):
        return InvariantResult(
            "CS-LS-001",
            "FAIL",
            ["schemas/LockedSpec.schema.json#/$defs/RepoRelPathPrefix"],
            "RepoRelPathPrefix pattern must forbid '..' segments.",
        )
    for token in must_tokens:
        if token not in patt_a or token not in patt_f:
            return InvariantResult(
                "CS-LS-001",
                "FAIL",
                ["schemas/LockedSpec.schema.json#/$defs/RepoRelPathPrefix"],
                "RepoRelPathPrefix pattern must forbid '/', './', '//', '\\', '*' and '?' patterns.",
            )

    return InvariantResult(
        "CS-LS-001",
        "PASS",
        ["schemas/LockedSpec.schema.json#/properties/constraints", "schemas/LockedSpec.schema.json#/$defs/RepoRelPathPrefix"],
        "",
    )


def check_cs_ref_001(root: Path) -> InvariantResult:
    """CS-REF-001 — ObjectRef storage_ref is constrained in every schema definition."""

    targets = [
        ("schemas/LockedSpec.schema.json", "#/$defs/ObjectRef/properties/storage_ref"),
        ("schemas/EvidenceManifest.schema.json", "#/$defs/ObjectRef/properties/storage_ref"),
        ("schemas/GateVerdict.schema.json", "#/$defs/ObjectRef/properties/storage_ref"),
        ("schemas/SealManifest.schema.json", "#/$defs/ObjectRef/properties/storage_ref"),
        ("schemas/Waiver.schema.json", "#/$defs/AuditTrailRef/properties/storage_ref"),
    ]

    bad: List[str] = []
    for rel, ptr in targets:
        p = repo_path(root, rel)
        if not p.exists():
            bad.append(f"{rel} (missing)")
            continue
        doc = load_json(p)
        try:
            sr = json_pointer(doc, ptr)
        except Exception:
            bad.append(f"{rel}{ptr} (missing)")
            continue
        if not isinstance(sr, dict) or "pattern" not in sr:
            bad.append(f"{rel}{ptr} (no pattern)")
            continue
        patt = sr.get("pattern")
        if not isinstance(patt, str) or not patt:
            bad.append(f"{rel}{ptr} (empty pattern)")
            continue
        required_fragments = ["(?!/)", "(?!.*\\\\)", "(?!.*://)", "(?!.*:)", "(?!.*//)", "(?!\\./)"]
        has_dotdot_forbid = (".." in patt) or ("\\.\\." in patt)
        if (not has_dotdot_forbid) or any(frag not in patt for frag in required_fragments):
            bad.append(f"{rel}{ptr} (pattern missing required constraints)")

    if bad:
        return InvariantResult(
            "CS-REF-001",
            "FAIL",
            bad[:8],
            "Constrain storage_ref with a safe local-only pattern in all schema ObjectRef-like definitions.",
        )

    return InvariantResult("CS-REF-001", "PASS", [f"{rel}{ptr}" for rel, ptr in targets], "")


def check_cs_verify_bundle_001(root: Path) -> InvariantResult:
    """CS-VERIFY_BUNDLE-001 — Canonical verifier entrypoint exists."""

    p = repo_path(root, "chain/gate_r_verify.py")
    if not p.exists():
        return InvariantResult(
            "CS-VERIFY_BUNDLE-001",
            "FAIL",
            [],
            "Add chain/gate_r_verify.py deterministic verifier entrypoint and rerun sweep.",
        )

    return InvariantResult("CS-VERIFY_BUNDLE-001", "PASS", ["chain/gate_r_verify.py"], "")


def check_cs_gate_r_mandates_verify_bundle_001(root: Path) -> InvariantResult:
    """CS-GATE_R-MANDATES-VERIFY_BUNDLE-001 — Gate R explicitly requires verify_bundle."""

    p = repo_path(root, "gates/GATE_R.md")
    if not p.exists():
        return InvariantResult("CS-GATE_R-MANDATES-VERIFY_BUNDLE-001", "FAIL", [], "Missing gates/GATE_R.md.")

    md = read_text(p)
    must_have = [
        "chain/gate_r_verify.py",
        "MUST",
        "MUST match **exactly one**",
        "If it matches 0 entries => **NO-GO**.",
        "If it matches more than 1 entry => **NO-GO**.",
        "Resolve bytes via the artifact’s `storage_ref`",
        "Compute `sha256(bytes)`",
        "PolicyReportPayload.schema.json",
        "TestReportPayload.schema.json",
    ]
    missing = [s for s in must_have if s not in md]
    if missing:
        return InvariantResult(
            "CS-GATE_R-MANDATES-VERIFY_BUNDLE-001",
            "FAIL",
            ["gates/GATE_R.md#522-canonical-deterministic-verifier-must"],
            f"Gate R must explicitly mandate the canonical verifier and its enforced contracts; missing: {missing[:5]}",
        )

    return InvariantResult(
        "CS-GATE_R-MANDATES-VERIFY_BUNDLE-001",
        "PASS",
        ["gates/GATE_R.md#522-canonical-deterministic-verifier-must"],
        "",
    )


def check_cs_verify_bundle_gateverdict_binding_001(root: Path) -> InvariantResult:
    """CS-VERIFY_BUNDLE-GATEVERDICT-BINDING-001 — Gate R mentions optional verdict→manifest binding."""

    p = repo_path(root, "gates/GATE_R.md")
    if not p.exists():
        return InvariantResult("CS-VERIFY_BUNDLE-GATEVERDICT-BINDING-001", "FAIL", [], "Missing gates/GATE_R.md.")

    md = read_text(p)
    must_phrases = [
        "GateVerdict.evidence_manifest_ref",
        "MUST",
        "resolve",
        "sha256",
        "gate_r_verify",
    ]
    if not all(s.lower() in md.lower() for s in must_phrases):
        return InvariantResult(
            "CS-VERIFY_BUNDLE-GATEVERDICT-BINDING-001",
            "FAIL",
            ["gates/GATE_R.md"],
            "When GateVerdict is provided, Gate R must state the verdict's evidence_manifest_ref resolves under repo root and sha256(bytes) matches the declared hash.",
        )

    return InvariantResult("CS-VERIFY_BUNDLE-GATEVERDICT-BINDING-001", "PASS", ["gates/GATE_R.md"], "")


def check_cs_render_001(root: Path) -> InvariantResult:
    """CS-RENDER-001 — Render targets must not drift.

    Verifies that all registered render targets (JSON canonical → MD generated view)
    have no drift. Uses tools/render.py check_target_drift() for comparison.
    """
    # Import render module (fail-closed if unavailable)
    try:
        from tools.render import check_target_drift, get_all_target_names, get_target_evidence_files
    except ImportError as e:
        return InvariantResult(
            "CS-RENDER-001",
            "FAIL",
            [],
            f"Cannot import tools/render.py: {e}. Ensure render.py exists.",
        )

    target_names = get_all_target_names()
    if not target_names:
        # No registered targets is valid (no drift possible)
        return InvariantResult(
            "CS-RENDER-001",
            "PASS",
            ["tools/render.py"],
            "",
        )

    drift_targets: list[str] = []
    evidence: set[str] = {"tools/render.py"}

    for target_name in target_names:
        # Add target-specific evidence files
        evidence.update(get_target_evidence_files(target_name))
        has_drift, msg = check_target_drift(root, target_name)
        if has_drift:
            drift_targets.append(target_name)

    if drift_targets:
        regen_cmds = [f"python -m tools.render {t} --repo ." for t in drift_targets]
        return InvariantResult(
            "CS-RENDER-001",
            "FAIL",
            sorted(evidence),
            f"Render drift detected for: {', '.join(drift_targets)}. Regenerate: {'; '.join(regen_cmds)}",
        )

    return InvariantResult(
        "CS-RENDER-001",
        "PASS",
        sorted(evidence),
        "",
    )


def check_cs_r0_enforcement_wired_001(root: Path) -> InvariantResult:
    """CS-R0-ENFORCEMENT-WIRED-001 — R0 evidence sufficiency check is wired into registry."""

    p = repo_path(root, "chain/logic/r_checks/registry.py")
    if not p.exists():
        return InvariantResult("CS-R0-ENFORCEMENT-WIRED-001", "FAIL", [], "Missing chain/logic/r_checks/registry.py.")

    txt = read_text(p)
    required = [
        "r0_evidence_sufficiency",
        "r0_evidence_sufficiency.run",
    ]
    if not all(s in txt for s in required):
        return InvariantResult(
            "CS-R0-ENFORCEMENT-WIRED-001",
            "FAIL",
            ["chain/logic/r_checks/registry.py"],
            "Wire chain/logic/r_checks/r0_evidence_sufficiency.py into chain/logic/r_checks/registry.py deterministic check order.",
        )

    return InvariantResult(
        "CS-R0-ENFORCEMENT-WIRED-001",
        "PASS",
        ["chain/logic/r_checks/registry.py"],
        "",
    )


def build_inputs(root: Path, rel_paths: list[str], *, blob_overrides: dict[str, bytes] | None = None) -> list[dict[str, str]]:
    overrides = {_validate_repo_rel(k): v for k, v in (blob_overrides or {}).items()}
    out: list[dict[str, str]] = []
    for rel in rel_paths:
        rel = _validate_repo_rel(rel)
        if rel in overrides:
            h = hashlib.sha256(overrides[rel]).hexdigest()
        else:
            p = _resolve_repo_path(root, rel, must_exist=True, must_be_file=True)
            h = sha256_file(p)  # sende hangisi varsa: _sha256_file vs
        out.append({"path": rel, "sha256": h})
    out.sort(key=lambda d: d["path"])
    return out


def _iter_schema_files(repo_root: Path) -> list[str]:
    schemas_dir = _resolve_repo_path(repo_root, "schemas", must_exist=True, must_be_file=False)

    out: list[str] = []
    for p in sorted(schemas_dir.glob("*.schema.json"), key=lambda x: x.name):
        rel = p.resolve().relative_to(repo_root.resolve()).as_posix()
        out.append(rel)
    return out


def _iter_builtin_protocol_pack_files(repo_root: Path) -> list[str]:
    """Deterministically enumerate builtin protocol pack files.

    These are part of the governed surface because fixture pins depend on the
    active builtin pack identity and the manifest is validated against its tree.
    Fail-closed on symlinks.
    """

    pack_root = _resolve_repo_path(repo_root, "belgi/_protocol_packs/v1", must_exist=True, must_be_file=False)
    if not pack_root.is_dir():
        raise _UserInputError("builtin protocol pack root is not a directory: belgi/_protocol_packs/v1")

    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(pack_root, followlinks=False):
        d = Path(dirpath)
        if d.is_symlink():
            raise _UserInputError(f"symlink directory not allowed under belgi/_protocol_packs/v1: {d}")
        dirnames.sort()
        filenames.sort()
        for name in filenames:
            p = d / name
            if p.is_symlink():
                raise _UserInputError(f"symlink file not allowed under belgi/_protocol_packs/v1: {p}")
            rel = p.resolve().relative_to(repo_root.resolve()).as_posix()
            out.append(rel)

    out.sort()
    return out


def _canonical_inputs(repo_root: Path) -> list[str]:
    # Core, explicitly governed files.
    base = [
        "CANONICALS.md",
        "README.md",
        "CHANGELOG.md",
        "VERSION",
        "terminology.md",
        "trust-model.md",
        "gates/GATE_Q.md",
        "gates/GATE_R.md",
        "gates/failure-taxonomy.md",
        ".github/workflows/ci.yml",
        "tiers/tier-packs.md",
        "tiers/tier-packs.json",
        "tiers/tier-packs.template.md",
        # Human-facing wrapper entrypoints
        "wrapper/gate_Q.py",
        "wrapper/gate_R.py",
        "wrapper/comp_C1.py",
        "wrapper/comp_C3.py",
        "wrapper/seal_S.py",
        # Canonical templates / runbooks
        "belgi/templates/IntentSpec.core.template.md",
        "belgi/templates/PromptBundle.blocks.md",
        "belgi/templates/DocsCompiler.template.md",
        "docs/operations/running-belgi.md",
        "docs/operations/evidence-bundles.md",
        "docs/operations/waivers.md",
        "docs/operations/security.md",
        "docs/operations/consistency-sweep.md",
        "docs/research/experiment-design.md",
        # Canonical deterministic verifier entrypoints
        "chain/gate_q_verify.py",
        "chain/gate_r_verify.py",
        "chain/gate_s_verify.py",
        "chain/seal_bundle.py",
        "chain/compiler_c3_docs.py",
        # Canonical tools
        "tools/render.py",
        "tools/normalize.py",
        "tools/rehash.py",
        "tools/sweep.py",
        # Fixture governance
        "policy/fixtures/public/gate_q/cases.json",
        "policy/fixtures/public/gate_r/cases.json",
        # R-check wiring governance
        "chain/logic/r_checks/context.py",
        "chain/logic/r_checks/registry.py",
        "chain/logic/r_checks/r0_evidence_sufficiency.py",
        "chain/logic/r_checks/r_doc_001_doc_impact.py",
        "chain/logic/r_checks/r4_schema_contract.py",
        # Schema index doc
        "schemas/README.md",
    ]

    # Dynamic, authoritative schema surface.
    base.extend(_iter_schema_files(repo_root))

    # Dynamic, authoritative builtin protocol pack surface.
    base.extend(_iter_builtin_protocol_pack_files(repo_root))

    # Normalize, de-dup, stable order.
    canon = sorted(set(_validate_repo_rel(p) for p in base))
    return canon


def check_cs_byte_001(root: Path) -> InvariantResult:
    """CS-BYTE-001 — Byte Integrity: tools/normalize.py --check must pass."""

    # CS-BYTE-001 MUST use the exact Byte Guard enumeration + detector to avoid drift.
    from tools.normalize import scan_byte_guard

    # Exclude sweep outputs so CS-BYTE-001 cannot self-invalidate the consistency sweep fixed-point.
    report = scan_byte_guard(
        root,
        tracked_only=True,
        exclude_roots=None,
        exclude_paths=[CANONICAL_SWEEP_OUT, CANONICAL_SWEEP_SUMMARY],
        allow_empty=False,
        mode="check",
    )
    details = {
        "scope": "tracked-only",
        "surface": report.get("surface"),
        "counts": report.get("counts"),
        "drift_files": report.get("drift_files"),
    }
    status = str(report.get("status") or "FAIL")
    if status != "PASS":
        return InvariantResult(
            "CS-BYTE-001",
            "FAIL",
            ["tools/normalize.py"],
            "Run python -m tools.normalize --fix --tracked-only to eliminate CRLF drift, then rerun the sweep.",
            details,
        )
    return InvariantResult("CS-BYTE-001", "PASS", ["tools/normalize.py"], "", details)


def _find_em_artifacts(em: dict[str, Any], *, kind: str, artifact_id: str) -> list[dict[str, Any]]:
    arts = em.get("artifacts")
    if not isinstance(arts, list):
        return []
    return [a for a in arts if isinstance(a, dict) and a.get("kind") == kind and a.get("id") == artifact_id]


def _locked_spec_tier_id(ls: dict[str, Any]) -> str | None:
    tier = ls.get("tier")
    if not isinstance(tier, dict):
        return None
    tid = tier.get("tier_id")
    return tid if isinstance(tid, str) and tid.strip() else None


def _manifest_claims_tier_ge_1(ls: dict[str, Any] | None, em: dict[str, Any]) -> bool:
    if ls is not None:
        tid = _locked_spec_tier_id(ls)
        return tid in ("tier-1", "tier-2", "tier-3")

    # Fallback: treat presence of tier>=1-only evidence kinds as a tier>=1 claim.
    arts = em.get("artifacts")
    if not isinstance(arts, list):
        return False
    kinds = {a.get("kind") for a in arts if isinstance(a, dict)}
    return ("env_attestation" in kinds) or ("test_report" in kinds)
def _write_json_deterministic(path: Path, obj: Any) -> None:
    _atomic_write_text(path, json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=True) + "\n")


def _fix_cs_ev_006_manifest(*, em_obj: dict[str, Any], expected_hash: str) -> bool:
    artifacts = em_obj.get("artifacts")
    if not isinstance(artifacts, list):
        artifacts = []
        em_obj["artifacts"] = artifacts

    matches = [
        (idx, a)
        for idx, a in enumerate(artifacts)
        if isinstance(a, dict) and a.get("kind") == "policy_report" and a.get("id") == "policy.consistency_sweep"
    ]

    changed = False
    if not matches:
        new_art = {
            "kind": "policy_report",
            "id": "policy.consistency_sweep",
            "hash": expected_hash,
            "media_type": "application/json",
            "storage_ref": CANONICAL_SWEEP_OUT,
            "produced_by": "C1",
        }
        # Stable insertion: after last policy_report, else at end.
        insert_at = 0
        for i, a in enumerate(artifacts):
            if isinstance(a, dict) and a.get("kind") == "policy_report":
                insert_at = i + 1
        artifacts.insert(insert_at, new_art)
        return True

    # De-duplicate deterministically: keep first occurrence by list order.
    keep_idx, keep = matches[0]
    for del_idx, _ in reversed(matches[1:]):
        del artifacts[del_idx]
        changed = True

    # Normalize required fields deterministically.
    if keep.get("hash") != expected_hash:
        keep["hash"] = expected_hash
        changed = True
    if keep.get("storage_ref") != CANONICAL_SWEEP_OUT:
        keep["storage_ref"] = CANONICAL_SWEEP_OUT
        changed = True
    if keep.get("media_type") != "application/json":
        keep["media_type"] = "application/json"
        changed = True
    if keep.get("produced_by") != "C1":
        keep["produced_by"] = "C1"
        changed = True
    if keep.get("kind") != "policy_report":
        keep["kind"] = "policy_report"
        changed = True
    if keep.get("id") != "policy.consistency_sweep":
        keep["id"] = "policy.consistency_sweep"
        changed = True
    return changed


def _eval_cs_ev_006_expected_hash(root: Path, expected_hash: str, *, fix_fixtures: bool) -> tuple[InvariantResult, list[str]]:
    """Evaluate CS-EV-006 against an expected sweep artifact hash.

    This avoids circular dependence on reading policy/consistency_sweep.json while it is being generated.
    """

    # Primary enforcement surface: governed public Gate R fixtures.
    cases_path = _resolve_repo_path(root, "policy/fixtures/public/gate_r/cases.json", must_exist=True, must_be_file=True)
    cases_obj = load_json(cases_path)
    if not isinstance(cases_obj, dict) or not isinstance(cases_obj.get("cases"), list):
        return (
            InvariantResult(
                "CS-EV-006",
                "FAIL",
                ["policy/fixtures/public/gate_r/cases.json"],
                "Fix cases.json shape, then rerun sweep.",
            ),
            [],
        )

    # Deterministic + bounded: details must never explode artifact size.
    max_violations = 50

    violations: list[dict[str, Any]] = []
    modified: list[str] = []
    checked_cases = 0

    cases = [c for c in cases_obj["cases"] if isinstance(c, dict)]
    cases.sort(key=lambda c: str(c.get("case_id") or "").strip())
    for c in cases:
        case_id = str(c.get("case_id") or "").strip()
        paths = c.get("paths")
        if not isinstance(paths, dict):
            continue
        ls_rel = paths.get("locked_spec")
        em_rel = paths.get("evidence_manifest")
        if not isinstance(ls_rel, str) or not isinstance(em_rel, str):
            continue

        # Only enforce strictly for fixtures expected to PASS.
        expected_exit_code = c.get("expected_exit_code")
        if expected_exit_code != 0:
            continue

        try:
            ls_path = _resolve_repo_path(root, ls_rel, must_exist=True, must_be_file=True)
            em_path = _resolve_repo_path(root, em_rel, must_exist=True, must_be_file=True)
        except _UserInputError as e:
            violations.append(
                {
                    "case_id": case_id,
                    "locked_spec": ls_rel,
                    "evidence_manifest": em_rel,
                    "code": "path_invalid",
                    "message": str(e),
                    "declared_hash": None,
                    "declared_storage_ref": None,
                }
            )
            continue

        try:
            ls_obj = load_json(ls_path)
            em_obj = load_json(em_path)
        except Exception as e:
            violations.append(
                {
                    "case_id": case_id,
                    "locked_spec": ls_rel,
                    "evidence_manifest": em_rel,
                    "code": "invalid_json",
                    "message": str(e),
                    "declared_hash": None,
                    "declared_storage_ref": None,
                }
            )
            continue

        if not isinstance(ls_obj, dict) or not isinstance(em_obj, dict):
            violations.append(
                {
                    "case_id": case_id,
                    "locked_spec": ls_rel,
                    "evidence_manifest": em_rel,
                    "code": "invalid_json",
                    "message": "LockedSpec/EvidenceManifest must be JSON objects",
                    "declared_hash": None,
                    "declared_storage_ref": None,
                }
            )
            continue

        if not _manifest_claims_tier_ge_1(ls_obj, em_obj):
            continue

        checked_cases += 1

        if fix_fixtures:
            changed = _fix_cs_ev_006_manifest(em_obj=em_obj, expected_hash=expected_hash)
            if changed:
                _write_json_deterministic(em_path, em_obj)
                modified.append(em_rel)

        matches = _find_em_artifacts(em_obj, kind="policy_report", artifact_id="policy.consistency_sweep")
        if not matches:
            violations.append(
                {
                    "case_id": case_id,
                    "locked_spec": ls_rel,
                    "evidence_manifest": em_rel,
                    "code": "missing_entry",
                    "message": "missing policy_report:policy.consistency_sweep",
                    "declared_hash": None,
                    "declared_storage_ref": None,
                }
            )
            continue

        if len(matches) != 1:
            first = matches[0]
            violations.append(
                {
                    "case_id": case_id,
                    "locked_spec": ls_rel,
                    "evidence_manifest": em_rel,
                    "code": "ambiguous_entry",
                    "message": f"ambiguous policy_report:policy.consistency_sweep (count={len(matches)})",
                    "declared_hash": first.get("hash") if isinstance(first.get("hash"), str) else None,
                    "declared_storage_ref": first.get("storage_ref") if isinstance(first.get("storage_ref"), str) else None,
                }
            )
            continue

        art = matches[0]

        storage_ref = art.get("storage_ref")
        if storage_ref != CANONICAL_SWEEP_OUT:
            violations.append(
                {
                    "case_id": case_id,
                    "locked_spec": ls_rel,
                    "evidence_manifest": em_rel,
                    "code": "wrong_storage_ref",
                    "message": f"storage_ref must be {CANONICAL_SWEEP_OUT}",
                    "declared_hash": art.get("hash") if isinstance(art.get("hash"), str) else None,
                    "declared_storage_ref": storage_ref if isinstance(storage_ref, str) else None,
                }
            )
            continue

        declared_hash = art.get("hash")
        if not isinstance(declared_hash, str) or declared_hash != expected_hash:
            violations.append(
                {
                    "case_id": case_id,
                    "locked_spec": ls_rel,
                    "evidence_manifest": em_rel,
                    "code": "hash_mismatch",
                    "message": "policy.consistency_sweep hash mismatch",
                    "declared_hash": declared_hash if isinstance(declared_hash, str) else None,
                    "declared_storage_ref": CANONICAL_SWEEP_OUT,
                }
            )
            continue

    violations.sort(
        key=lambda v: (
            str(v.get("case_id") or ""),
            str(v.get("code") or ""),
            str(v.get("evidence_manifest") or ""),
            str(v.get("locked_spec") or ""),
        )
    )
    modified = sorted(set(_validate_repo_rel(p) for p in modified))

    if violations:
        total = len(violations)
        truncated = total > max_violations
        vios_out = violations[:max_violations]
        details = {
            "expected_hash": expected_hash,
            "cases_file": "policy/fixtures/public/gate_r/cases.json",
            "checked_cases": checked_cases,
            "violations_total": total,
            "violations_truncated": truncated,
            "violations": vios_out,
        }
        remediation = (
            f"Index policy.consistency_sweep in every Tier>=1 PASS EvidenceManifest (fixtures) with hash={expected_hash}, then rerun the sweep."
        )
        if not fix_fixtures:
            remediation += " (Tip: run python -m tools.sweep consistency --repo . --fix-fixtures)"
        return (
            InvariantResult(
                "CS-EV-006",
                "FAIL",
                ["policy/fixtures/public/gate_r/cases.json", CANONICAL_SWEEP_OUT],
                remediation,
                details,
            ),
            modified,
        )
    # PASS: details MUST be absent (fixed-point hash stability).
    return (InvariantResult("CS-EV-006", "PASS", ["policy/fixtures/public/gate_r/cases.json"], ""), modified)


def check_cs_ev_006(root: Path) -> InvariantResult:
    """CS-EV-006 — Manifest Completeness: Tier>=1 manifests must index policy.consistency_sweep.

    The canonical consistency sweep command evaluates this invariant against the would-be report hash
    (see _consistency_sweep_main). This shim is fail-closed for any other callers.
    """

    try:
        p = _resolve_repo_path(root, CANONICAL_SWEEP_OUT, must_exist=True, must_be_file=True)
    except _UserInputError:
        return InvariantResult(
            "CS-EV-006",
            "FAIL",
            ["policy/fixtures/public/gate_r/cases.json", CANONICAL_SWEEP_OUT],
            "Missing policy/consistency_sweep.json; run the consistency sweep to generate it, then rerun.",
        )
    res, _ = _eval_cs_ev_006_expected_hash(root, sha256_file(p), fix_fixtures=False)
    return res


def _iter_fixture_locked_specs(repo_root: Path) -> list[Path]:
    """Deterministically enumerate policy/fixtures/**/LockedSpec.json.

    Fail-closed on symlinks anywhere under policy/fixtures.
    """

    base = _resolve_repo_path(repo_root, "policy/fixtures", must_exist=True, must_be_file=False)
    if not base.is_dir():
        raise _UserInputError("policy/fixtures is not a directory")

    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        d = Path(dirpath)
        if d.is_symlink():
            raise _UserInputError(f"symlink directory not allowed under policy/fixtures: {d}")
        dirnames.sort()
        filenames.sort()
        for name in filenames:
            p = d / name
            if p.is_symlink():
                raise _UserInputError(f"symlink file not allowed under policy/fixtures: {p}")
            if name == "LockedSpec.json":
                out.append(p)

    out.sort(key=lambda p: p.relative_to(repo_root.resolve()).as_posix())
    return out


def check_cs_pack_identity_001(root: Path) -> InvariantResult:
    """CS-PACK-IDENTITY-001 — Fixture LockedSpec protocol_pack pins match active builtin pack."""

    from belgi.protocol.pack import MANIFEST_FILENAME, validate_manifest_bytes

    pack_root = _resolve_repo_path(root, "belgi/_protocol_packs/v1", must_exist=True, must_be_file=False)
    manifest_path = pack_root / MANIFEST_FILENAME
    if not manifest_path.exists() or not manifest_path.is_file() or manifest_path.is_symlink():
        return InvariantResult(
            "CS-PACK-IDENTITY-001",
            "FAIL",
            [CONSISTENCY_SPEC_DOC],
            "Missing or invalid builtin protocol pack manifest under belgi/_protocol_packs/v1; rebuild/restore it, then rerun sweep.",
        )

    manifest_bytes = manifest_path.read_bytes()
    try:
        validate_manifest_bytes(pack_root=pack_root, manifest_bytes=manifest_bytes)
    except Exception as e:
        return InvariantResult(
            "CS-PACK-IDENTITY-001",
            "FAIL",
            [CONSISTENCY_SPEC_DOC],
            f"Builtin protocol pack manifest invalid: {e}. Fix manifest/tree binding, then rerun sweep.",
        )

    parsed = json.loads(manifest_bytes.decode("utf-8", errors="strict"))
    if not isinstance(parsed, dict) or not isinstance(parsed.get("pack_id"), str) or not str(parsed.get("pack_id") or "").strip():
        return InvariantResult(
            "CS-PACK-IDENTITY-001",
            "FAIL",
            [CONSISTENCY_SPEC_DOC],
            "Builtin protocol pack manifest missing/invalid pack_id; fix it, then rerun sweep.",
        )

    pack_id = str(parsed.get("pack_id") or "").strip()
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()

    locked_specs = _iter_fixture_locked_specs(root)
    if not locked_specs:
        return InvariantResult(
            "CS-PACK-IDENTITY-001",
            "FAIL",
            [CONSISTENCY_SPEC_DOC],
            "NO-GO: no fixture LockedSpec targets found (checked 0).",
        )

    mismatches: list[str] = []
    invalid: list[str] = []
    for p in locked_specs:
        rel = p.relative_to(root.resolve()).as_posix()
        try:
            doc = json.loads(read_text(p))
        except Exception as e:
            invalid.append(f"{rel}: JSON parse error: {e}")
            continue
        if not isinstance(doc, dict):
            invalid.append(f"{rel}: LockedSpec is not an object")
            continue
        pp = doc.get("protocol_pack")
        if not isinstance(pp, dict):
            mismatches.append(f"{rel}: protocol_pack missing/invalid")
            continue
        if pp.get("pack_id") != pack_id or pp.get("manifest_sha256") != manifest_sha256:
            mismatches.append(
                f"{rel}: pin mismatch pack_id={str(pp.get('pack_id') or '')[:8]}.. manifest_sha256={str(pp.get('manifest_sha256') or '')[:8]}.."
            )

    if invalid or mismatches:
        details: dict[str, Any] = {
            "pack_id": pack_id,
            "manifest_sha256": manifest_sha256,
            "checked": len(locked_specs),
            "invalid_total": len(invalid),
            "mismatches_total": len(mismatches),
            "invalid_sample": sorted(invalid)[:8],
            "mismatches_sample": sorted(mismatches)[:8],
        }
        return InvariantResult(
            "CS-PACK-IDENTITY-001",
            "FAIL",
            [CONSISTENCY_SPEC_DOC, "belgi/_protocol_packs/v1/ProtocolPackManifest.json"],
            "Run `python -m tools.belgi fixtures sync-pack-identity --repo . --pack-dir belgi/_protocol_packs/v1`, then rerun the sweep.",
            details,
        )

    return InvariantResult(
        "CS-PACK-IDENTITY-001",
        "PASS",
        [CONSISTENCY_SPEC_DOC, "belgi/_protocol_packs/v1/ProtocolPackManifest.json"],
        "",
    )


def check_cs_seal_keypair_001(root: Path) -> InvariantResult:
    """CS-SEAL-KEYPAIR-001 — SEAL fixture keypair and seal_pubkey_ref binding are correct."""

    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except Exception as e:
        return InvariantResult(
            "CS-SEAL-KEYPAIR-001",
            "FAIL",
            [CONSISTENCY_SPEC_DOC],
            f"Missing crypto dependency for Ed25519 checks ({e}); install 'cryptography' and rerun sweep.",
        )

    cases_path = _resolve_repo_path(root, "policy/fixtures/public/seal/cases.json", must_exist=True, must_be_file=True)
    doc = json.loads(read_text(cases_path))
    cases = doc.get("cases") if isinstance(doc, dict) else None
    if not isinstance(cases, list):
        return InvariantResult(
            "CS-SEAL-KEYPAIR-001",
            "FAIL",
            [CONSISTENCY_SPEC_DOC, "policy/fixtures/public/seal/cases.json"],
            "Fix policy/fixtures/public/seal/cases.json to be an object with cases[] list, then rerun sweep.",
        )

    case_ids: list[str] = []
    for c in cases:
        if isinstance(c, dict) and isinstance(c.get("case_id"), str) and str(c.get("case_id") or "").strip():
            case_ids.append(str(c.get("case_id") or "").strip())
    case_ids = sorted(set(case_ids))
    if not case_ids:
        return InvariantResult(
            "CS-SEAL-KEYPAIR-001",
            "FAIL",
            [CONSISTENCY_SPEC_DOC, "policy/fixtures/public/seal/cases.json"],
            "NO-GO: no SEAL fixture case_id targets found (checked 0).",
        )

    # Build a deterministic set of derived pubkeys from all available SEAL fixture private keys.
    derived_pubkeys: set[str] = set()
    for case_id in case_ids:
        fixture_dir_rel = f"policy/fixtures/public/seal/{case_id}"
        fixture_dir = _resolve_repo_path(root, fixture_dir_rel, must_exist=True, must_be_file=False)
        priv_path = fixture_dir / "seal_private_key.hex"
        if not priv_path.exists() or not priv_path.is_file() or priv_path.is_symlink():
            continue
        seed_hex = read_text(priv_path).strip()
        if not re.fullmatch(r"[0-9a-fA-F]{64}", seed_hex):
            continue
        priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
        pub_bytes = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        derived_pubkeys.add(pub_bytes.hex().lower())

    if not derived_pubkeys:
        return InvariantResult(
            "CS-SEAL-KEYPAIR-001",
            "FAIL",
            [CONSISTENCY_SPEC_DOC, "policy/fixtures/public/seal/cases.json"],
            "NO-GO: no valid seal_private_key.hex seeds found in SEAL fixtures (checked 0).",
        )

    violations: list[str] = []
    for case_id in case_ids:
        fixture_dir_rel = f"policy/fixtures/public/seal/{case_id}"
        fixture_dir = _resolve_repo_path(root, fixture_dir_rel, must_exist=True, must_be_file=False)
        priv_path = fixture_dir / "seal_private_key.hex"
        pub_path = fixture_dir / "seal_pubkey.hex"
        ls_path = fixture_dir / "LockedSpec.json"
        if not pub_path.exists() or not pub_path.is_file() or pub_path.is_symlink():
            violations.append(f"{fixture_dir_rel}: missing/invalid seal_pubkey.hex")
            continue
        if not ls_path.exists() or not ls_path.is_file() or ls_path.is_symlink():
            violations.append(f"{fixture_dir_rel}: missing/invalid LockedSpec.json")
            continue

        actual_pub_hex = read_text(pub_path).strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", actual_pub_hex):
            violations.append(f"{fixture_dir_rel}: seal_pubkey.hex must be 64 hex chars")
        else:
            if priv_path.exists() and priv_path.is_file() and not priv_path.is_symlink():
                seed_hex = read_text(priv_path).strip()
                if not re.fullmatch(r"[0-9a-fA-F]{64}", seed_hex):
                    violations.append(f"{fixture_dir_rel}: seal_private_key.hex must be 64 hex chars")
                else:
                    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
                    pub_bytes = priv.public_key().public_bytes(
                        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
                    )
                    expected_pub_hex = pub_bytes.hex().lower()
                    if actual_pub_hex != expected_pub_hex:
                        violations.append(f"{fixture_dir_rel}: seal_pubkey.hex does not match derived public key")
            else:
                # If this fixture has no private key, its pubkey must still match an in-repo derived pubkey.
                if actual_pub_hex not in derived_pubkeys:
                    violations.append(f"{fixture_dir_rel}: seal_pubkey.hex not derived from any in-repo seal_private_key.hex")

        locked = json.loads(read_text(ls_path))
        env = locked.get("environment_envelope") if isinstance(locked, dict) else None
        ref = env.get("seal_pubkey_ref") if isinstance(env, dict) else None
        if not isinstance(ref, dict):
            violations.append(f"{fixture_dir_rel}: LockedSpec.environment_envelope.seal_pubkey_ref missing/invalid")
            continue

        expected_storage_ref = f"{fixture_dir_rel}/seal_pubkey.hex"
        if ref.get("storage_ref") != expected_storage_ref:
            violations.append(f"{fixture_dir_rel}: seal_pubkey_ref.storage_ref must be {expected_storage_ref}")

        declared_hash = str(ref.get("hash") or "").lower()
        computed_hash = hashlib.sha256(pub_path.read_bytes()).hexdigest().lower()
        if declared_hash != computed_hash:
            violations.append(f"{fixture_dir_rel}: seal_pubkey_ref.hash mismatch")

    violations = sorted(set(violations))
    if violations:
        details = {
            "checked": len(case_ids),
            "violations_total": len(violations),
            "violations_sample": violations[:12],
        }
        return InvariantResult(
            "CS-SEAL-KEYPAIR-001",
            "FAIL",
            [CONSISTENCY_SPEC_DOC, "policy/fixtures/public/seal/cases.json"],
            "Run `python -m tools.belgi fixtures fix-all --repo . --create-missing-private-keys`, then rerun the sweep.",
            details,
        )

    return InvariantResult(
        "CS-SEAL-KEYPAIR-001",
        "PASS",
        [CONSISTENCY_SPEC_DOC, "policy/fixtures/public/seal/cases.json"],
        "",
    )


def check_cs_sweep_001(root: Path) -> InvariantResult:
    """CS-SWEEP-001 — Input Authority: canonical inputs reflect current schemas/tools."""

    try:
        canon = _canonical_inputs(root)
    except Exception as e:
        return InvariantResult(
            "CS-SWEEP-001",
            "FAIL",
            ["schemas/README.md", "tools/sweep.py"],
            f"Fix canonical input enumeration error ({e}), then rerun sweep.",
        )

    # Ensure dynamic schema surface is included.
    schema_files = set(_iter_schema_files(root))
    if not schema_files.issubset(set(canon)):
        return InvariantResult(
            "CS-SWEEP-001",
            "FAIL",
            ["schemas/README.md", "tools/sweep.py"],
            "Ensure sweep inputs include all current schema files under schemas/, then rerun sweep.",
        )

    required = {"tools/normalize.py", "tools/rehash.py", "tools/sweep.py"}
    if not required.issubset(set(canon)):
        return InvariantResult(
            "CS-SWEEP-001",
            "FAIL",
            ["tools/sweep.py"],
            "Ensure sweep inputs include the canonical tools surface, then rerun sweep.",
        )

    return InvariantResult("CS-SWEEP-001", "PASS", ["schemas/README.md", "tools/normalize.py"], "")


def _remediation_for_message(msg: str) -> str:
    """Map failure message to human-readable remediation hint."""
    m = (msg or "").lower()
    if "fixtures should declare" in m or ("fixtures" in m and "sha-256" in m) or "hash=" in m:
        return (
            "CS-EV-006 bootstrap: update fixture expected hash to the printed 'fixtures should declare' value "
            "(or run `python -m tools.sweep consistency --repo . --fix-fixtures`) and add/update the "
            "EvidenceManifest.artifacts[] entry for policy.consistency_sweep."
        )
    if "run_id" in m and ("missing" in m or "empty" in m):
        return "Ensure all required artifacts include non-empty run_id; regenerate bundle."
    if "schema" in m and ("invalid" in m or "validation" in m):
        return "Fix JSON to satisfy the referenced schema (missing/extra fields)."
    return "Open policy/consistency_sweep.json and fix the reported check; re-run tools.sweep consistency."


def _write_consistency_summary_md(
    path: Path,
    total: int,
    passed: int,
    failed: int,
    results: list[InvariantResult],
) -> None:
    """Write human-readable summary markdown for CI step summary."""
    lines: list[str] = []
    lines.append("## Consistency sweep")
    lines.append(f"- total: **{total}**  passed: **{passed}**  failed: **{failed}**")
    lines.append("")

    if failed == 0:
        lines.append("✅ all checks passed")
    else:
        lines.append("### Failures")
        # Sort failures by check_id for determinism
        failures = sorted(
            [r for r in results if r.status == "FAIL"],
            key=lambda r: r.invariant_id,
        )
        for r in failures:
            msg = r.remediation.replace("\n", " ").strip() if r.remediation else "(no message)"
            remediation = _remediation_for_message(msg)
            lines.append(f"#### {r.invariant_id}")
            lines.append(f"- message: {msg}")
            lines.append(f"- remediation: {remediation}")

            # Deterministic details hint for flake-prone checks (bounded output).
            if r.invariant_id == "CS-BYTE-001" and isinstance(r.details, dict):
                counts = r.details.get("counts") if isinstance(r.details.get("counts"), dict) else {}
                drift = r.details.get("drift_files") if isinstance(r.details.get("drift_files"), list) else []
                paths = [d.get("path") for d in drift if isinstance(d, dict) and isinstance(d.get("path"), str)]
                paths = sorted(set(paths))
                ex = ", ".join(paths[:5])
                lines.append(f"- details: drift_files={counts.get('drift_files')} examples={ex if ex else '<none>'}")

            if r.invariant_id == "CS-EV-006" and isinstance(r.details, dict):
                vios = r.details.get("violations") if isinstance(r.details.get("violations"), list) else []
                case_ids = [v.get("case_id") for v in vios if isinstance(v, dict) and isinstance(v.get("case_id"), str)]
                case_ids = sorted(set(case_ids))
                ex = ", ".join(case_ids[:5])
                lines.append(f"- details: violations={len(vios)} examples={ex if ex else '<none>'}")

    _atomic_write_text(path, "\n".join(lines) + "\n")


def _run_at(repo_root: Path, cmd: list[str]) -> tuple[int, str, str]:
    env = dict(os.environ)
    env.setdefault("LANG", "C")
    env.setdefault("LC_ALL", "C")
    proc = subprocess.run(cmd, cwd=str(repo_root), env=env, stdin=subprocess.DEVNULL, text=True, capture_output=True)
    return proc.returncode, proc.stdout, proc.stderr


def _fixture_dir_from_repo_rel_written_file(repo_rel_file: str) -> str | None:
    """Map a written fixture file path to its fixture case directory.

    Deterministic policy: if the written file is under policy/fixtures/, the fixture dir is its parent directory.
    """

    rel = _validate_repo_rel(repo_rel_file)
    if not rel.startswith("policy/fixtures/"):
        return None
    if "/" not in rel:
        return None
    return rel.rsplit("/", 1)[0]


def _seal_payload_paths_in_fixture_dir(repo_root: Path, fixture_dir_rel: str) -> list[str]:
    fixture_dir_rel = _validate_repo_rel(fixture_dir_rel)
    fixture_dir = _resolve_repo_path(repo_root, fixture_dir_rel, must_exist=True, must_be_file=False)
    if not fixture_dir.is_dir():
        raise _UserInputError(f"fixture dir is not a directory: {fixture_dir_rel}")

    present: list[str] = []
    for name in _SEAL_PAYLOAD_FILENAMES:
        p = fixture_dir / name
        if p.exists() and p.is_file():
            present.append((Path(fixture_dir_rel) / name).as_posix())
    present.sort()
    return present


def _is_seal_related_fixture_dir(repo_root: Path, fixture_dir_rel: str) -> bool:
    fixture_dir_rel = _validate_repo_rel(fixture_dir_rel)
    if not fixture_dir_rel.startswith("policy/fixtures/"):
        return False
    if ("/gate_s/" not in fixture_dir_rel) and ("/seal/" not in fixture_dir_rel):
        return False
    payloads = _seal_payload_paths_in_fixture_dir(repo_root, fixture_dir_rel)
    return len(payloads) > 0


def _pick_primary_seal_payload(repo_root: Path, fixture_dir_rel: str) -> str:
    payloads = _seal_payload_paths_in_fixture_dir(repo_root, fixture_dir_rel)
    preferred = [
        (Path(fixture_dir_rel) / "SealManifest.json").as_posix(),
        (Path(fixture_dir_rel) / "SealManifest.signed.json").as_posix(),
        (Path(fixture_dir_rel) / "SealManifest.out.json").as_posix(),
    ]
    for p in preferred:
        if p in payloads:
            return p
    raise _UserInputError(f"seal-related fixture dir missing known payload files: {fixture_dir_rel}")


def _load_cases_by_id(repo_root: Path, cases_rel: str) -> dict[str, dict[str, object]]:
    cases_path = _resolve_repo_path(repo_root, cases_rel, must_exist=True, must_be_file=True)
    doc = load_json(cases_path)
    cases = doc.get("cases") if isinstance(doc, dict) else None
    if not isinstance(cases, list):
        raise _UserInputError(f"Invalid cases.json shape at {cases_rel}")
    out: dict[str, dict[str, object]] = {}
    for c in cases:
        if not isinstance(c, dict):
            continue
        case_id = str(c.get("case_id") or "").strip()
        if not case_id:
            continue
        out[case_id] = dict(c)
    return out


def _build_seal_bundle_cmd_for_fixture_dir(repo_root: Path, fixture_dir_rel: str, out_rel: str) -> list[str]:
    fixture_dir_rel = _validate_repo_rel(fixture_dir_rel)
    out_rel = _validate_repo_rel(out_rel)

    # Seal producer fixtures use cases.json params (final_commit_sha, sealed_at, signer) and optional signature file.
    if "/policy/fixtures/public/seal/" in f"/{fixture_dir_rel}":
        cases = _load_cases_by_id(repo_root, "policy/fixtures/public/seal/cases.json")
        case_id = Path(fixture_dir_rel).name
        entry = cases.get(case_id)
        if entry is None:
            raise _UserInputError(f"Unknown seal fixture case_id '{case_id}' (missing in seal/cases.json)")
        paths = entry.get("paths")
        if not isinstance(paths, dict):
            raise _UserInputError(f"Invalid seal fixture entry paths for '{case_id}'")
        params = entry.get("params")
        if not isinstance(params, dict):
            params = {}

        final_commit_sha = str(params.get("final_commit_sha") or "0" * 40)
        sealed_at = str(params.get("sealed_at") or "2000-01-01T00:30:00Z")
        signer = str(params.get("signer") or "human:fixture")

        cmd = [
            sys.executable,
            "-m",
            "chain.seal_bundle",
            "--repo",
            ".",
            "--locked-spec",
            str(paths.get("locked_spec")),
            "--gate-q-verdict",
            str(paths.get("gate_q_verdict")),
            "--gate-r-verdict",
            str(paths.get("gate_r_verdict")),
            "--evidence-manifest",
            str(paths.get("evidence_manifest")),
            "--final-commit-sha",
            final_commit_sha,
            "--sealed-at",
            sealed_at,
            "--signer",
            signer,
            "--out",
            out_rel,
        ]
        sig_path = paths.get("seal_signature_b64")
        if isinstance(sig_path, str) and sig_path.strip():
            cmd.extend(["--seal-signature-file", sig_path.strip()])
        return cmd

    # Gate S fixtures (and other seal-related dirs) use standard in-dir inputs.
    fixture_dir = _resolve_repo_path(repo_root, fixture_dir_rel, must_exist=True, must_be_file=False)
    if not fixture_dir.is_dir():
        raise _UserInputError(f"fixture dir is not a directory: {fixture_dir_rel}")

    locked_spec = (fixture_dir / "LockedSpec.json").relative_to(repo_root).as_posix()
    gate_q_verdict = (fixture_dir / "GateVerdict.Q.json").relative_to(repo_root).as_posix()
    gate_r_verdict = (fixture_dir / "GateVerdict.R.json").relative_to(repo_root).as_posix()
    evidence_manifest = (fixture_dir / "EvidenceManifest.json").relative_to(repo_root).as_posix()
    sig_file = fixture_dir / "seal_signature.b64"

    cmd = [
        sys.executable,
        "-m",
        "chain.seal_bundle",
        "--repo",
        ".",
        "--locked-spec",
        locked_spec,
        "--gate-q-verdict",
        gate_q_verdict,
        "--gate-r-verdict",
        gate_r_verdict,
        "--evidence-manifest",
        evidence_manifest,
        "--final-commit-sha",
        "0" * 40,
        "--sealed-at",
        "2000-01-01T00:30:00Z",
        "--signer",
        "human:fixture",
        "--out",
        out_rel,
    ]
    if sig_file.exists() and sig_file.is_file():
        cmd.extend(["--seal-signature-file", sig_file.relative_to(repo_root).as_posix()])
    return cmd


def _build_gate_s_verify_cmd_for_fixture_dir(
    repo_root: Path,
    fixture_dir_rel: str,
    seal_manifest_rel: str,
    out_rel: str,
) -> list[str]:
    fixture_dir = _resolve_repo_path(repo_root, fixture_dir_rel, must_exist=True, must_be_file=False)
    if not fixture_dir.is_dir():
        raise _UserInputError(f"fixture dir is not a directory: {fixture_dir_rel}")

    locked_spec = (fixture_dir / "LockedSpec.json").relative_to(repo_root).as_posix()
    evidence_manifest = (fixture_dir / "EvidenceManifest.json").relative_to(repo_root).as_posix()

    return [
        sys.executable,
        "-m",
        "chain.gate_s_verify",
        "--repo",
        ".",
        "--locked-spec",
        locked_spec,
        "--seal-manifest",
        _validate_repo_rel(seal_manifest_rel),
        "--evidence-manifest",
        evidence_manifest,
        "--out",
        _validate_repo_rel(out_rel),
    ]


def _expected_gate_s_rc_for_fixture_dir(repo_root: Path, fixture_dir_rel: str) -> int | None:
    fixture_dir_rel = _validate_repo_rel(fixture_dir_rel)
    if "/policy/fixtures/public/gate_s/" not in f"/{fixture_dir_rel}":
        return None
    cases = _load_cases_by_id(repo_root, "policy/fixtures/public/gate_s/cases.json")
    case_id = Path(fixture_dir_rel).name
    entry = cases.get(case_id)
    if entry is None:
        raise _UserInputError(f"Unknown gate_s fixture case_id '{case_id}' (missing in gate_s/cases.json)")
    return int(entry.get("expected_exit_code", 2))


def _regen_and_verify_seal_related_fixtures(
    *,
    repo_root: Path,
    fixture_dirs_rel: Sequence[str],
    regen_seals: bool,
) -> int:
    """Regenerate SealManifests for touched seal-related fixture dirs (and verify via Gate S).

    Fail-closed behavior:
    - If regen_seals is False: Gate S precheck; on mismatch, emit deterministic remediation and return 2.
    - If regen_seals is True: seal_bundle outputs in-place (only known payload files), then Gate S verify; return 2 on mismatch.
    """

    dirs = sorted(set(_validate_repo_rel(d) for d in fixture_dirs_rel))
    seal_dirs = [d for d in dirs if _is_seal_related_fixture_dir(repo_root, d)]
    if not seal_dirs:
        return 0

    verify_out_root = _resolve_repo_path(repo_root, "temp/regen_seals_verify", must_exist=False)
    verify_out_root.mkdir(parents=True, exist_ok=True)

    if not regen_seals:
        drifted: list[str] = []
        for d in seal_dirs:
            seal_manifest_rel = _pick_primary_seal_payload(repo_root, d)
            out_rel = (verify_out_root / f"S__precheck__{Path(d).name}.json").relative_to(repo_root).as_posix()
            cmd = _build_gate_s_verify_cmd_for_fixture_dir(repo_root, d, seal_manifest_rel, out_rel)
            rc, _, _ = _run_at(repo_root, cmd)
            expected_rc = _expected_gate_s_rc_for_fixture_dir(repo_root, d)
            if expected_rc is None:
                expected_rc = 0
            if rc != expected_rc:
                drifted.append(d)
        if drifted:
            drifted.sort()
            joined = ", ".join(drifted)
            print(f"REGEN-SEALS NO-GO: drifted_fixture_dirs: {joined}", file=sys.stderr)
            print(_REGEN_SEALS_REMEDIATION_TEXT, file=sys.stderr)
            return 2
        return 0

    for d in seal_dirs:
        payloads = _seal_payload_paths_in_fixture_dir(repo_root, d)
        if len(payloads) == 0:
            raise _UserInputError(f"seal-related fixture dir missing known payload files: {d}")

        for out_rel in payloads:
            cmd = _build_seal_bundle_cmd_for_fixture_dir(repo_root, d, out_rel)
            rc, stdout, stderr = _run_at(repo_root, cmd)
            if rc != 0:
                if stdout:
                    print(stdout, file=sys.stderr)
                if stderr:
                    print(stderr, file=sys.stderr)
                print(f"REGEN-SEALS NO-GO: seal_bundle failed for {d} (rc={rc})", file=sys.stderr)
                return 2

        seal_manifest_rel = _pick_primary_seal_payload(repo_root, d)
        out_rel = (verify_out_root / f"S__postregen__{Path(d).name}.json").relative_to(repo_root).as_posix()
        verify_cmd = _build_gate_s_verify_cmd_for_fixture_dir(repo_root, d, seal_manifest_rel, out_rel)
        rc, stdout, stderr = _run_at(repo_root, verify_cmd)
        expected_rc = _expected_gate_s_rc_for_fixture_dir(repo_root, d)
        if expected_rc is None:
            expected_rc = 0
        if rc != expected_rc:
            if stdout:
                print(stdout, file=sys.stderr)
            if stderr:
                print(stderr, file=sys.stderr)
            print(
                f"REGEN-SEALS NO-GO: gate_s_verify mismatch for {d} (rc={rc} expected={expected_rc})",
                file=sys.stderr,
            )
            return 2

    return 0


def _consistency_sweep_main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".", help="Repo root path")
    ap.add_argument(
        "--out",
        default=CANONICAL_SWEEP_OUT,
        help=f"Output JSON path (MUST be {CANONICAL_SWEEP_OUT})",
    )
    ap.add_argument("--tool-name", default="consistency-sweep", help="Tool name for report")
    ap.add_argument("--tool-version", default="1.0.0", help="Tool version for report")
    ap.add_argument(
        "--inputs",
        nargs="*",
        default=[],
        help="Additional repo-relative input files to include (canonical core inputs are always included)",
    )
    ap.add_argument(
        "--fix-fixtures",
        action="store_true",
        help="Deterministically patch governed Gate R fixture EvidenceManifest.json files for CS-EV-006 (default: no changes)",
    )
    ap.add_argument(
        "--regen-seals",
        action="store_true",
        help="When used with --fix-fixtures, regenerate SealManifests for touched seal-related fixtures (policy/fixtures/**/(gate_s|seal)/**) and verify via Gate S (default: no regen)",
    )
    args = ap.parse_args(argv)

    if bool(args.regen_seals) and not bool(args.fix_fixtures):
        raise SystemExit("--regen-seals requires --fix-fixtures")

    # Deterministic contract: the consistency sweep artifact location is fixed and
    # is consumed as evidence by downstream verification. Fail closed if asked to
    # emit the canonical artifact elsewhere.
    if args.out.replace("\\\\", "/") != CANONICAL_SWEEP_OUT:
        raise SystemExit(f"--out must be '{CANONICAL_SWEEP_OUT}' (required by the evidence contract).")

    root = Path(args.repo).resolve()
    if not root.exists() or not root.is_dir():
        raise _UserInputError(f"repo root is not a directory: {root}")
    started = utc_now_rfc3339()

    # Spec-sync guard: law (consistency-sweep.md) must match enforcer registry 1:1.
    spec_ids = _extract_spec_invariant_ids(root)

    registry: dict[str, Callable[[Path], InvariantResult]] = {
        # Canonical semantics
        "CS-CAN-001": check_cs_can_001,
        "CS-CAN-004": check_cs_can_004,
        "CS-CAN-002": check_cs_can_002,
        "CS-CAN-003": check_cs_can_003,
        # Gate-schema
        "CS-GS-001": check_cs_gs_001,
        "CS-GS-002": check_cs_gs_002,
        "CS-GS-003": check_cs_gs_003,
        "CS-GS-004": check_cs_gs_004,
        "CS-GS-005": check_cs_gs_005,
        # IntentSpec
        "CS-IS-001": check_intentspec_yaml_single_block,
        "CS-IS-002": check_cs_is_002,
        "CS-IS-003": check_cs_is_003,
        "CS-IS-004": check_cs_is_004,
        # Evidence bundles
        "CS-EV-001": check_cs_ev_001,
        "CS-EV-002": check_cs_ev_002,
        "CS-EV-003": check_cs_ev_003,
        "CS-EV-004": check_cs_ev_004,
        "CS-EV-005": check_cs_ev_005,
        # Tier parameters
        "CS-TIER-001": check_cs_tier_001,
        "CS-TIER-002": check_cs_tier_002,
        "CS-TIER-003": check_cs_tier_003,
        "CS-TIER-004": check_cs_tier_004,
        "CS-TIER-005": check_cs_tier_005,
        # Waivers
        "CS-WVR-001": check_cs_wvr_001,
        "CS-WVR-002": check_cs_wvr_002,
        "CS-WVR-003": check_cs_wvr_003,
        "CS-WVR-004": check_cs_wvr_004,
        "CS-WVR-005": check_cs_wvr_005,
        # Templates
        "CS-TPL-001": check_cs_tpl_001,
        "CS-TPL-002": check_cs_tpl_002,
        "CS-TPL-003": check_cs_tpl_003,
        "CS-TPL-004": check_cs_tpl_004,
        "CS-TPL-005": check_cs_tpl_005,
        # Verify bundle
        "CS-VERIFY_BUNDLE-001": check_cs_verify_bundle_001,
        "CS-GATE_R-MANDATES-VERIFY_BUNDLE-001": check_cs_gate_r_mandates_verify_bundle_001,
        "CS-VERIFY_BUNDLE-GATEVERDICT-BINDING-001": check_cs_verify_bundle_gateverdict_binding_001,
        # Orchestration invariants
        "CS-BYTE-001": check_cs_byte_001,
        "CS-EV-006": check_cs_ev_006,
        "CS-PACK-IDENTITY-001": check_cs_pack_identity_001,
        "CS-SEAL-KEYPAIR-001": check_cs_seal_keypair_001,
        "CS-SWEEP-001": check_cs_sweep_001,
        "CS-GV-001": check_cs_gv_001,
        "CS-LS-001": check_cs_ls_001,
        "CS-REF-001": check_cs_ref_001,
        "CS-R0-ENFORCEMENT-WIRED-001": check_cs_r0_enforcement_wired_001,
        # Render targets
        "CS-RENDER-001": check_cs_render_001,
    }

    spec_set = set(spec_ids)
    reg_set = set(registry.keys())
    missing_in_code = sorted(spec_set - reg_set)
    extra_in_code = sorted(reg_set - spec_set)
    if missing_in_code or extra_in_code:
        if missing_in_code:
            print("Spec-sync NO-GO: invariant_ids missing in code registry:", file=sys.stderr)
            for inv in missing_in_code:
                print(f"  - {inv}", file=sys.stderr)
        if extra_in_code:
            print("Spec-sync NO-GO: invariant_ids present in code but not in spec:", file=sys.stderr)
            for inv in extra_in_code:
                print(f"  - {inv}", file=sys.stderr)
        return 2

    # Evaluate all invariants except CS-EV-006 first. CS-EV-006 binds fixtures to the
    # hash of this sweep's output artifact, so it must be evaluated against the
    # would-be report hash via a deterministic fixed-point stabilization.
    base_results: List[InvariantResult] = []
    for inv_id in spec_ids:
        if inv_id == "CS-EV-006":
            continue
        fn = registry[inv_id]
        try:
            res = fn(root)
        except Exception as e:
            res = InvariantResult(
                inv_id,
                "FAIL",
                [CONSISTENCY_SPEC_DOC],
                f"Sweep check raised an exception: {e}",
            )

        if res.invariant_id != inv_id:
            print(
                f"Spec-sync NO-GO: invariant '{inv_id}' returned mismatched id '{res.invariant_id}'",
                file=sys.stderr,
            )
            return 2
        base_results.append(res)

    finished = utc_now_rfc3339()
    out_path = _resolve_repo_path(root, args.out, must_exist=False)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    canon_inputs = _canonical_inputs(root)
    extra_inputs = [_validate_repo_rel(p) for p in (args.inputs or [])]
    all_inputs = sorted(set(canon_inputs + extra_inputs))
    
    # Exclude the sweep output and summary from the inputs list.
    excluded = {"policy/consistency_sweep.json", "policy/consistency_sweep.summary.md"}
    filtered = [p for p in all_inputs if _validate_repo_rel(p) not in excluded]
    ev006_overrides = _ev006_blob_overrides_for_normalization(root)
    inputs = build_inputs(root, filtered, blob_overrides=ev006_overrides)


    report_base = {
        "artifact_id": "policy.consistency_sweep",
        "generated_at": finished,
        "sweep_started_at": started,
        "sweep_finished_at": finished,
        "tool": {"name": args.tool_name, "version": args.tool_version},
        # Deterministic binding: use tree SHA for evaluated inputs, excluding sweep outputs and
        # normalizing CS-EV-006 self-reference in fixture EvidenceManifests.
        "repo_revision": _git_tree_sha_excluding(
            root,
            [CANONICAL_SWEEP_OUT, CANONICAL_SWEEP_SUMMARY],
            blob_overrides=_ev006_blob_overrides_for_normalization(root),
        ),
        "inputs": inputs,
    }

    def _render_report(result_set: list[InvariantResult]) -> tuple[dict[str, Any], bytes, str, int, int, list[InvariantResult]]:
        ordered = list(result_set)
        ordered.sort(key=lambda r: r.invariant_id)
        passed_count = sum(1 for r in ordered if r.status == "PASS")
        failed_count = sum(1 for r in ordered if r.status == "FAIL")
        report = dict(report_base)
        report["invariants"] = [
            {
                "invariant_id": r.invariant_id,
                "status": r.status,
                "evidence": r.evidence,
                "remediation": r.remediation if r.status == "FAIL" else "",
                **({"details": r.details} if isinstance(r.details, dict) else {}),
            }
            for r in ordered
        ]
        report["summary"] = {"total": len(ordered), "passed": passed_count, "failed": failed_count}
        # Add structured failures list (backwards-compatible new key)
        report["failures"] = [
            {
                "check_id": r.invariant_id,
                "message": r.remediation.replace("\n", " ").strip() if r.remediation else "",
            }
            for r in ordered
            if r.status == "FAIL"
        ]
        b = _canonical_json_bytes(report)
        h = hashlib.sha256(b).hexdigest()
        return report, b, h, passed_count, failed_count, ordered

    # CS-EV-006 is self-referential: fixtures declare the sweep artifact hash, and CS-EV-006
    # checks those declarations. Compute the PASS-target artifact hash (i.e., the hash of the
    # report where CS-EV-006 is PASS) and evaluate CS-EV-006 against that target.
    cs_pass = InvariantResult("CS-EV-006", "PASS", ["policy/fixtures/public/gate_r/cases.json"], "")
    _, _, fixture_target_hash, _, _, _ = _render_report(list(base_results) + [cs_pass])

    cs_eval, modified = _eval_cs_ev_006_expected_hash(root, fixture_target_hash, fix_fixtures=bool(args.fix_fixtures))
    if args.fix_fixtures and modified:
        max_paths = 25
        shown = modified[:max_paths]
        suffix = "" if len(modified) <= max_paths else f" ... (+{len(modified) - max_paths} more)"
        joined = ", ".join(shown)
        print(f"FIX-FIXTURES modified_files: {joined}{suffix}", file=sys.stderr)

    # If fix-fixtures touched any seal-related fixture dirs, optionally regenerate seals (scoped)
    # or fail-closed with deterministic remediation if Gate S indicates drift.
    touched_fixture_dirs: list[str] = []
    if bool(args.fix_fixtures) and modified:
        for p in modified:
            d = _fixture_dir_from_repo_rel_written_file(p)
            if d is not None:
                touched_fixture_dirs.append(d)
    if bool(args.fix_fixtures) and touched_fixture_dirs:
        rc = _regen_and_verify_seal_related_fixtures(
            repo_root=root,
            fixture_dirs_rel=touched_fixture_dirs,
            regen_seals=bool(args.regen_seals),
        )
        if rc != 0:
            return rc

    report_obj, _, report_hash, passed, failed, results = _render_report(list(base_results) + [cs_eval])
    _write_json(out_path, report_obj, canonical=True)

    # Write human-readable summary markdown for CI step summary
    summary_md_path = out_path.with_suffix(".summary.md")
    _write_consistency_summary_md(summary_md_path, len(results), passed, failed, results)

    print(f"Wrote: {args.out}")
    print(f"SHA-256 (report): {report_hash}")
    print(f"SHA-256 (fixtures should declare): {fixture_target_hash}")
    print(f"Summary: total={len(results)} passed={passed} failed={failed}")

    failed_ids = [r.invariant_id for r in results if r.status == "FAIL"]
    if not args.fix_fixtures and failed_ids == ["CS-EV-006"]:
        print(
            "\nNote: CS-EV-006 is intentionally self-referential (fixtures pin the sweep artifact hash; the sweep also reports CS-EV-006). "
            "Until fixtures are updated, the written report hash will differ from the PASS-target hash printed as 'fixtures should declare'.\n"
            "Fix: run `python -m tools.sweep consistency --repo . --fix-fixtures` to deterministically patch governed fixtures and converge in one pass.",
            file=sys.stderr,
        )

    print("\nEvidenceManifest.artifacts[] entry you must include (example):")
    print(
        json.dumps(
            {
                "kind": "policy_report",
                "id": "policy.consistency_sweep",
                "hash": fixture_target_hash,
                "media_type": "application/json",
                "storage_ref": CANONICAL_SWEEP_OUT,
                "produced_by": "C1",
            },
            indent=2,
        )
    )

    return 1 if failed > 0 else 0


# ----------------------------
# Fixture sweeps (embedded)
# ----------------------------


def _run(cmd: list[str]) -> tuple[int, str, str]:
    env = dict(os.environ)
    env.setdefault("LANG", "C")
    env.setdefault("LC_ALL", "C")
    proc = subprocess.run(cmd, cwd=str(REPO_ROOT), env=env, stdin=subprocess.DEVNULL, text=True, capture_output=True)
    return proc.returncode, proc.stdout, proc.stderr


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write_text(path, text)


def _write_json(path: Path, obj: object, *, canonical: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if canonical:
        _atomic_write_canonical_json(path, obj)
    else:
        _atomic_write_json(path, obj)


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except Exception:
        return False


def _load_cases_expected(cases_path: Path) -> dict[str, dict[str, object]]:
    if not cases_path.exists():
        raise ValueError(f"Missing cases.json at {cases_path.as_posix()}")

    doc = json.loads(cases_path.read_text(encoding="utf-8", errors="strict"))
    cases = doc.get("cases")
    if not isinstance(cases, list):
        raise ValueError(f"Invalid cases.json (expected cases: list) at {cases_path.as_posix()}")

    out: dict[str, dict[str, object]] = {}
    for c in cases:
        if not isinstance(c, dict):
            raise ValueError(f"Invalid cases.json (case not object) at {cases_path.as_posix()}")
        case_id = str(c.get("case_id") or "").strip()
        if not case_id:
            raise ValueError(f"Invalid cases.json (missing case_id) at {cases_path.as_posix()}")
        if case_id in out:
            raise ValueError(f"Duplicate case_id '{case_id}' in {cases_path.as_posix()}")
        out[case_id] = dict(c)
    return out


def _list_fixture_dirs(fixtures_root: Path) -> list[Path]:
    return sorted([p for p in fixtures_root.iterdir() if p.is_dir()], key=lambda p: p.name)


def _validate_cases_warn_missing_paths(
    *,
    gate: str,
    fixtures_root: Path,
    cases_expected: dict[str, dict[str, object]],
) -> tuple[list[str], list[str], dict[str, list[str]]]:
    """Validate expectation contract.

    Missing files referenced in case "paths" are warnings (non-fatal) so the
    underlying gate/seal tool remains the mechanical-truth authority.
    """

    errors: list[str] = []
    warnings: list[str] = []
    missing_paths_by_fixture: dict[str, list[str]] = {}

    fixture_dirs = _list_fixture_dirs(fixtures_root)
    fixture_names = {p.name for p in fixture_dirs}
    case_names = set(cases_expected.keys())

    missing_in_cases = sorted(fixture_names - case_names)
    extra_in_cases = sorted(case_names - fixture_names)
    for name in missing_in_cases:
        errors.append(f"{gate}: fixture directory missing from cases.json: {name}")
    for name in extra_in_cases:
        errors.append(f"{gate}: cases.json entry has no fixture directory: {name}")

    for name in sorted(case_names):
        entry = cases_expected[name]

        exp_rc = entry.get("expected_exit_code")
        if not isinstance(exp_rc, int):
            errors.append(f"{gate}:{name}: expected_exit_code must be int")

        allow_missing_paths_raw = entry.get("allow_missing_paths")
        allow_missing_keys: set[str] = set()
        if allow_missing_paths_raw is not None:
            if not isinstance(allow_missing_paths_raw, list):
                errors.append(f"{gate}:{name}: allow_missing_paths must be a list if present")
            else:
                for v in allow_missing_paths_raw:
                    if not isinstance(v, str) or not v.strip():
                        errors.append(f"{gate}:{name}: allow_missing_paths entries must be non-empty strings")
                        continue
                    allow_missing_keys.add(v.strip())

        paths = entry.get("paths")
        if paths is None:
            continue
        if not isinstance(paths, dict):
            errors.append(f"{gate}:{name}: paths must be an object if present")
            continue

        if allow_missing_keys:
            if isinstance(exp_rc, int) and exp_rc == 0:
                errors.append(f"{gate}:{name}: allow_missing_paths not allowed when expected_exit_code is 0")
            unknown = sorted(allow_missing_keys - set(paths.keys()))
            for k in unknown:
                errors.append(f"{gate}:{name}: allow_missing_paths contains unknown key: {k}")

        fixdir = fixtures_root / name
        for key, rel_str in sorted(paths.items(), key=lambda kv: str(kv[0])):
            if not isinstance(rel_str, str) or not rel_str.strip():
                errors.append(f"{gate}:{name}: paths.{key} must be a non-empty string")
                continue

            rel_path = Path(rel_str)
            if rel_path.is_absolute():
                errors.append(f"{gate}:{name}: paths.{key} must be repo-relative, got absolute")
                continue

            resolved = (REPO_ROOT / rel_path).resolve()

            if not _is_relative_to(resolved, fixdir.resolve()):
                errors.append(
                    f"{gate}:{name}: paths.{key} must be under its fixture dir {fixdir.as_posix()}, got {rel_str}"
                )
                continue

            if not resolved.exists():
                if key in allow_missing_keys:
                    missing_paths_by_fixture.setdefault(name, []).append(rel_str)
                else:
                    warnings.append(f"{gate}:{name}: paths.{key} missing on disk (allowed): {rel_str}")
                    missing_paths_by_fixture.setdefault(name, []).append(rel_str)

    return errors, warnings, missing_paths_by_fixture


def _validate_cases_fail_closed_on_missing_paths(
    *,
    fixtures_root: Path,
    cases_expected: dict[str, dict[str, object]],
) -> list[str]:
    """Gate S verifier fixtures are strict: referenced paths MUST exist."""

    errors: list[str] = []

    fixture_dirs = _list_fixture_dirs(fixtures_root)
    fixture_names = {p.name for p in fixture_dirs}
    case_names = set(cases_expected.keys())

    missing_in_cases = sorted(fixture_names - case_names)
    extra_in_cases = sorted(case_names - fixture_names)
    for name in missing_in_cases:
        errors.append(f"S: fixture directory missing from cases.json: {name}")
    for name in extra_in_cases:
        errors.append(f"S: cases.json entry has no fixture directory: {name}")

    for name in sorted(case_names):
        entry = cases_expected[name]

        exp_rc = entry.get("expected_exit_code")
        if not isinstance(exp_rc, int):
            errors.append(f"S:{name}: expected_exit_code must be int")

        paths = entry.get("paths")
        if not isinstance(paths, dict):
            errors.append(f"S:{name}: paths must be an object")
            continue

        required_keys = {"locked_spec", "seal_manifest", "evidence_manifest"}
        missing_keys = sorted([k for k in required_keys if k not in paths])
        if missing_keys:
            errors.append(f"S:{name}: missing required paths keys: {missing_keys}")

        fixdir = fixtures_root / name
        for key, rel_str in sorted(paths.items(), key=lambda kv: str(kv[0])):
            if not isinstance(rel_str, str) or not rel_str.strip():
                errors.append(f"S:{name}: paths.{key} must be a non-empty string")
                continue

            rel_path = Path(rel_str)
            if rel_path.is_absolute():
                errors.append(f"S:{name}: paths.{key} must be repo-relative, got absolute")
                continue

            resolved = (REPO_ROOT / rel_path).resolve()
            if not _is_relative_to(resolved, fixdir.resolve()):
                errors.append(
                    f"S:{name}: paths.{key} must be under its fixture dir {fixdir.as_posix()}, got {rel_str}"
                )
                continue

            if not resolved.exists():
                errors.append(f"S:{name}: paths.{key} missing on disk: {rel_str}")

    return errors


def _load_json_if_exists(path: Path) -> object | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="strict"))
    except Exception:
        return None


def _primary_from_gate_q_verdict(verdict_path: Path) -> tuple[str | None, str | None]:
    obj = _load_json_if_exists(verdict_path)
    if not isinstance(obj, dict):
        return (None, None)

    fc = obj.get("failure_category")
    failure_category = fc if isinstance(fc, str) and fc.strip() else None

    verdict = obj.get("verdict")
    if isinstance(verdict, str) and verdict.strip().upper() == "GO":
        return (None, None)

    failures = obj.get("failures")
    if not isinstance(failures, list) or not failures:
        return (None, failure_category)
    first = failures[0]
    if not isinstance(first, dict):
        return (None, failure_category)
    rid = first.get("rule_id")
    primary = rid if isinstance(rid, str) and rid.strip() else None
    return (primary, failure_category)


def _primary_from_gate_r_report(report_path: Path) -> tuple[str | None, str | None]:
    obj = _load_json_if_exists(report_path)
    if not isinstance(obj, dict):
        return (None, None)

    results = obj.get("results")
    if not isinstance(results, list):
        return (None, None)

    for r in results:
        if not isinstance(r, dict):
            continue
        status = r.get("status")
        if not (isinstance(status, str) and status.strip().upper() == "FAIL"):
            continue
        cid = r.get("check_id")
        primary = cid if isinstance(cid, str) and cid.strip() else None
        return (primary, None)
    return (None, None)


def _fixtures_qr_main(argv: list[str] | None = None) -> int:
    """Sweep Gate Q/R fixtures (policy/fixtures/public/gate_{q,r})."""

    parser = argparse.ArgumentParser(description="Run Gate Q/R verifiers across fixtures and record results.")
    parser.add_argument(
        "--repo",
        default=str(REPO_ROOT),
        help="Compatibility flag (must resolve to this repo root).",
    )
    parser.add_argument(
        "--fixtures-root",
        default="policy/fixtures/public",
        help=(
            "Repo-relative path to a fixtures root that contains gate_q/ and/or gate_r/. "
            "Defaults to policy/fixtures/public."
        ),
    )
    parser.add_argument(
        "--out-dir",
        default="temp/fixture_sweep",
        help="Directory to write sweep outputs (report + per-case logs). Defaults to temp/fixture_sweep/.",
    )
    parser.add_argument(
        "--gate",
        choices=["Q", "R", "QR"],
        default="QR",
        help="Which gate fixtures to sweep (default: QR).",
    )
    args = parser.parse_args(argv)

    repo_arg = Path(str(args.repo)).resolve()
    if repo_arg != REPO_ROOT:
        raise _UserInputError(f"--repo must resolve to repo root {REPO_ROOT}, got {repo_arg}")

    fixtures_root_rel = _validate_repo_rel(str(args.fixtures_root))
    fixtures_root = _resolve_repo_path(REPO_ROOT, fixtures_root_rel, must_exist=True, must_be_file=False)
    if not fixtures_root.is_dir():
        print("ERROR: fixtures-root must be a directory")
        return 3

    want_q = str(args.gate).upper() in ("Q", "QR")
    want_r = str(args.gate).upper() in ("R", "QR")

    fix_q = fixtures_root / "gate_q"
    fix_r = fixtures_root / "gate_r"

    out_dir_rel = _validate_repo_rel(str(args.out_dir))
    out_dir = _resolve_repo_path(REPO_ROOT, out_dir_rel, must_exist=False)
    out_dir.mkdir(parents=True, exist_ok=True)
    logs_dir = out_dir / "logs"
    verifier_out_dir = out_dir / "verifier_out"
    logs_dir.mkdir(parents=True, exist_ok=True)
    verifier_out_dir.mkdir(parents=True, exist_ok=True)

    validation_errors: list[str] = []
    validation_warnings: list[str] = []
    q_missing_paths: dict[str, list[str]] = {}
    r_missing_paths: dict[str, list[str]] = {}

    try:
        q_cases_expected = _load_cases_expected(fix_q / "cases.json") if want_q else {}
        r_cases_expected = _load_cases_expected(fix_r / "cases.json") if want_r else {}
    except Exception as e:
        print(f"ERROR: Failed to load cases.json: {e}")
        return 3

    if want_q:
        q_errs, q_warns, q_missing_paths = _validate_cases_warn_missing_paths(
            gate="Q", fixtures_root=fix_q, cases_expected=q_cases_expected
        )
        validation_errors.extend(q_errs)
        validation_warnings.extend(q_warns)
    if want_r:
        r_errs, r_warns, r_missing_paths = _validate_cases_warn_missing_paths(
            gate="R", fixtures_root=fix_r, cases_expected=r_cases_expected
        )
        validation_errors.extend(r_errs)
        validation_warnings.extend(r_warns)

    if validation_errors:
        print("ERROR: Fixture expectation contract violated (fail-closed).")
        for msg in validation_errors:
            print(f"- {msg}")
        return 2

    if validation_warnings:
        print("WARN: Fixture physical reality notes (non-fatal).")
        for msg in validation_warnings:
            print(f"- {msg}")

    results: list[dict[str, object]] = []

    if want_q:
        for fixture_dir in _list_fixture_dirs(fix_q):
            name = fixture_dir.name
            entry = q_cases_expected.get(name)
            if not isinstance(entry, dict):
                continue
            expected_rc = entry.get("expected_exit_code")
            expected_primary = entry.get("expected_primary")
            paths = entry.get("paths")
            if not isinstance(expected_rc, int) or not isinstance(paths, dict):
                continue

            out_path = verifier_out_dir / f"Q__{name}.json"
            out_path_rel = out_path.relative_to(REPO_ROOT).as_posix()
            cmd = [
                sys.executable,
                "-m",
                "chain.gate_q_verify",
                "--repo",
                ".",
                "--intent-spec",
                str(paths.get("intent_spec")),
                "--locked-spec",
                str(paths.get("locked_spec")),
                "--evidence-manifest",
                str(paths.get("evidence_manifest")),
                "--out",
                out_path_rel,
            ]

            rc, stdout, stderr = _run(cmd)
            primary, failure_category = _primary_from_gate_q_verdict(out_path)

            stdout_path = logs_dir / f"Q__{name}.stdout.txt"
            stderr_path = logs_dir / f"Q__{name}.stderr.txt"
            _write_text(stdout_path, stdout)
            _write_text(stderr_path, stderr)

            results.append(
                {
                    "gate": "Q",
                    "fixture": name,
                    "expected_exit_code": expected_rc,
                    "expected_primary": expected_primary,
                    "actual_exit_code": rc,
                    "primary": primary,
                    "failure_category": failure_category,
                    "physical_missing_paths": sorted(q_missing_paths.get(name, [])),
                    "cmd": cmd,
                    "verifier_out_path": str(out_path.as_posix()),
                    "stdout_path": str(stdout_path.as_posix()),
                    "stderr_path": str(stderr_path.as_posix()),
                    "stdout_sha256": _sha256_text(stdout),
                    "stderr_sha256": _sha256_text(stderr),
                }
            )

    if want_r:
        for fixture_dir in _list_fixture_dirs(fix_r):
            name = fixture_dir.name
            entry = r_cases_expected.get(name)
            if not isinstance(entry, dict):
                continue
            expected_rc = entry.get("expected_exit_code")
            expected_primary = entry.get("expected_primary")
            paths = entry.get("paths")
            if not isinstance(expected_rc, int) or not isinstance(paths, dict):
                continue

            out_path = verifier_out_dir / f"R__{name}.json"
            gate_verdict_out = verifier_out_dir / f"R__{name}.GateVerdict.json"
            r_snapshot_out = verifier_out_dir / f"R__{name}.EvidenceManifest.r_snapshot.json"
            out_path_rel = out_path.relative_to(REPO_ROOT).as_posix()
            gate_verdict_out_rel = gate_verdict_out.relative_to(REPO_ROOT).as_posix()
            r_snapshot_out_rel = r_snapshot_out.relative_to(REPO_ROOT).as_posix()

            fixture_error: str | None = None
            evaluated_revision: str | None = None
            locked_spec_rel = str(paths.get("locked_spec") or "").strip()
            try:
                if not locked_spec_rel:
                    fixture_error = "paths.locked_spec missing/empty"
                else:
                    locked_spec_path = repo_path(REPO_ROOT, locked_spec_rel)
                    locked_spec_doc = load_json(locked_spec_path)
                    if not isinstance(locked_spec_doc, dict):
                        fixture_error = "LockedSpec must be a JSON object"
                    else:
                        upstream_state = locked_spec_doc.get("upstream_state")
                        if not isinstance(upstream_state, dict):
                            fixture_error = "LockedSpec.upstream_state missing/invalid"
                        else:
                            base_sha = upstream_state.get("commit_sha")
                            if not isinstance(base_sha, str):
                                fixture_error = "LockedSpec.upstream_state.commit_sha missing/invalid"
                            else:
                                base_sha = base_sha.strip()
                                if not re.fullmatch(r"[0-9a-f]{40}", base_sha):
                                    fixture_error = f"LockedSpec.upstream_state.commit_sha must be 40 lowercase hex, got {base_sha!r}"
                                elif base_sha == "0" * 40:
                                    fixture_error = "LockedSpec.upstream_state.commit_sha cannot be all-zero"
                                else:
                                    evaluated_revision = base_sha
            except Exception as e:
                fixture_error = f"Failed to load/parse LockedSpec for evaluated_revision ({locked_spec_rel}): {e}"

            cmd: list[str] = []
            if fixture_error is None and evaluated_revision is not None:
                cmd = [
                    sys.executable,
                    "-m",
                    "chain.gate_r_verify",
                    "--repo",
                    ".",
                    "--locked-spec",
                    str(paths.get("locked_spec")),
                    "--gate-q-verdict",
                    str(paths.get("gate_q_verdict")),
                    "--evidence-manifest",
                    str(paths.get("evidence_manifest")),
                    "--r-snapshot-manifest-out",
                    r_snapshot_out_rel,
                    "--evaluated-revision",
                    evaluated_revision,
                    "--out",
                    out_path_rel,
                    "--gate-verdict-out",
                    gate_verdict_out_rel,
                ]

                rc, stdout, stderr = _run(cmd)
                primary, failure_category = _primary_from_gate_r_report(out_path)
            else:
                rc, stdout, stderr = 3, "", f"FIXTURE INVALID: {fixture_error}\n"
                primary, failure_category = (None, None)

            stdout_path = logs_dir / f"R__{name}.stdout.txt"
            stderr_path = logs_dir / f"R__{name}.stderr.txt"
            _write_text(stdout_path, stdout)
            _write_text(stderr_path, stderr)

            results.append(
                {
                    "gate": "R",
                    "fixture": name,
                    "expected_exit_code": expected_rc,
                    "expected_primary": expected_primary,
                    "actual_exit_code": rc,
                    "primary": primary,
                    "failure_category": failure_category,
                    "physical_missing_paths": sorted(r_missing_paths.get(name, [])),
                    "cmd": cmd,
                    "verifier_out_path": str(out_path.as_posix()),
                    "stdout_path": str(stdout_path.as_posix()),
                    "stderr_path": str(stderr_path.as_posix()),
                    "stdout_sha256": _sha256_text(stdout),
                    "stderr_sha256": _sha256_text(stderr),
                }
            )

    unexpected_rc = [r for r in results if int(r.get("actual_exit_code", -999)) != int(r.get("expected_exit_code", -998))]
    unexpected_primary = [
        r
        for r in results
        if (r.get("expected_primary") is not None)
        and (r.get("expected_primary") != r.get("primary"))
        and not (int(r.get("expected_exit_code", -1)) == 0 and r.get("expected_primary") is None)
    ]

    print(
        f"Ran {len(results)} fixtures ("
        f"{len([r for r in results if r.get('gate')=='Q'])} Q, {len([r for r in results if r.get('gate')=='R'])} R)."
    )
    if unexpected_rc or unexpected_primary:
        print(f"UNEXPECTED: rc={len(unexpected_rc)}, primary={len(unexpected_primary)}")
        for r in unexpected_rc:
            print(
                f"- Gate {r.get('gate')} {r.get('fixture')}: expected rc {r.get('expected_exit_code')}, got {r.get('actual_exit_code')}"
            )
        for r in unexpected_primary:
            print(
                f"- Gate {r.get('gate')} {r.get('fixture')}: expected primary {r.get('expected_primary')}, got {r.get('primary')}"
            )
    else:
        print("All fixtures matched expected rc and expected_primary (when provided).")

    report = {
        "generated_at": EVALUATED_AT,
        "repo_root": str(REPO_ROOT),
        "out_dir": str(out_dir),
        "gate": str(args.gate).upper(),
        "validation_warnings": validation_warnings,
        "results": results,
    }
    _write_json(out_dir / "fixture_sweep_report.json", report)

    return 1 if (unexpected_rc or unexpected_primary) else 0


def _fixtures_seal_main(argv: list[str] | None = None) -> int:
    """Sweep Seal producer fixtures (policy/fixtures/public/seal) through chain/seal_bundle.py."""

    default_fixtures_root = "policy/fixtures/public/seal"
    ap = argparse.ArgumentParser(description="Run Seal producer fixtures sweep")
    ap.add_argument(
        "--repo",
        default=str(REPO_ROOT),
        help="Compatibility flag (must resolve to this repo root).",
    )
    ap.add_argument("--fixtures-root", default=default_fixtures_root)
    ap.add_argument("--out-dir", default="temp/seal_fixture_sweep")
    args = ap.parse_args(argv)

    repo_arg = Path(str(args.repo)).resolve()
    if repo_arg != REPO_ROOT:
        raise _UserInputError(f"--repo must resolve to repo root {REPO_ROOT}, got {repo_arg}")

    fixtures_root_rel = _validate_repo_rel(str(args.fixtures_root))
    fixtures_root = _resolve_repo_path(REPO_ROOT, fixtures_root_rel, must_exist=True, must_be_file=False)
    if not fixtures_root.is_dir():
        print("ERROR: fixtures-root must be a directory", file=sys.stderr)
        return 3

    out_dir_rel = _validate_repo_rel(str(args.out_dir))
    out_dir = _resolve_repo_path(REPO_ROOT, out_dir_rel, must_exist=False)
    out_dir.mkdir(parents=True, exist_ok=True)
    manifests_out_dir = out_dir / "manifests"
    manifests_out_dir.mkdir(parents=True, exist_ok=True)

    try:
        cases_expected = _load_cases_expected(fixtures_root / "cases.json")
    except Exception as e:
        print(f"ERROR: Failed to load cases.json: {e}", file=sys.stderr)
        return 3

    errors, warnings, missing_by_fixture = _validate_cases_warn_missing_paths(
        gate="SEAL", fixtures_root=fixtures_root, cases_expected=cases_expected
    )
    for w in warnings:
        print(f"WARNING: {w}", file=sys.stderr)

    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        return 2

    results: list[dict[str, object]] = []
    all_ok = True

    for fixture_dir in _list_fixture_dirs(fixtures_root):
        name = fixture_dir.name
        entry = cases_expected[name]
        expected_rc = int(entry["expected_exit_code"])

        paths = entry.get("paths")
        assert isinstance(paths, dict)

        params = entry.get("params")
        if not isinstance(params, dict):
            params = {}

        final_commit_sha = str(params.get("final_commit_sha") or "0" * 40)
        sealed_at = str(params.get("sealed_at") or "2000-01-01T00:30:00Z")
        signer = str(params.get("signer") or "human:fixture")

        out_manifest = paths.get("out_manifest")
        if isinstance(out_manifest, str) and out_manifest.strip():
            out_path = out_manifest.strip()
        else:
            out_path = (manifests_out_dir / f"SealManifest__{name}.json").relative_to(REPO_ROOT).as_posix()

        cmd = [
            sys.executable,
            "-m",
            "chain.seal_bundle",
            "--repo",
            ".",
            "--locked-spec",
            str(paths["locked_spec"]),
            "--gate-q-verdict",
            str(paths["gate_q_verdict"]),
            "--gate-r-verdict",
            str(paths["gate_r_verdict"]),
            "--evidence-manifest",
            str(paths["evidence_manifest"]),
            "--final-commit-sha",
            final_commit_sha,
            "--sealed-at",
            sealed_at,
            "--signer",
            signer,
            "--out",
            out_path,
        ]

        sig_path = paths.get("seal_signature_b64")
        if isinstance(sig_path, str) and sig_path.strip():
            cmd.extend(["--seal-signature-file", sig_path.strip()])

        rc, stdout, stderr = _run(cmd)
        ok = rc == expected_rc
        all_ok = all_ok and ok

        stdout_path = out_dir / f"{name}.stdout.txt"
        stderr_path = out_dir / f"{name}.stderr.txt"
        _write_text(stdout_path, stdout)
        _write_text(stderr_path, stderr)

        results.append(
            {
                "fixture": name,
                "expected_exit_code": expected_rc,
                "exit_code": rc,
                "physical_missing_paths": sorted(missing_by_fixture.get(name, [])),
                "cmd": cmd,
                "out_path": out_path,
                "stdout_sha256": _sha256_text(stdout),
                "stderr_sha256": _sha256_text(stderr),
            }
        )

        status = "OK" if ok else "MISMATCH"
        print(f"SEAL {name}: rc={rc} expected={expected_rc} => {status}")

    report = {
        "generated_at": EVALUATED_AT,
        "tool": "fixtures-seal",
        "fixtures_root": fixtures_root.as_posix(),
        "results": results,
        "summary": {
            "total": len(results),
            "matched": sum(1 for r in results if int(r.get("exit_code", -1)) == int(r.get("expected_exit_code", -2))),
            "mismatched": sum(
                1 for r in results if int(r.get("exit_code", -1)) != int(r.get("expected_exit_code", -2))
            ),
        },
    }

    report_path = out_dir / "seal_fixture_sweep_report.json"
    _write_json(report_path, report)
    print(f"Wrote: {report_path.as_posix()}")

    return 0 if all_ok else 2


def _fixtures_s_main(argv: list[str] | None = None) -> int:
    """Sweep Gate S verifier fixtures (policy/fixtures/public/gate_s) through chain/gate_s_verify.py."""

    default_fixtures_root = "policy/fixtures/public/gate_s"
    ap = argparse.ArgumentParser(description="Run Gate S verifier fixtures sweep")
    ap.add_argument(
        "--repo",
        default=str(REPO_ROOT),
        help="Compatibility flag (must resolve to this repo root).",
    )
    ap.add_argument("--fixtures-root", default=default_fixtures_root)
    ap.add_argument("--out-dir", default="temp/gate_s_fixture_sweep")
    args = ap.parse_args(argv)

    repo_arg = Path(str(args.repo)).resolve()
    if repo_arg != REPO_ROOT:
        raise _UserInputError(f"--repo must resolve to repo root {REPO_ROOT}, got {repo_arg}")

    fixtures_root_rel = _validate_repo_rel(str(args.fixtures_root))
    fixtures_root = _resolve_repo_path(REPO_ROOT, fixtures_root_rel, must_exist=True, must_be_file=False)
    if not fixtures_root.is_dir():
        print("ERROR: fixtures-root must be a directory", file=sys.stderr)
        return 3

    out_dir_rel = _validate_repo_rel(str(args.out_dir))
    out_dir = _resolve_repo_path(REPO_ROOT, out_dir_rel, must_exist=False)
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        cases_expected = _load_cases_expected(fixtures_root / "cases.json")
    except Exception as e:
        print(f"ERROR: Failed to load cases.json: {e}", file=sys.stderr)
        return 3

    validation_errors = _validate_cases_fail_closed_on_missing_paths(fixtures_root=fixtures_root, cases_expected=cases_expected)
    if validation_errors:
        print("ERROR: Fixture expectation contract violated (fail-closed).", file=sys.stderr)
        for msg in validation_errors:
            print(f"- {msg}", file=sys.stderr)
        return 2

    verifier_out_dir = out_dir / "verifier_out"
    verifier_out_dir.mkdir(parents=True, exist_ok=True)
    logs_dir = out_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, object]] = []
    for fixture_dir in _list_fixture_dirs(fixtures_root):
        name = fixture_dir.name
        entry = cases_expected[name]
        expected_rc = int(entry["expected_exit_code"])

        paths = entry.get("paths")
        assert isinstance(paths, dict)

        out_path = verifier_out_dir / f"S__{name}.json"
        out_path_rel = out_path.relative_to(REPO_ROOT).as_posix()

        cmd = [
            sys.executable,
            "-m",
            "chain.gate_s_verify",
            "--repo",
            ".",
            "--locked-spec",
            str(paths["locked_spec"]),
            "--seal-manifest",
            str(paths["seal_manifest"]),
            "--evidence-manifest",
            str(paths["evidence_manifest"]),
            "--out",
            out_path_rel,
        ]

        rc, stdout, stderr = _run(cmd)

        stdout_path = logs_dir / f"S__{name}.stdout.txt"
        stderr_path = logs_dir / f"S__{name}.stderr.txt"
        _write_text(stdout_path, stdout)
        _write_text(stderr_path, stderr)

        results.append(
            {
                "fixture": name,
                "expected_exit_code": expected_rc,
                "actual_exit_code": rc,
                "ok": rc == expected_rc,
                "cmd": cmd,
                "verifier_out_path": str(out_path.as_posix()),
                "stdout_sha256": _sha256_text(stdout),
                "stderr_sha256": _sha256_text(stderr),
            }
        )

    unexpected_rc = [r for r in results if int(r.get("actual_exit_code", -1)) != int(r.get("expected_exit_code", -2))]

    print(f"Ran {len(results)} Gate S fixtures.")
    if unexpected_rc:
        print(f"UNEXPECTED: rc={len(unexpected_rc)}")
        for r in unexpected_rc:
            print(
                f"- Gate S {r.get('fixture')}: expected rc {r.get('expected_exit_code')}, got {r.get('actual_exit_code')}"
            )
    else:
        print("All fixtures matched expected exit code.")

    report = {
        "generated_at": EVALUATED_AT,
        "repo_root": str(REPO_ROOT),
        "out_dir": str(out_dir),
        "fixtures_root": str(fixtures_root),
        "results": results,
    }
    _write_json(out_dir / "gate_s_fixture_sweep_report.json", report)

    return 1 if unexpected_rc else 0


# ----------------------------
# Unified CLI
# ----------------------------


def _parse_args(argv: Sequence[str] | None) -> tuple[argparse.Namespace, list[str]]:
    ap = argparse.ArgumentParser(description="Unified sweeper entrypoint")
    ap.add_argument(
        "cmd",
        choices=["consistency", "fixtures-q", "fixtures-r", "fixtures-qr", "fixtures-s", "fixtures-seal"],
        help="Subcommand",
    )
    ap.add_argument("args", nargs=argparse.REMAINDER, help="Subcommand args (optional leading '--' accepted)")
    ns = ap.parse_args(list(argv) if argv is not None else None)
    rest = [a for a in ns.args if a != "--"]
    return ns, rest


def main(argv: list[str] | None = None) -> int:
    try:
        ns, rest = _parse_args(argv)

        if ns.cmd == "consistency":
            return int(_consistency_sweep_main(rest))

        if ns.cmd in ("fixtures-q", "fixtures-r", "fixtures-qr"):
            gate = "QR"
            if ns.cmd == "fixtures-q":
                gate = "Q"
            elif ns.cmd == "fixtures-r":
                gate = "R"

            return int(_fixtures_qr_main(["--gate", gate] + rest))

        if ns.cmd == "fixtures-s":
            return int(_fixtures_s_main(rest))

        if ns.cmd == "fixtures-seal":
            return int(_fixtures_seal_main(rest))

        raise _UserInputError(f"Unknown command: {ns.cmd}")
    except _UserInputError as e:
        print(f"NO-GO: {e}")
        return 2
    except json.JSONDecodeError as e:
        print(f"NO-GO: JSON parse error: {e}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
