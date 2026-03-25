#!/usr/bin/env python3
"""Unified sweeper entrypoint.

This file is the canonical sweep CLI.

Commands:
- consistency: generate policy/consistency_sweep.json (canonical)
"""

# maintainer marker: bk_ycanary_7f3a9c2d

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, List, Sequence

EVALUATED_AT = "1970-01-01T00:00:00Z"

CANONICAL_SWEEP_OUT = "policy/consistency_sweep.json"
CANONICAL_SWEEP_SUMMARY = "policy/consistency_sweep.summary.md"
CONSISTENCY_SPEC_DOC = "docs/operations/consistency-sweep.md"

_C3_CANONICAL_MIRROR_BINDINGS: tuple[tuple[str, str], ...] = (
    ("CANONICALS.md", "belgi/canonicals/CANONICALS.md"),
    ("terminology.md", "belgi/canonicals/terminology.md"),
    ("trust-model.md", "belgi/canonicals/trust-model.md"),
    ("docs/operations/consistency-sweep.md", "belgi/canonicals/docs/operations/consistency-sweep.md"),
    ("docs/operations/cli.md", "belgi/canonicals/docs/operations/cli.md"),
    ("docs/operations/evidence-bundles.md", "belgi/canonicals/docs/operations/evidence-bundles.md"),
    ("docs/operations/evidence-ownership.md", "belgi/canonicals/docs/operations/evidence-ownership.md"),
    ("docs/operations/running-belgi.md", "belgi/canonicals/docs/operations/running-belgi.md"),
    ("docs/operations/security.md", "belgi/canonicals/docs/operations/security.md"),
    ("docs/operations/waivers.md", "belgi/canonicals/docs/operations/waivers.md"),
    ("docs/research/README.md", "belgi/canonicals/docs/research/README.md"),
    ("docs/research/experiment-design.md", "belgi/canonicals/docs/research/experiment-design.md"),
    ("docs/research/metrics.md", "belgi/canonicals/docs/research/metrics.md"),
)

_PROTOCOL_IDENTITY_SOURCE_GUARD_FILES: tuple[str, ...] = (
    "CANONICALS.md",
    "gates/GATE_Q.md",
    "gates/GATE_R.md",
    "gates/GATE_S.md",
    "gates/failure-taxonomy.md",
    "belgi/canonicals/CANONICALS.md",
    "belgi/_protocol_packs/v1/gates/GATE_Q.md",
    "belgi/_protocol_packs/v1/gates/GATE_R.md",
    "belgi/_protocol_packs/v1/gates/GATE_S.md",
    "belgi/_protocol_packs/v1/gates/failure-taxonomy.md",
)

_PROTOCOL_IDENTITY_SOURCE_FORBIDDEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "identity tuple includes source",
        re.compile(r"\bpack_id\s*,\s*manifest_sha256\s*,\s*pack_name\s*,\s*source\b", flags=re.IGNORECASE),
    ),
    (
        "active identity includes source",
        re.compile(r"active protocol context identity.*\bsource\b", flags=re.IGNORECASE),
    ),
    (
        "source compared for identity",
        re.compile(r"lockedspec\.protocol_pack\.source.*active\s+`?source`?", flags=re.IGNORECASE),
    ),
    (
        "source mismatch wording",
        re.compile(r"\bsource mismatch\b", flags=re.IGNORECASE),
    ),
)

_FIXTURE_ZERO_GOVERNED_PUBLIC_PATHS: tuple[str, ...] = (
    "policy/fixtures/public/gate_q/cases.json",
    "policy/fixtures/public/gate_r/cases.json",
    "policy/fixtures/public/gate_s/cases.json",
    "policy/fixtures/public/seal/cases.json",
)

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


def check_cs_can_005(root: Path) -> InvariantResult:
    """CS-CAN-005 — Package canonical mirror is byte-identical to source docs."""

    missing: list[str] = []
    drifted: list[str] = []
    evidence: list[str] = []

    for src_rel, dst_rel in _C3_CANONICAL_MIRROR_BINDINGS:
        try:
            src = _resolve_repo_path(root, src_rel, must_exist=True, must_be_file=True)
        except _UserInputError:
            missing.append(src_rel)
            continue
        try:
            dst = _resolve_repo_path(root, dst_rel, must_exist=True, must_be_file=True)
        except _UserInputError:
            missing.append(dst_rel)
            continue

        evidence.extend([src_rel, dst_rel])
        if src.read_bytes() != dst.read_bytes():
            drifted.append(f"{dst_rel} != {src_rel}")

    if missing:
        joined = ", ".join(sorted(set(missing)))
        return InvariantResult(
            "CS-CAN-005",
            "FAIL",
            [f"{CONSISTENCY_SPEC_DOC}#cs-can-005--package-canonical-mirror-is-byte-identical-to-source-docs"],
            f"Missing canonical mirror source/target file(s): {joined}.",
        )

    if drifted:
        sample = ", ".join(sorted(drifted)[:8])
        extra = len(drifted) - 8
        suffix = "" if extra <= 0 else f" (+{extra} more)"
        return InvariantResult(
            "CS-CAN-005",
            "FAIL",
            [f"{CONSISTENCY_SPEC_DOC}#cs-can-005--package-canonical-mirror-is-byte-identical-to-source-docs"],
            (
                "Canonical package mirror drift detected. "
                "Run `python -m tools.build_builtin_pack` and rerun sweep. Drift: "
                f"{sample}{suffix}."
            ),
        )

    return InvariantResult(
        "CS-CAN-005",
        "PASS",
        sorted(set(evidence)),
        "",
    )


_TERM_GUARD_FIXED_FILES: set[str] = {
    "README.md",
    "CANONICALS.md",
    "WHITEPAPER.md",
    "terminology.md",
    "trust-model.md",
    "schemas/README.md",
    "belgi/_protocol_packs/v1/schemas/README.md",
}

_TERM_GUARD_PREFIXES: tuple[str, ...] = (
    "docs/",
    "gates/",
    "tiers/",
    "belgi/_protocol_packs/v1/gates/",
    "belgi/_protocol_packs/v1/tiers/",
)

_TERM_GUARD_ALLOWED_CONTEXTS: tuple[str, ...] = (
    "schema",
    "schema_validation",
    ".schema.json",
    "format validation",
    "parse validation",
    "input validation",
)


def _term_guard_scan_files(root: Path) -> list[str]:
    """Deterministically enumerate tracked doc surfaces for CS-TERM-001."""

    tracked = _run_git(root, ["ls-files"])
    files: set[str] = set()
    for raw in tracked.splitlines():
        rel = raw.strip()
        if not rel:
            continue
        rel = _validate_repo_rel(rel)
        # This spec file contains forbidden token examples by design.
        if rel == CONSISTENCY_SPEC_DOC:
            continue
        if rel in _TERM_GUARD_FIXED_FILES:
            files.add(rel)
            continue
        if rel.endswith((".md", ".txt")) and any(rel.startswith(p) for p in _TERM_GUARD_PREFIXES):
            files.add(rel)
    return sorted(files)


def check_cs_term_001(root: Path) -> InvariantResult:
    """CS-TERM-001 — Terminology Drift Guard (Verification vs Validation)."""

    try:
        targets = _term_guard_scan_files(root)
    except Exception as e:
        return InvariantResult(
            "CS-TERM-001",
            "FAIL",
            ["docs/operations/consistency-sweep.md#cs-term-001--terminology-drift-guard-verification-vs-validation"],
            f"Failed to enumerate tracked doc surfaces for terminology drift guard ({e}).",
        )

    if not targets:
        return InvariantResult(
            "CS-TERM-001",
            "FAIL",
            ["docs/operations/consistency-sweep.md#cs-term-001--terminology-drift-guard-verification-vs-validation"],
            "No tracked documentation files found for terminology drift guard scope.",
        )

    token_re = re.compile(r"(?i)\b(validation|validate|validated)\b")
    offenders: list[tuple[str, int, str]] = []

    for rel in targets:
        p = _resolve_repo_path(root, rel, must_exist=True, must_be_file=True)
        lines = read_text(p).splitlines()
        for idx, line in enumerate(lines, start=1):
            lower = line.lower()
            reason = ""
            if "deterministic validation" in lower:
                reason = "contains banned phrase 'deterministic validation'"
            elif "validation posture" in lower:
                reason = "contains banned phrase 'validation posture'"
            elif "probabilistic execution" in lower:
                reason = "contains banned phrase 'probabilistic execution'"
            elif token_re.search(line) and not any(ctx in lower for ctx in _TERM_GUARD_ALLOWED_CONTEXTS):
                reason = "contains non-mechanical validation token"
            if reason:
                offenders.append((rel, idx, reason))

    if offenders:
        offenders.sort(key=lambda t: (t[0], t[1], t[2]))
        listed = "; ".join(f"{rel}:{line} ({reason})" for rel, line, reason in offenders)
        return InvariantResult(
            "CS-TERM-001",
            "FAIL",
            ["CANONICALS.md#bounded-claim", "CANONICALS.md#terminology-boundaries"],
            "Terminology drift detected at "
            + listed
            + ". Replace claim-level wording with 'verification'; use 'schema-validate'/'schema validation' only for mechanical conformance. See CANONICALS.md#terminology-boundaries.",
        )

    return InvariantResult(
        "CS-TERM-001",
        "PASS",
        ["CANONICALS.md#bounded-claim", "CANONICALS.md#terminology-boundaries"],
        "",
    )


def _normalize_cs_can_001_subject(text: str) -> str:
    subject = re.sub(r"\s+", " ", str(text or "").strip())
    if len(subject) >= 2 and subject.startswith("`") and subject.endswith("`"):
        inner = subject[1:-1].strip()
        if inner:
            subject = inner
    return re.sub(r"\s+", " ", subject).casefold()


def _extract_cs_can_001_term_map_subjects(term_map: str) -> set[str]:
    subjects: set[str] = set()
    for raw_line in term_map.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if line.startswith("|") and line.endswith("|"):
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            if len(cells) >= 2 and cells[0].lower() != "term":
                if re.search(r"\(CANONICALS\.md#[^)]+\)", cells[1]):
                    normalized = _normalize_cs_can_001_subject(cells[0])
                    if normalized:
                        subjects.add(normalized)
            continue

        link_match = re.match(r"^\s*[-*+]\s+\[([^\]]+)\]\((CANONICALS\.md#[^)]+)\)\s*$", line)
        if link_match:
            normalized = _normalize_cs_can_001_subject(link_match.group(1))
            if normalized:
                subjects.add(normalized)
    return subjects


def _extract_cs_can_001_definitional_subject(line: str) -> str | None:
    match = re.match(r"^(?P<subject>.+?)\s+is\s+(?:an|the|a)\s+.+$", str(line or "").strip(), re.IGNORECASE)
    if not match:
        return None
    subject = _normalize_cs_can_001_subject(match.group("subject") or "")
    return subject or None


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
        canonical_subjects = _extract_cs_can_001_term_map_subjects(term_map)
        if not canonical_subjects:
            return InvariantResult(
                "CS-CAN-001",
                "FAIL",
                ["terminology.md#term-map"],
                "Populate the 'Term Map' section with canonical term pointers to CANONICALS.md#<anchor>.",
            )
    else:
        return InvariantResult(
            "CS-CAN-001",
            "FAIL",
            ["terminology.md"],
            "Add a 'Term Map' section whose entries link to CANONICALS.md#<anchor>.",
        )

    remaining_lines = strip_code_blocks_and_tables(md)
    offenders = []
    for raw_line in remaining_lines:
        line = raw_line.strip()
        if not line:
            continue
        subject = _extract_cs_can_001_definitional_subject(line)
        if subject and subject in canonical_subjects:
            offenders.append(line)
    if offenders:
        return InvariantResult(
            "CS-CAN-001",
            "FAIL",
            ["terminology.md"],
            "Remove non-pointer term definitions from terminology.md (found glossary-like definitional sentences for canonical term subjects of the form '<term> is a/an/the ...').",
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


def check_cs_is_005(root: Path) -> InvariantResult:
    """CS-IS-005 — Legacy numeric-budget retirement is consistent across schema/runtime/docs."""

    schema_path = repo_path(root, "schemas/IntentSpec.schema.json")
    if not schema_path.exists():
        return InvariantResult("CS-IS-005", "FAIL", ["schemas/IntentSpec.schema.json"], "Add schemas/IntentSpec.schema.json.")
    schema = load_json(schema_path)
    violations: list[str] = []
    try:
        scope_props = json_pointer(schema, "#/properties/scope/properties")
    except Exception:
        scope_props = {}
    if isinstance(scope_props, dict):
        for retired in ("max_touched_files", "max_loc_delta"):
            if retired in scope_props:
                violations.append(f"schemas/IntentSpec.schema.json still defines scope.{retired}")

    targets = {
        "chain/compiler_c1_intent.py": [
            "IntentSpec.scope numeric budgets are retired on the shipped run spine;",
            "move numeric budgets into a Tolerances object.",
        ],
        "chain/logic/q_checks/q_intent_003.py": [
            "IntentSpec.scope numeric budgets are retired on the shipped run spine;",
            "Do remove IntentSpec.scope.max_* and move numeric budgets into a Tolerances object ",
        ],
        "docs/operations/cli.md": [
            "numeric scope budgets no longer live in `IntentSpec`; move any legacy `IntentSpec.scope.max_*` values into the Tolerances object",
        ],
    }
    for rel, needles in targets.items():
        path = repo_path(root, rel)
        if not path.exists():
            violations.append(f"missing file: {rel}")
            continue
        text = read_text(path)
        for needle in needles:
            if needle not in text:
                violations.append(f"{rel} missing {needle!r}")

    if violations:
        return InvariantResult(
            "CS-IS-005",
            "FAIL",
            [
                "schemas/IntentSpec.schema.json",
                "chain/compiler_c1_intent.py",
                "chain/logic/q_checks/q_intent_003.py",
                "docs/operations/cli.md",
            ],
            "Keep legacy IntentSpec numeric-budget retirement aligned across schema, compiler, Gate Q, and operator docs.",
            {"violations_sample": violations[:12], "violations_total": len(violations)},
        )

    return InvariantResult(
        "CS-IS-005",
        "PASS",
        [
            "schemas/IntentSpec.schema.json",
            "chain/compiler_c1_intent.py",
            "chain/logic/q_checks/q_intent_003.py",
            "docs/operations/cli.md",
        ],
        "",
    )


def check_cs_run_001(root: Path) -> InvariantResult:
    """CS-RUN-001 — Shipped run object-ref CLI contract matches parser and command semantics."""

    targets = {
        "docs/operations/cli.md": [
            "--toolchain-set-ref <object_id>=<repo-relative-path>",
            "--toolchain-ref <object_id>=<repo-relative-path>",
            "--tolerances-ref <object_id>=<repo-relative-path>",
            "the referenced ToolchainSet file is a pre-lock operator input; accepted only as the current run's canonical run-local object path: `.belgi/runs/<run_id>/inputs/environment/toolchain-set.json`",
            "ToolchainSet member declaration paths must still point at actual repo-relative dependency/toolchain declaration surfaces in the evaluated revision truth envelope",
            "the referenced Tolerances file is a pre-lock operator input; accepted only as the current run's canonical run-local object path: `.belgi/runs/<run_id>/inputs/environment/tolerances.json`",
            "do not mix `--toolchain-set-ref` with shorthand `--toolchain-ref` values",
            "`toolchain.main` is reserved for the built-in generated run toolchain input",
        ],
        "belgi/cli_app/parser/run.py": ['"--toolchain-set-ref"', '"--toolchain-ref"', '"--tolerances-ref"'],
        "belgi/cli_app/commands/run.py": [
            "def _resolve_run_environment_object_ref(",
            "must point to the current run canonical input:",
            "do not mix --toolchain-set-ref with shorthand --toolchain-ref values",
            "--toolchain-ref id `toolchain.main` is reserved for the built-in run toolchain input",
            "--toolchain-set-ref id `toolchain.main` is reserved for the built-in run toolchain input",
        ],
    }
    violations: list[str] = []
    for rel, needles in targets.items():
        path = repo_path(root, rel)
        if not path.exists():
            violations.append(f"missing file: {rel}")
            continue
        text = read_text(path)
        for needle in needles:
            if needle not in text:
                violations.append(f"{rel} missing {needle!r}")

    if violations:
        return InvariantResult(
            "CS-RUN-001",
            "FAIL",
            ["docs/operations/cli.md", "belgi/cli_app/parser/run.py", "belgi/cli_app/commands/run.py"],
            "Keep shipped run object-ref flags and guardrails aligned across CLI docs, parser wiring, and command enforcement.",
            {"violations_sample": violations[:12], "violations_total": len(violations)},
        )

    return InvariantResult(
        "CS-RUN-001",
        "PASS",
        ["docs/operations/cli.md", "belgi/cli_app/parser/run.py", "belgi/cli_app/commands/run.py"],
        "",
    )


def check_cs_run_002(root: Path) -> InvariantResult:
    """CS-RUN-002 — run new guidance promotes authoritative environment inputs, not placeholders."""

    violations: list[str] = []
    command_path = repo_path(root, "belgi/cli_app/commands/run.py")
    if not command_path.exists():
        violations.append("missing file: belgi/cli_app/commands/run.py")
    else:
        from belgi.cli_app.commands.run import (
            _render_adopter_readme,
            _render_runbook_template,
        )

        rendered_targets = {
            "belgi/cli_app/commands/run.py::README.md(.belgi)": (
                _render_adopter_readme(workspace_rel=".belgi"),
                [
                    ".belgi/runs/run-001/inputs/environment/toolchain-set.json",
                    ".belgi/runs/run-001/inputs/environment/tolerances.json",
                    "--toolchain-set-ref env.toolchains=.belgi/runs/run-001/inputs/environment/toolchain-set.json",
                    "--tolerances-ref tier.tolerances=.belgi/runs/run-001/inputs/environment/tolerances.json",
                    "Optional shared run object inputs:",
                ],
            ),
            "belgi/cli_app/commands/run.py::RUN.md(run-001)": (
                _render_runbook_template(run_id="run-001"),
                [
                    ".belgi/runs/run-001/inputs/environment/toolchain-set.json",
                    ".belgi/runs/run-001/inputs/environment/tolerances.json",
                    "Optional shared environment objects:",
                    "cat > .belgi/runs/run-001/inputs/environment/toolchain-set.json <<'JSON'",
                    "cat > .belgi/runs/run-001/inputs/environment/tolerances.json <<'JSON'",
                    "--toolchain-set-ref env.toolchains=.belgi/runs/run-001/inputs/environment/toolchain-set.json",
                    "--tolerances-ref tier.tolerances=.belgi/runs/run-001/inputs/environment/tolerances.json",
                ],
            ),
        }
        forbidden_rendered = {
            "belgi/cli_app/commands/run.py::README.md(.belgi)": [
                ".belgi/runs/run-001/toolchain.json",
                ".belgi/runs/run-001/tolerances.json",
            ],
            "belgi/cli_app/commands/run.py::RUN.md(run-001)": [
                ".belgi/runs/run-001/toolchain.json",
                ".belgi/runs/run-001/tolerances.json",
            ],
        }
        for rel, (text, needles) in rendered_targets.items():
            for needle in needles:
                if needle not in text:
                    violations.append(f"{rel} missing {needle!r}")
        for rel, forbidden in forbidden_rendered.items():
            text = rendered_targets[rel][0]
            for needle in forbidden:
                if needle in text:
                    violations.append(f"{rel} still advertises stale placeholder {needle!r}")

    doc_targets = {
        "docs/operations/running-belgi.md": [
            ".belgi/runs/<run_id>/inputs/environment/toolchain-set.json",
            ".belgi/runs/<run_id>/inputs/environment/tolerances.json",
            "`belgi run new`",
            "this is the only accepted explicit `belgi run` ingress path for ToolchainSet",
            "this is the only accepted explicit `belgi run` ingress path for Tolerances",
        ],
    }
    forbidden_docs = {
        "docs/operations/running-belgi.md": [
            ".belgi/runs/<run_id>/toolchain.json",
            ".belgi/runs/<run_id>/tolerances.json",
            "The explicit CLI flags remain repo-relative and do not require a hardcoded workspace location.",
        ]
    }
    for rel, needles in doc_targets.items():
        path = repo_path(root, rel)
        if not path.exists():
            violations.append(f"missing file: {rel}")
            continue
        text = read_text(path)
        for needle in needles:
            if needle not in text:
                violations.append(f"{rel} missing {needle!r}")
    for rel, forbidden in forbidden_docs.items():
        path = repo_path(root, rel)
        if not path.exists():
            continue
        text = read_text(path)
        for needle in forbidden:
            if needle in text:
                violations.append(f"{rel} still advertises stale placeholder {needle!r}")

    if violations:
        return InvariantResult(
            "CS-RUN-002",
            "FAIL",
            ["belgi/cli_app/commands/run.py", "docs/operations/running-belgi.md"],
            "Keep run new guidance and operator docs anchored on authoritative inputs/environment ToolchainSet and Tolerances objects.",
            {"violations_sample": violations[:12], "violations_total": len(violations)},
        )

    return InvariantResult(
        "CS-RUN-002",
        "PASS",
        ["belgi/cli_app/commands/run.py", "docs/operations/running-belgi.md"],
        "",
    )


def check_cs_schema_001(root: Path) -> InvariantResult:
    """CS-SCHEMA-001 — Schema catalog claims for ToolchainSet/Tolerances match runtime loaders."""

    root_readme_path = repo_path(root, "schemas/README.md")
    pack_readme_path = repo_path(root, "belgi/_protocol_packs/v1/schemas/README.md")
    required_files = [
        "schemas/README.md",
        "belgi/_protocol_packs/v1/schemas/README.md",
        "chain/logic/locked_object_schema.py",
        "chain/logic/toolchain_set.py",
        "chain/logic/tolerances.py",
    ]
    violations: list[str] = []
    for rel in required_files:
        if not repo_path(root, rel).exists():
            violations.append(f"{rel} missing")
    if not violations:
        if root_readme_path.read_bytes() != pack_readme_path.read_bytes():
            violations.append("schema README mirror drift: root vs protocol-pack")

        required_claims = [
            "Gate Q / Gate R locked-object loaders validate ToolchainSet and Tolerances against these published schemas after ObjectRef hash binding.",
            "schema and runtime both reject legacy `IntentSpec.scope.max_*` fields.",
        ]
        for rel in ("schemas/README.md", "belgi/_protocol_packs/v1/schemas/README.md"):
            text = read_text(repo_path(root, rel))
            for needle in required_claims:
                if needle not in text:
                    violations.append(f"{rel} missing {needle!r}")

        loader_targets = {
            "chain/logic/locked_object_schema.py": ["validate_schema(", "resolve_storage_ref"],
            "chain/logic/toolchain_set.py": ["schemas/ToolchainSet.schema.json", "load_locked_schema_object"],
            "chain/logic/tolerances.py": ["schemas/Tolerances.schema.json", "load_locked_schema_object"],
        }
        for rel, needles in loader_targets.items():
            text = read_text(repo_path(root, rel))
            for needle in needles:
                if needle not in text:
                    violations.append(f"{rel} missing {needle!r}")

    if violations:
        return InvariantResult(
            "CS-SCHEMA-001",
            "FAIL",
            [
                "schemas/README.md",
                "belgi/_protocol_packs/v1/schemas/README.md",
                "chain/logic/locked_object_schema.py",
                "chain/logic/toolchain_set.py",
                "chain/logic/tolerances.py",
            ],
            "Keep schema catalog claims, protocol-pack mirror, and ToolchainSet/Tolerances runtime loaders aligned.",
            {"violations_sample": violations[:12], "violations_total": len(violations)},
        )

    return InvariantResult(
        "CS-SCHEMA-001",
        "PASS",
        [
            "schemas/README.md",
            "belgi/_protocol_packs/v1/schemas/README.md",
            "chain/logic/locked_object_schema.py",
            "chain/logic/toolchain_set.py",
            "chain/logic/tolerances.py",
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

    def extract_tier_block(doc: str, tier_id: str) -> str | None:
        header_re = re.compile(
            rf"^###\s+(?:\d+(?:\.\d+)*\s+)?Tier\s+\d+\s+\({re.escape(tier_id)}\)\s*$",
            re.MULTILINE,
        )
        m = header_re.search(doc)
        if not m:
            return None
        start = m.end()
        next_m = re.search(r"^###\s+(?:\d+(?:\.\d+)*\s+)?Tier\s+\d+\s+\(tier-\d\)\s*$", doc[start:], re.MULTILINE)
        end = start + next_m.start() if next_m else len(doc)
        return doc[start:end]

    if not doc_mentions_all(t_txt, tier0) or not doc_mentions_all(t_txt, tier1):
        return InvariantResult(
            "CS-TIER-002",
            "FAIL",
            ["tiers/tier-packs.md#3-tier-parameter-sets"],
            "Ensure tier-packs.md lists required_evidence_kinds for tier-0 and tier-1..3 exactly as specified.",
        )

    tier0_block = extract_tier_block(t_txt, "tier-0")
    if tier0_block is None or "- adversarial_policy:" not in tier0_block or "findings_mode: `warn`" not in tier0_block:
        return InvariantResult(
            "CS-TIER-002",
            "FAIL",
            ["tiers/tier-packs.md#3-tier-parameter-sets"],
            "Ensure tier-0 documents adversarial_policy.findings_mode as warn.",
        )
    for tid in ("tier-1", "tier-2", "tier-3"):
        block = extract_tier_block(t_txt, tid)
        if block is None or "- adversarial_policy:" not in block or "findings_mode: `fail`" not in block:
            return InvariantResult(
                "CS-TIER-002",
                "FAIL",
                ["tiers/tier-packs.md#3-tier-parameter-sets"],
                "Ensure tier-1..tier-3 document adversarial_policy.findings_mode as fail.",
            )
    if "| R8 |" not in t_txt or "adversarial_policy.findings_mode" not in t_txt:
        return InvariantResult(
            "CS-TIER-002",
            "FAIL",
            ["tiers/tier-packs.md#4-tier--gate-parameter-map"],
            "Ensure R8 gate parameter map includes adversarial_policy.findings_mode.",
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
    missing_q = _missing_needles(q_txt, ["Q6", "status == \"active\"", "expires_at", "anchored_time_utc", "placeholder"])
    if missing_q:
        return InvariantResult(
            "CS-WVR-002",
            "FAIL",
            ["gates/GATE_Q.md#q6--waivers-validity-if-present"],
            "Ensure Gate Q Q6 enforces active status, placeholder rejection, and expires_at after EvidenceManifest.anchored_time_utc.",
        )
    ops_txt = read_text(ops)
    if "expires_at" not in ops_txt or "audit_trail_ref" not in ops_txt:
        return InvariantResult(
            "CS-WVR-002",
            "FAIL",
            ["docs/operations/waivers.md#34-apply-to-a-run-lockedspecwaivers_applied"],
            "Ensure waivers.md documents expires_at and audit_trail_ref requirements and application point.",
        )
    missing_ops = _missing_needles(
        ops_txt,
        [
            "status: \"revoked\"",
            "placeholder",
            "anchored_time_utc",
            "belgi verify",
            "fails closed",
            "mitigation",
        ],
    )
    if missing_ops:
        return InvariantResult(
            "CS-WVR-002",
            "FAIL",
            ["docs/operations/waivers.md#31-create-request-human", "docs/operations/waivers.md#43-verify-replay-enforcement-post-run"],
            "Ensure waivers.md documents revoked-by-default draft posture, placeholder rejection, anchored replay via belgi verify, fail-closed behavior, and mitigation field requirements.",
        )

    return InvariantResult(
        "CS-WVR-002",
        "PASS",
        ["schemas/Waiver.schema.json#/required", "gates/GATE_Q.md#q6--waivers-validity-if-present", "docs/operations/waivers.md#34-apply-to-a-run-lockedspecwaivers_applied"],
        "",
    )


def check_cs_wvr_003(root: Path) -> InvariantResult:
    """CS-WVR-003 — Tier waiver policy is consistent and enforced."""

    tiers_json = repo_path(root, "tiers/tier-packs.json")
    tiers = repo_path(root, "tiers/tier-packs.md")
    q = repo_path(root, "gates/GATE_Q.md")
    ops = repo_path(root, "docs/operations/waivers.md")
    for rel, p in [
        ("tiers/tier-packs.json", tiers_json),
        ("tiers/tier-packs.md", tiers),
        ("gates/GATE_Q.md", q),
        ("docs/operations/waivers.md", ops),
    ]:
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

    try:
        tiers_obj = load_json(tiers_json)
    except Exception as e:
        return InvariantResult(
            "CS-WVR-003",
            "FAIL",
            ["tiers/tier-packs.json"],
            f"Fix tier-packs.json parse error ({e}).",
        )

    tier_map = tiers_obj.get("tiers")
    if not isinstance(tier_map, dict):
        return InvariantResult(
            "CS-WVR-003",
            "FAIL",
            ["tiers/tier-packs.json#/tiers"],
            "tiers/tier-packs.json must define an object at /tiers.",
        )

    expected_limits: dict[str, tuple[bool, int]] = {}
    for tid in ("tier-0", "tier-1", "tier-2", "tier-3"):
        tier_entry = tier_map.get(tid)
        if not isinstance(tier_entry, dict):
            return InvariantResult(
                "CS-WVR-003",
                "FAIL",
                [f"tiers/tier-packs.json#/tiers/{tid}"],
                f"tiers/tier-packs.json missing {tid} tier entry.",
            )
        waiver_policy = tier_entry.get("waiver_policy")
        if not isinstance(waiver_policy, dict):
            return InvariantResult(
                "CS-WVR-003",
                "FAIL",
                [f"tiers/tier-packs.json#/tiers/{tid}/waiver_policy"],
                f"tiers/tier-packs.json missing waiver_policy for {tid}.",
            )
        allowed = waiver_policy.get("allowed")
        max_active = waiver_policy.get("max_active_waivers")
        if not isinstance(allowed, bool):
            return InvariantResult(
                "CS-WVR-003",
                "FAIL",
                [f"tiers/tier-packs.json#/tiers/{tid}/waiver_policy/allowed"],
                f"tiers/tier-packs.json waiver_policy.allowed must be boolean for {tid}.",
            )
        if not (isinstance(max_active, int) and not isinstance(max_active, bool) and max_active >= 0):
            return InvariantResult(
                "CS-WVR-003",
                "FAIL",
                [f"tiers/tier-packs.json#/tiers/{tid}/waiver_policy/max_active_waivers"],
                f"tiers/tier-packs.json waiver_policy.max_active_waivers must be a non-negative integer for {tid}.",
            )
        expected_limits[tid] = (allowed, max_active)

    observed_limits: dict[str, tuple[bool, int, int]] = {}
    tier_line_re = re.compile(
        r"^\s*-\s*Tier\s+([0-3])\s*:\s*waivers\s+(allowed|not allowed)"
        r"(?:,\s*max\s+([0-9]+)\s+active)?(?:,\s*.*)?\s*$",
        flags=re.IGNORECASE,
    )
    for line_no, line in enumerate(read_text(ops).splitlines(), start=1):
        m = tier_line_re.match(line)
        if m is None:
            continue
        tid = f"tier-{m.group(1)}"
        allowed_token = m.group(2).lower()
        allowed = allowed_token == "allowed"
        max_active_raw = m.group(3)
        max_active = int(max_active_raw) if max_active_raw is not None else 0
        observed_limits[tid] = (allowed, max_active, line_no)

    drift: list[str] = []
    for tid in ("tier-0", "tier-1", "tier-2", "tier-3"):
        if tid not in observed_limits:
            drift.append(f"{tid}:missing in docs/operations/waivers.md#5.1")
            continue
        expected_allowed, expected_max = expected_limits[tid]
        observed_allowed, observed_max, observed_line = observed_limits[tid]
        if (expected_allowed, expected_max) != (observed_allowed, observed_max):
            drift.append(
                f"{tid}@docs/operations/waivers.md:{observed_line}:"
                f"expected allowed={expected_allowed},max_active_waivers={expected_max};"
                f"found allowed={observed_allowed},max_active_waivers={observed_max}"
            )
    if drift:
        return InvariantResult(
            "CS-WVR-003",
            "FAIL",
            ["tiers/tier-packs.json#/tiers", "docs/operations/waivers.md#51-limits-per-tier"],
            "Ensure docs/operations/waivers.md §5.1 limits exactly match tiers/tier-packs.json waiver_policy. "
            + "; ".join(drift),
            {"drift": drift},
        )

    return InvariantResult(
        "CS-WVR-003",
        "PASS",
        [
            "tiers/tier-packs.json#/tiers",
            "tiers/tier-packs.md#24-waiver_policy",
            "gates/GATE_Q.md#q6--waivers-validity-if-present",
            "docs/operations/waivers.md#51-limits-per-tier",
        ],
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


def check_cs_ls_002(root: Path) -> InvariantResult:
    """CS-LS-002 — ToolchainSet/Tolerances locked-object authority is explicit and wired."""

    locked_schema_path = repo_path(root, "schemas/LockedSpec.schema.json")
    if not locked_schema_path.exists():
        return InvariantResult(
            "CS-LS-002",
            "FAIL",
            ["schemas/LockedSpec.schema.json"],
            "Add explicit ToolchainSet/Tolerances ObjectRef fields to LockedSpec schema, then rerun sweep.",
        )

    locked_schema = load_json(locked_schema_path)
    pointer_expectations = [
        ("#/properties/environment_envelope/properties/toolchain_set_ref/$ref", "#/$defs/ObjectRef"),
        ("#/properties/environment_envelope/properties/pinned_toolchain_refs/items/$ref", "#/$defs/ObjectRef"),
        ("#/properties/tier/properties/tolerances_ref/$ref", "#/$defs/ObjectRef"),
    ]
    violations: list[str] = []
    for ptr, expected in pointer_expectations:
        try:
            actual = json_pointer(locked_schema, ptr)
        except Exception:
            violations.append(f"schemas/LockedSpec.schema.json{ptr} missing")
            continue
        if actual != expected:
            violations.append(f"schemas/LockedSpec.schema.json{ptr} expected {expected!r}, got {actual!r}")

    required_files = [
        "schemas/ToolchainSet.schema.json",
        "schemas/Tolerances.schema.json",
        "chain/compiler_c1_intent.py",
        "chain/logic/locked_object_schema.py",
        "chain/logic/toolchain_set.py",
        "chain/logic/tolerances.py",
        "chain/logic/q_checks/q4_constraints_present.py",
        "chain/logic/q_checks/q5_environment_envelope.py",
        "chain/logic/r_checks/r2_scope_budgets.py",
        "docs/operations/running-belgi.md",
    ]
    for rel in required_files:
        if not repo_path(root, rel).exists():
            violations.append(f"{rel} missing")

    string_expectations: list[tuple[str, list[str]]] = [
        (
            "chain/compiler_c1_intent.py",
            [
                "schemas/ToolchainSet.schema.json",
                "schemas/Tolerances.schema.json",
                '"toolchain_set_ref": toolchain_set_ref_obj',
                '"tolerances_ref": tolerances_ref',
            ],
        ),
        ("chain/logic/locked_object_schema.py", ["def load_locked_schema_object(", "resolve_storage_ref", "validate_schema("]),
        ("chain/logic/toolchain_set.py", ["load_locked_schema_object", "schemas/ToolchainSet.schema.json"]),
        ("chain/logic/tolerances.py", ["load_locked_schema_object", "schemas/Tolerances.schema.json"]),
        ("chain/logic/q_checks/q4_constraints_present.py", ["load_locked_tolerances"]),
        ("chain/logic/q_checks/q5_environment_envelope.py", ["load_locked_toolchain_set"]),
        ("chain/logic/r_checks/r2_scope_budgets.py", ["load_locked_tolerances", "locked Tolerances object only"]),
        ("docs/operations/running-belgi.md", ["--toolchain-set-ref", "--tolerances-ref"]),
    ]
    for rel, needles in string_expectations:
        path = repo_path(root, rel)
        if not path.exists():
            continue
        text = read_text(path)
        for needle in needles:
            if needle not in text:
                violations.append(f"{rel} missing {needle!r}")

    if violations:
        return InvariantResult(
            "CS-LS-002",
            "FAIL",
            [
                "schemas/LockedSpec.schema.json",
                "schemas/ToolchainSet.schema.json",
                "schemas/Tolerances.schema.json",
                "chain/compiler_c1_intent.py",
                "chain/logic/locked_object_schema.py",
                "chain/logic/toolchain_set.py",
                "chain/logic/tolerances.py",
                "chain/logic/q_checks/q4_constraints_present.py",
                "chain/logic/q_checks/q5_environment_envelope.py",
                "chain/logic/r_checks/r2_scope_budgets.py",
                "docs/operations/running-belgi.md",
            ],
            "Keep ToolchainSet/Tolerances as first-class LockedSpec object authority in schema, C1, loaders, Gate Q/R consumers, and run docs, then rerun sweep.",
            {"violations_sample": violations[:12], "violations_total": len(violations)},
        )

    return InvariantResult(
        "CS-LS-002",
        "PASS",
        [
            "schemas/LockedSpec.schema.json#/properties/environment_envelope/properties/toolchain_set_ref",
            "schemas/LockedSpec.schema.json#/properties/environment_envelope/properties/pinned_toolchain_refs/items",
            "schemas/LockedSpec.schema.json#/properties/tier/properties/tolerances_ref",
            "schemas/ToolchainSet.schema.json",
            "schemas/Tolerances.schema.json",
            "chain/compiler_c1_intent.py",
            "chain/logic/locked_object_schema.py",
            "chain/logic/toolchain_set.py",
            "chain/logic/tolerances.py",
            "chain/logic/q_checks/q4_constraints_present.py",
            "chain/logic/q_checks/q5_environment_envelope.py",
            "chain/logic/r_checks/r2_scope_budgets.py",
            "docs/operations/running-belgi.md",
        ],
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
        from tools.render import (
            check_target_drift,
            get_all_target_names,
            get_target_evidence_files,
        )
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

    These are part of the governed surface because the active builtin pack
    identity is authoritative and the manifest is validated against its tree.
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
        "WHITEPAPER.md",
        "TRADEMARK.md",
        "VERSION",
        "terminology.md",
        "trust-model.md",
        "gates/GATE_Q.md",
        "gates/GATE_R.md",
        "gates/GATE_S.md",
        "gates/failure-taxonomy.md",
        ".github/scripts/check_external_action_pins.py",
        ".github/scripts/resolve_belgi_workflow_inputs.py",
        ".github/scripts/run_belgi_smoke.py",
        ".github/scripts/validate_belgi_ref_pin.py",
        ".github/workflows/pinned-install-proof.yml",
        ".github/workflows/pull-request-proof.yml",
        ".github/workflows/repository-verification.yml",
        ".github/CODEOWNERS",
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
        "docs/operations/cli.md",
        "docs/operations/evidence-bundles.md",
        "docs/operations/evidence-ownership.md",
        "docs/operations/exit-codes.md",
        "docs/operations/operator-anchors.md",
        "docs/operations/running-belgi.md",
        "docs/operations/security.md",
        "docs/operations/consistency-sweep.md",
        "docs/operations/waivers.md",
        "docs/operations/workflows.md",
        "docs/research/README.md",
        "docs/research/experiment-design.md",
        "docs/research/metrics.md",
        "belgi/_protocol_packs/v1/schemas/README.md",
        # Package canonical mirror (must stay byte-identical to source docs)
        "belgi/canonicals/CANONICALS.md",
        "belgi/canonicals/terminology.md",
        "belgi/canonicals/trust-model.md",
        "belgi/canonicals/docs/operations/consistency-sweep.md",
        "belgi/canonicals/docs/operations/cli.md",
        "belgi/canonicals/docs/operations/evidence-bundles.md",
        "belgi/canonicals/docs/operations/evidence-ownership.md",
        "belgi/canonicals/docs/operations/operator-anchors.md",
        "belgi/canonicals/docs/operations/running-belgi.md",
        "belgi/canonicals/docs/operations/security.md",
        "belgi/canonicals/docs/operations/waivers.md",
        "belgi/canonicals/docs/research/README.md",
        "belgi/canonicals/docs/research/experiment-design.md",
        "belgi/canonicals/docs/research/metrics.md",
        # Tier-3 canonical authority surfaces
        "belgi/anchor/v1/TrustAnchor.json",
        "belgi/genesis/GenesisSealPayload.json",
        "belgi/genesis/README.md",
        "belgi/trust_anchor.py",
        # Operator convenience scripts (public ergonomics surface)
        "scripts/belgi_latest_run.ps1",
        "scripts/belgi_latest_run.py",
        "scripts/belgi_latest_run.sh",
        "scripts/belgi_wip_commit_run_reset.ps1",
        # CI template surface
        "templates/ci/github/belgi-tier1.yml",
        # Canonical deterministic verifier entrypoints
        "belgi/cli_app/parser/run.py",
        "belgi/cli_app/commands/run.py",
        "chain/gate_q_verify.py",
        "chain/gate_r_verify.py",
        "chain/gate_s_verify.py",
        "chain/compiler_c1_intent.py",
        "chain/seal_bundle.py",
        "chain/compiler_c3_docs.py",
        "chain/logic/locked_object_schema.py",
        "chain/logic/q_checks/q_intent_003.py",
        "chain/logic/toolchain_set.py",
        "chain/logic/tolerances.py",
        "chain/logic/q_checks/q4_constraints_present.py",
        "chain/logic/q_checks/q5_environment_envelope.py",
        "chain/logic/r_checks/r2_scope_budgets.py",
        # Canonical tools
        "tools/README.md",
        "tools/render.py",
        "tools/normalize.py",
        "tools/rehash.py",
        "tools/check_codeowners.py",
        "tools/report.py",
        "tools/sweep.py",
        "tools/wheel_boundary.py",
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

    # Exclude sweep outputs so CS-BYTE-001 cannot self-invalidate the current sweep artifact write.
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


def check_cs_protocol_identity_001(root: Path) -> InvariantResult:
    """CS-PROTOCOL-IDENTITY-001 — Protocol identity language excludes source from identity tuple."""

    missing_files: list[str] = []
    violations: list[str] = []
    for rel in sorted(_PROTOCOL_IDENTITY_SOURCE_GUARD_FILES):
        try:
            p = _resolve_repo_path(root, rel, must_exist=True, must_be_file=True)
        except _UserInputError:
            missing_files.append(rel)
            continue
        for line_no, line in enumerate(read_text(p).splitlines(), start=1):
            for reason, pattern in _PROTOCOL_IDENTITY_SOURCE_FORBIDDEN_PATTERNS:
                if pattern.search(line):
                    violations.append(f"{rel}:{line_no} ({reason})")
                    break

    if missing_files:
        joined = ", ".join(sorted(missing_files))
        return InvariantResult(
            "CS-PROTOCOL-IDENTITY-001",
            "FAIL",
            [CONSISTENCY_SPEC_DOC, "CANONICALS.md#protocol-pack-identity"],
            (
                "Missing protocol-identity guard file(s): "
                f"{joined}. Restore/add these files, then rerun sweep."
            ),
        )

    if violations:
        sample = ", ".join(violations[:8])
        suffix = "" if len(violations) <= 8 else f" (+{len(violations) - 8} more)"
        return InvariantResult(
            "CS-PROTOCOL-IDENTITY-001",
            "FAIL",
            [
                f"{CONSISTENCY_SPEC_DOC}#cs-protocol-identity-001--protocol-identity-language-excludes-source-from-identity-tuple",
                "CANONICALS.md#protocol-pack-identity",
            ],
            (
                "Protocol identity wording must treat source as operational context only. "
                "Remove source-based identity semantics from: "
                f"{sample}{suffix}."
            ),
            {"violations": violations},
        )

    return InvariantResult(
        "CS-PROTOCOL-IDENTITY-001",
        "PASS",
        [
            f"{CONSISTENCY_SPEC_DOC}#cs-protocol-identity-001--protocol-identity-language-excludes-source-from-identity-tuple",
            "CANONICALS.md#protocol-pack-identity",
        ],
        "",
    )


def check_cs_fixture_zero_001(root: Path) -> InvariantResult:
    """CS-FIXTURE-ZERO-001 — governed public fixture surface stays absent."""

    reintroduced = [
        rel
        for rel in _FIXTURE_ZERO_GOVERNED_PUBLIC_PATHS
        if (root / Path(*rel.split("/"))).exists()
    ]
    evidence = [f"{CONSISTENCY_SPEC_DOC}#cs-fixture-zero-001--governed-public-fixture-surface-absent-in-belgi-main-repo"]
    if reintroduced:
        sample = ", ".join(reintroduced)
        return InvariantResult(
            "CS-FIXTURE-ZERO-001",
            "FAIL",
            evidence,
            f"Remove reintroduced governed public fixture surface path(s): {sample}.",
            {"reintroduced_paths": reintroduced},
        )
    return InvariantResult(
        "CS-FIXTURE-ZERO-001",
        "PASS",
        evidence,
        "",
        {"checked_paths": list(_FIXTURE_ZERO_GOVERNED_PUBLIC_PATHS)},
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


def _sweep_managed_surface_files(root: Path) -> list[str]:
    """Enumerate tracked managed surfaces that require explicit sweep listing.

    These surfaces change frequently across ops/workflow ergonomics work and
    must remain explicitly present in _canonical_inputs to avoid silent drift.
    """

    tracked = _run_git(root, ["ls-files"])
    out: set[str] = set()
    for raw in tracked.splitlines():
        rel = raw.strip()
        if not rel:
            continue
        rel = _validate_repo_rel(rel)
        if "/" not in rel and rel.endswith(".md"):
            out.add(rel)
            continue
        if rel.startswith("docs/operations/") and rel.endswith(".md"):
            out.add(rel)
            continue
        if rel.startswith("belgi/canonicals/") and rel.endswith(".md"):
            out.add(rel)
            continue
        if rel in {
            "belgi/anchor/v1/TrustAnchor.json",
            "belgi/genesis/GenesisSealPayload.json",
            "belgi/genesis/README.md",
            "belgi/trust_anchor.py",
            "tools/report.py",
        }:
            out.add(rel)
            continue
        if rel.startswith(".github/workflows/") and rel.endswith((".yml", ".yaml")):
            out.add(rel)
            continue
        if rel.startswith(".github/scripts/") and rel.endswith(".py"):
            out.add(rel)
            continue
        if rel.startswith("scripts/belgi_") and rel.endswith((".py", ".sh", ".ps1")):
            out.add(rel)
            continue
        if rel.startswith("templates/ci/github/") and rel.endswith((".yml", ".yaml")):
            out.add(rel)
            continue
        if rel == "tools/README.md":
            out.add(rel)
            continue
        if rel in {
            "belgi/_protocol_packs/v1/schemas/README.md",
            "belgi/cli_app/parser/run.py",
            "belgi/cli_app/commands/run.py",
            "chain/compiler_c1_intent.py",
            "chain/logic/locked_object_schema.py",
            "chain/logic/q_checks/q_intent_003.py",
            "chain/logic/toolchain_set.py",
            "chain/logic/tolerances.py",
            "chain/logic/q_checks/q4_constraints_present.py",
            "chain/logic/q_checks/q5_environment_envelope.py",
            "chain/logic/r_checks/r2_scope_budgets.py",
        }:
            out.add(rel)
    return sorted(out)


def check_cs_sweep_002(root: Path) -> InvariantResult:
    """CS-SWEEP-002 — Managed surfaces are explicitly listed in sweep inputs."""

    try:
        canon = set(_canonical_inputs(root))
        required = _sweep_managed_surface_files(root)
    except Exception as e:
        return InvariantResult(
            "CS-SWEEP-002",
            "FAIL",
            [f"{CONSISTENCY_SPEC_DOC}#cs-sweep-002--managed-surface-coverage"],
            f"Failed to enumerate managed sweep surfaces ({e}).",
        )

    missing = sorted([rel for rel in required if rel not in canon])
    if missing:
        sample = ", ".join(missing[:8])
        suffix = "" if len(missing) <= 8 else f" (+{len(missing) - 8} more)"
        return InvariantResult(
            "CS-SWEEP-002",
            "FAIL",
            [f"{CONSISTENCY_SPEC_DOC}#cs-sweep-002--managed-surface-coverage", "tools/sweep.py"],
            (
                "Add missing managed surface path(s) to _canonical_inputs and synchronize "
                "docs/operations/consistency-sweep.md Inputs list. Missing: "
                f"{sample}{suffix}."
            ),
        )

    return InvariantResult(
        "CS-SWEEP-002",
        "PASS",
        [f"{CONSISTENCY_SPEC_DOC}#cs-sweep-002--managed-surface-coverage", "tools/sweep.py"],
        "",
    )


def _remediation_for_message(msg: str) -> str:
    """Map failure message to human-readable remediation hint."""
    m = (msg or "").lower()
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

    _atomic_write_text(path, "\n".join(lines) + "\n")


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
    args = ap.parse_args(argv)

    # Deterministic contract: the consistency sweep artifact location is fixed and
    # is consumed as evidence by downstream verification. Fail closed if asked to
    # emit the canonical artifact elsewhere.
    if args.out.replace("\\\\", "/") != CANONICAL_SWEEP_OUT:
        print(
            f"NO-GO: --out must be '{CANONICAL_SWEEP_OUT}' (required by the evidence contract).",
            file=sys.stderr,
        )
        raise SystemExit(2)

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
        "CS-CAN-005": check_cs_can_005,
        "CS-TERM-001": check_cs_term_001,
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
        "CS-IS-005": check_cs_is_005,
        # Shipped run object inputs
        "CS-RUN-001": check_cs_run_001,
        "CS-RUN-002": check_cs_run_002,
        # Schema catalog truth
        "CS-SCHEMA-001": check_cs_schema_001,
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
        "CS-FIXTURE-ZERO-001": check_cs_fixture_zero_001,
        "CS-PROTOCOL-IDENTITY-001": check_cs_protocol_identity_001,
        "CS-SWEEP-001": check_cs_sweep_001,
        "CS-SWEEP-002": check_cs_sweep_002,
        "CS-GV-001": check_cs_gv_001,
        "CS-LS-001": check_cs_ls_001,
        "CS-LS-002": check_cs_ls_002,
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

    results: List[InvariantResult] = []
    for inv_id in spec_ids:
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
        results.append(res)

    finished = utc_now_rfc3339()
    out_path = _resolve_repo_path(root, args.out, must_exist=False)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    canon_inputs = _canonical_inputs(root)
    extra_inputs = [_validate_repo_rel(p) for p in (args.inputs or [])]
    all_inputs = sorted(set(canon_inputs + extra_inputs))

    # Exclude the sweep output and summary from the inputs list.
    excluded = {"policy/consistency_sweep.json", "policy/consistency_sweep.summary.md"}
    filtered = [p for p in all_inputs if _validate_repo_rel(p) not in excluded]
    inputs = build_inputs(root, filtered)

    report_base = {
        "artifact_id": "policy.consistency_sweep",
        "generated_at": finished,
        "sweep_started_at": started,
        "sweep_finished_at": finished,
        "tool": {"name": args.tool_name, "version": args.tool_version},
        "repo_revision": _git_tree_sha_excluding(root, [CANONICAL_SWEEP_OUT, CANONICAL_SWEEP_SUMMARY]),
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

    report_obj, _, report_hash, passed, failed, results = _render_report(results)
    _write_json(out_path, report_obj, canonical=True)

    # Write human-readable summary markdown for CI step summary
    summary_md_path = out_path.with_suffix(".summary.md")
    _write_consistency_summary_md(summary_md_path, len(results), passed, failed, results)

    print(f"Wrote: {args.out}")
    print(f"SHA-256 (report): {report_hash}")
    print(f"Summary: total={len(results)} passed={passed} failed={failed}")

    if failed > 0:
        primary = next((r for r in results if r.status == "FAIL"), None)
        if primary is not None:
            primary_msg = str(primary.remediation or "").replace("\n", " ").strip()
            print(f"PRIMARY_CAUSE: {primary.invariant_id}: {primary_msg}", file=sys.stderr)

    return 1 if failed > 0 else 0

def _write_json(path: Path, obj: object, *, canonical: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if canonical:
        _atomic_write_canonical_json(path, obj)
    else:
        _atomic_write_json(path, obj)


def _parse_args(argv: Sequence[str] | None) -> tuple[argparse.Namespace, list[str]]:
    ap = argparse.ArgumentParser(description="Unified sweeper entrypoint")
    ap.add_argument(
        "cmd",
        choices=["consistency"],
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

        raise _UserInputError(f"Unknown command: {ns.cmd}")
    except _UserInputError as e:
        print(f"NO-GO: {e}")
        return 2
    except json.JSONDecodeError as e:
        print(f"NO-GO: JSON parse error: {e}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
