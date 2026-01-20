from __future__ import annotations

import ast
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from belgi.core.jail import ensure_within_root, safe_relpath
from belgi.core.json_canon import canonical_json_bytes
from belgi.core.time import utc_timestamp_iso_z


@dataclass(frozen=True)
class Finding:
    path: str
    lineno: int
    rule_id: str
    snippet: str


_RULE_ID_PARSE = "ADV-PARSE-001"
_RULE_ID_EVAL = "ADV-EVAL-001"
_RULE_ID_EXEC = "ADV-EXEC-001"
_RULE_ID_OSSYS = "ADV-OSSYS-001"
_RULE_ID_YAMLLOAD = "ADV-YAMLLOAD-001"
_RULE_ID_PICKLE_LOAD = "ADV-PICKLE-001"
_RULE_ID_PICKLE_LOADS = "ADV-PICKLE-002"
_RULE_ID_SHELL_TRUE = "ADV-SHELL-001"


def _snippet_at_line(txt: str, lineno: int) -> str:
    try:
        line = txt.splitlines()[lineno - 1]
    except Exception:
        return ""
    s = line.strip()
    return s[:160] if len(s) > 160 else s


def _scan_python_source(txt: str) -> list[tuple[int, str]]:
    """Return list of (lineno, rule_id) findings from Python source.

    AST-based to avoid false positives from string literals / identifiers.
    """

    findings: list[tuple[int, str]] = []
    try:
        tree = ast.parse(txt)
    except SyntaxError as e:
        findings.append((int(getattr(e, "lineno", 1) or 1), _RULE_ID_PARSE))
        return findings

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id == "eval":
                findings.append((int(node.lineno), _RULE_ID_EVAL))
            elif isinstance(func, ast.Name) and func.id == "exec":
                findings.append((int(node.lineno), _RULE_ID_EXEC))
            elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                if func.value.id == "os" and func.attr == "system":
                    findings.append((int(node.lineno), _RULE_ID_OSSYS))
                elif func.value.id == "yaml" and func.attr == "load":
                    findings.append((int(node.lineno), _RULE_ID_YAMLLOAD))
                elif func.value.id == "pickle" and func.attr == "load":
                    findings.append((int(node.lineno), _RULE_ID_PICKLE_LOAD))
                elif func.value.id == "pickle" and func.attr == "loads":
                    findings.append((int(node.lineno), _RULE_ID_PICKLE_LOADS))

            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    findings.append((int(node.lineno), _RULE_ID_SHELL_TRUE))

    findings.sort(key=lambda t: (t[0], t[1]))
    return findings


def run_adversarial_scan(
    *,
    repo: Path,
    out_path: Path,
    deterministic: bool,
    run_id: str = "unknown",
) -> int:
    repo = repo.resolve()
    ensure_within_root(repo, repo)

    if not isinstance(run_id, str) or not run_id.strip():
        raise ValueError("run_id must be a non-empty string")

    findings: list[Finding] = []

    skip_dirs = {
        ".git",
        "__pycache__",
        ".venv",
        "venv",
        ".venv_packtest",
        "site-packages",
        "build",
        "dist",
        "belgi.egg-info",
    }

    for p in repo.rglob("*.py"):
        if any(part in skip_dirs for part in p.parts):
            continue
        try:
            txt = p.read_text(encoding="utf-8", errors="strict")
        except Exception as e:
            rel = safe_relpath(repo, p)
            findings.append(Finding(path=rel, lineno=1, rule_id=_RULE_ID_PARSE, snippet=str(e)[:160]))
            continue

        rel = safe_relpath(repo, p)

        for lineno, rule_id in _scan_python_source(txt):
            findings.append(
                Finding(
                    path=rel,
                    lineno=lineno,
                    rule_id=rule_id,
                    snippet=_snippet_at_line(txt, lineno) if rule_id != _RULE_ID_PARSE else "syntax error",
                )
            )

    findings.sort(key=lambda f: (f.path, f.lineno, f.rule_id, f.snippet))

    passed = len(findings) == 0
    checks: list[dict[str, Any]] = [
        {
            "check_id": "policy.adversarial_scan.no_forbidden_primitives",
            "passed": passed,
            "message": "No forbidden primitives detected." if passed else f"Findings detected: {len(findings)}.",
        }
    ]

    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "run_id": run_id.strip(),
        "generated_at": utc_timestamp_iso_z(deterministic=deterministic),
        "report_type": "adversarial_scan",
        "summary": {
            "total_checks": len(checks),
            "passed": 1 if passed else 0,
            "failed": 0 if passed else 1,
        },
        "checks": checks,
        # Extension fields (allowed by PolicyReportPayload.additionalProperties).
        "finding_count": len(findings),
        "findings": [
            {"path": f.path, "lineno": f.lineno, "rule_id": f.rule_id, "snippet": f.snippet}
            for f in findings
        ],
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(canonical_json_bytes(payload))

    return 0 if passed else 2
