from __future__ import annotations


def extract_changed_paths_from_diff_bytes(diff_bytes: bytes) -> list[str]:
    """Extract repo-relative paths from a git-style unified diff.

    Deterministic, best-effort parser that supports synthetic fixtures.

    Strategy:
    - Prefer 'diff --git a/<p> b/<p>' headers.
    - Fall back to '+++ b/<p>' / '--- a/<p>' headers.
    - Normalize by stripping leading 'a/' or 'b/' and ignoring /dev/null.
    """

    try:
        text = diff_bytes.decode("utf-8", errors="replace")
    except Exception:
        return []

    paths: list[str] = []
    for line in text.splitlines():
        if line.startswith("diff --git "):
            parts = line.split(" ")
            if len(parts) >= 4:
                a_path = parts[2]
                b_path = parts[3]
                for candidate in (b_path, a_path):
                    if candidate in ("a/dev/null", "b/dev/null"):
                        continue
                    if candidate.startswith("a/") or candidate.startswith("b/"):
                        candidate = candidate[2:]
                    if candidate and candidate not in paths:
                        paths.append(candidate)

        elif line.startswith("+++ ") or line.startswith("--- "):
            parts = line.split(" ", 1)
            if len(parts) != 2:
                continue
            candidate = parts[1].strip()
            if candidate in ("a/dev/null", "b/dev/null", "/dev/null"):
                continue
            if candidate.startswith("a/") or candidate.startswith("b/"):
                candidate = candidate[2:]
            if candidate and candidate not in paths:
                paths.append(candidate)

    return paths
