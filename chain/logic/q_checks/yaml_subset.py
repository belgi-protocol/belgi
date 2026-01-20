from __future__ import annotations

import re
from typing import Any


class YamlParseError(Exception):
    pass


def _strip_yaml_comment(s: str) -> str:
    # Minimal: strip trailing comments introduced by ' #' (space-hash).
    if "#" not in s:
        return s
    out = []
    i = 0
    in_single = False
    in_double = False
    while i < len(s):
        ch = s[i]
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        if ch == "#" and not in_single and not in_double:
            # Only treat as comment if start-of-string or preceded by whitespace.
            if i == 0 or s[i - 1].isspace():
                break
        out.append(ch)
        i += 1
    return "".join(out)


def _parse_yaml_scalar(raw: str) -> Any:
    v = _strip_yaml_comment(raw).strip()
    if v == "":
        raise YamlParseError("empty scalar")
    if v == "[]":
        return []
    if v == "true":
        return True
    if v == "false":
        return False

    # Reject flow style (must not be treated as plain scalar strings).
    if (v.startswith("{") and v.endswith("}")) or (v.startswith("[") and v.endswith("]")):
        raise YamlParseError("flow style is not supported")
    if v in ("|", ">") or v.startswith("|") or v.startswith(">"):
        raise YamlParseError("block scalars are not supported")

    # quoted strings
    if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
        quote = v[0]
        inner = v[1:-1]
        if quote == '"':
            inner = inner.replace('\\"', '"').replace('\\n', '\n').replace('\\t', '\t').replace('\\\\', '\\')
        else:
            inner = inner.replace("''", "'")
        return inner

    # integers (decimal)
    if re.fullmatch(r"-?(0|[1-9][0-9]*)", v):
        try:
            return int(v)
        except Exception:
            pass

    return v


def _count_indent(line: str) -> int:
    if "\t" in line:
        raise YamlParseError("tabs are not permitted")
    return len(line) - len(line.lstrip(" "))


def parse_yaml_subset(yaml_text: str) -> Any:
    """Parse a strict deterministic subset of YAML.

    Supported:
      - mappings (key: value | key: <newline-indented block>)
      - lists (- value | - <newline-indented block>)
      - scalars: strings, ints, booleans, []

    Rejections:
      - duplicate mapping keys
      - tabs
      - flow style (e.g. {a:1} or [x,y])
      - block scalars (|, >)
    """

    lines = yaml_text.splitlines()

    # Strip blank lines.
    raw_lines = [(i, ln.rstrip("\r\n")) for i, ln in enumerate(lines)]

    def parse_block(start: int, indent: int) -> tuple[Any, int]:
        i = start
        # Skip blank lines
        while i < len(raw_lines) and raw_lines[i][1].strip() == "":
            i += 1
        if i >= len(raw_lines):
            return {}, i

        ln = raw_lines[i][1]
        cur_indent = _count_indent(ln)
        if cur_indent < indent:
            return {}, i

        # Determine list vs mapping
        if ln.lstrip(" ").startswith("-"):
            items: list[Any] = []
            while i < len(raw_lines):
                ln = raw_lines[i][1]
                if ln.strip() == "":
                    i += 1
                    continue
                cur_indent = _count_indent(ln)
                if cur_indent < indent:
                    break
                if cur_indent != indent:
                    raise YamlParseError("inconsistent indentation")
                stripped = ln.lstrip(" ")
                if not stripped.startswith("-"):
                    break
                rest = stripped[1:].lstrip(" ")
                if rest == "":
                    # nested block
                    nested, i2 = parse_block(i + 1, indent + 2)
                    items.append(nested)
                    i = i2
                    continue
                items.append(_parse_yaml_scalar(rest))
                i += 1
            return items, i

        # mapping
        obj: dict[str, Any] = {}
        while i < len(raw_lines):
            ln = raw_lines[i][1]
            if ln.strip() == "":
                i += 1
                continue
            cur_indent = _count_indent(ln)
            if cur_indent < indent:
                break
            if cur_indent != indent:
                raise YamlParseError("inconsistent indentation")
            stripped = ln.lstrip(" ")
            if stripped.startswith("-"):
                break
            if ":" not in stripped:
                raise YamlParseError("expected ':' in mapping")
            key, rest = stripped.split(":", 1)
            key = key.strip()
            if not key:
                raise YamlParseError("empty mapping key")
            if key in obj:
                raise YamlParseError(f"duplicate key: {key}")
            rest = rest.strip()
            if rest == "":
                nested, i2 = parse_block(i + 1, indent + 2)
                obj[key] = nested
                i = i2
                continue
            obj[key] = _parse_yaml_scalar(rest)
            i += 1
        return obj, i

    parsed, end = parse_block(0, 0)

    # Ensure full consumption (ignore trailing blank lines only).
    i = end
    while i < len(raw_lines) and raw_lines[i][1].strip() == "":
        i += 1
    if i < len(raw_lines):
        raise YamlParseError("trailing unparsed content")

    return parsed


def extract_single_fenced_yaml(text: str) -> tuple[int, str | None]:
    """Return (count, yaml_text) for fenced blocks delimited by exact lines ```yaml and ```.

    This is a strict single-pass extractor:
    - Only a closing fence line (exactly ```) closes a YAML block when currently inside it.
    - Other closing fences outside a YAML block do not participate in counting/pairing.
    """

    lines = text.splitlines()
    blocks: list[tuple[int, int]] = []
    in_yaml = False
    start = -1

    for i, line in enumerate(lines):
        s = line.strip()
        if not in_yaml:
            if s == "```yaml":
                in_yaml = True
                start = i
            continue

        # in_yaml
        if s == "```":
            blocks.append((start, i))
            in_yaml = False
            start = -1

    if len(blocks) != 1:
        return len(blocks), None

    s, e = blocks[0]
    yaml_text = "\n".join(lines[s + 1 : e])
    return 1, yaml_text
