from __future__ import annotations


def markdown_heading_section(md: str, heading: str) -> str:
    lines = md.splitlines()
    wanted = str(heading or "").strip()
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped != wanted:
            continue
        lstripped = line.lstrip()
        level = len(lstripped) - len(lstripped.lstrip("#"))
        if level <= 0:
            raise AssertionError(f"section heading is not markdown heading: {heading!r}")

        end = len(lines)
        for probe in range(index + 1, len(lines)):
            probe_line = lines[probe]
            probe_lstripped = probe_line.lstrip()
            probe_level = len(probe_lstripped) - len(probe_lstripped.lstrip("#"))
            if probe_level <= 0:
                continue
            if not probe_lstripped.startswith("#" * probe_level + " "):
                continue
            if probe_level <= level:
                end = probe
                break
        return "\n".join(lines[index:end])
    raise AssertionError(f"missing markdown heading: {heading!r}")


def markdown_marker_slice(md: str, *, start_marker: str, end_marker: str | None = None) -> str:
    start = md.find(start_marker)
    if start < 0:
        raise AssertionError(f"missing start marker: {start_marker!r}")
    end = len(md)
    if end_marker is not None:
        next_start = md.find(end_marker, start + len(start_marker))
        if next_start < 0:
            raise AssertionError(f"missing end marker: {end_marker!r}")
        end = next_start
    return md[start:end]
