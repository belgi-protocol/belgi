from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from belgi.core.intent_yaml import parse_yaml_subset


def test_parse_yaml_subset_allows_comment_lines_in_mapping_block() -> None:
    yaml_text = """
intent_id: "INTENT-0001"
scope:
  # comment line inside nested mapping
  allowed_dirs:
    - "src/"
""".strip()

    parsed = parse_yaml_subset(yaml_text)
    assert isinstance(parsed, dict)
    assert parsed["intent_id"] == "INTENT-0001"
    assert parsed["scope"]["allowed_dirs"] == ["src/"]


def test_parse_yaml_subset_allows_comment_lines_between_list_items() -> None:
    yaml_text = """
acceptance:
  success_criteria:
    - "first"
    # comment between list items
    - "second"
""".strip()

    parsed = parse_yaml_subset(yaml_text)
    assert isinstance(parsed, dict)
    assert parsed["acceptance"]["success_criteria"] == ["first", "second"]
