from __future__ import annotations

import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
for _k in list(sys.modules.keys()):
    if _k == "belgi" or _k.startswith("belgi."):
        del sys.modules[_k]

from belgi.core.schema import validate_schema


def test_tier_packs_schema_ref_target_exists() -> None:
    tier_packs_path = REPO_ROOT / "tiers" / "tier-packs.json"
    obj = json.loads(tier_packs_path.read_text(encoding="utf-8", errors="strict"))

    schema_rel = obj.get("$schema")
    assert isinstance(schema_rel, str) and schema_rel, "tier-packs.json must declare non-empty $schema"

    schema_path = (tier_packs_path.parent / schema_rel).resolve()
    assert schema_path.is_file(), f"declared schema target does not exist: {schema_path}"
    assert schema_path == (REPO_ROOT / "schemas" / "TierPacks.schema.json").resolve()


def test_tier_packs_json_validates_against_schema() -> None:
    schema = json.loads((REPO_ROOT / "schemas" / "TierPacks.schema.json").read_text(encoding="utf-8", errors="strict"))
    obj = json.loads((REPO_ROOT / "tiers" / "tier-packs.json").read_text(encoding="utf-8", errors="strict"))
    errs = validate_schema(obj, schema, root_schema=schema, path="TierPacks")
    assert errs == [], [f"{e.path}: {e.message}" for e in errs[:10]]
