from __future__ import annotations

from tools.consistency import common as _common
from tools.consistency.model import InvariantResult


def check_cs_schema_001(root: _common.Path) -> InvariantResult:
    """CS-SCHEMA-001 — Schema catalog claims for ToolchainSet/Tolerances match runtime loaders."""

    root_readme_path = _common.repo_path(root, "schemas/README.md")
    pack_readme_path = _common.repo_path(root, "belgi/_protocol_packs/v1/schemas/README.md")
    required_files = [
        "schemas/README.md",
        "belgi/_protocol_packs/v1/schemas/README.md",
        "chain/logic/locked_object_schema.py",
        "chain/logic/toolchain_set.py",
        "chain/logic/tolerances.py",
    ]
    violations: list[str] = []
    for rel in required_files:
        if not _common.repo_path(root, rel).exists():
            violations.append(f"{rel} missing")
    if not violations:
        if root_readme_path.read_bytes() != pack_readme_path.read_bytes():
            violations.append("schema README mirror drift: root vs protocol-pack")

        required_claims = [
            "Gate Q / Gate R locked-object loaders validate ToolchainSet and Tolerances against these published schemas after ObjectRef hash binding.",
            "schema and runtime both reject legacy `IntentSpec.scope.max_*` fields.",
        ]
        for rel in ("schemas/README.md", "belgi/_protocol_packs/v1/schemas/README.md"):
            text = _common.read_text(_common.repo_path(root, rel))
            for needle in required_claims:
                if needle not in text:
                    violations.append(f"{rel} missing {needle!r}")

        loader_targets = {
            "chain/logic/locked_object_schema.py": ["validate_schema(", "resolve_storage_ref"],
            "chain/logic/toolchain_set.py": ["schemas/ToolchainSet.schema.json", "load_locked_schema_object"],
            "chain/logic/tolerances.py": ["schemas/Tolerances.schema.json", "load_locked_schema_object"],
        }
        for rel, needles in loader_targets.items():
            text = _common.read_text(_common.repo_path(root, rel))
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
