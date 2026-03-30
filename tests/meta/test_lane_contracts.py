from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.repo_local

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_ROOT = REPO_ROOT / "tests"
RUN_CLI_ROOT = TESTS_ROOT / "run_cli"
LANE_DIRS = (
    "meta",
    "docs_authority",
    "run_cli",
    "run_orchestrator",
    "gates",
    "schemas",
    "shipped_surface",
    "tools",
    "serial",
)
NON_LANE_DIRS = {"helpers", "__pycache__"}
FORBIDDEN_RUN_CLI_HELPERS = {"tests.helpers.run_cli_harness"}
FORBIDDEN_RUN_CLI_HANDLES = {"belgi_cli", "belgi_main", "run_orchestrator"}
META_ALLOWED_TEST_PREFIXES = ("tests.helpers", "tests.meta")
META_ALLOWED_PRODUCT_IMPORTS = {
    "tests/meta/test_builders.py": {
        "belgi.core.schema.validate_schema",
        "chain.logic.tier_packs.TierParams",
        "chain.logic.tier_packs.load_tier_params",
    },
    "tests/meta/test_import_graph_sanity.py": {
        "belgi.core.jail",
        "belgi.protocol.pack",
        "chain.logic.base",
    },
    "tests/meta/test_sweep_semantics.py": {
        "belgi.cli_app.commands.run",
        "tools.sweep",
    },
}
PRODUCT_NAMESPACE_PREFIXES = ("belgi.", "chain.", "tools.", "wrapper.")
DRIFT_OWNER_IMPORTS = {
    "tools.check_drift",
    "tools.build_builtin_pack",
    "belgi.protocol.pack.build_manifest_bytes",
    "belgi.protocol.pack.validate_manifest_bytes",
    "belgi.protocol.pack.MANIFEST_FILENAME",
}
NON_TOOLS_DRIFT_OWNER_IMPORT_EXCEPTIONS = {
    "tests/shipped_surface/test_builtin_protocol_pack_contracts.py": {
        "belgi.protocol.pack.MANIFEST_FILENAME",
    },
    "tests/shipped_surface/test_packaging_smoke_contracts.py": {
        "belgi.protocol.pack.MANIFEST_FILENAME",
        "belgi.protocol.pack.validate_manifest_bytes",
    },
    "tests/shipped_surface/test_protocol_pack_lifecycle_contracts.py": {
        "belgi.protocol.pack.MANIFEST_FILENAME",
        "belgi.protocol.pack.build_manifest_bytes",
        "belgi.protocol.pack.validate_manifest_bytes",
    },
    "tests/shipped_surface/test_protocol_pack_manifest_contracts.py": {
        "belgi.protocol.pack.build_manifest_bytes",
        "belgi.protocol.pack.validate_manifest_bytes",
    },
}
SWEEP_OWNED_PARITY_TARGET_ROOTS = (
    "belgi/canonicals/",
    "belgi/_protocol_packs/v1/",
)
REPO_TARGET_FILE_SINKS = {
    "read_text",
    "read_bytes",
    "write_text",
    "write_bytes",
    "exists",
    "is_file",
    "open",
}


def _iter_test_modules() -> list[Path]:
    return sorted(
        path
        for path in TESTS_ROOT.rglob("test_*.py")
        if "__pycache__" not in path.parts
    )


def _classify_test_module(path_or_rel: Path | str) -> str:
    rel = path_or_rel.relative_to(REPO_ROOT).as_posix() if isinstance(path_or_rel, Path) else path_or_rel
    parts = Path(rel).parts
    if len(parts) >= 3 and parts[0] == "tests" and parts[1] in LANE_DIRS:
        return parts[1]
    raise AssertionError(f"unclassified test module: {rel}")


def _iter_import_targets(tree: ast.AST) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                out.append((alias.name, getattr(node, "lineno", 0)))
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            for alias in node.names:
                out.append((f"{node.module}.{alias.name}", getattr(node, "lineno", 0)))
    return out


def _matches_prefix(target: str, prefix: str) -> bool:
    return target == prefix or target.startswith(prefix + ".")


def _imported_test_lane(target: str) -> str | None:
    parts = target.split(".")
    if len(parts) >= 2 and parts[0] == "tests" and parts[1] in LANE_DIRS:
        return parts[1]
    return None


def _is_product_namespace(target: str) -> bool:
    return target.startswith(PRODUCT_NAMESPACE_PREFIXES)


def _function_param_order(node: ast.FunctionDef) -> list[str]:
    return [arg.arg for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs]


def _literal_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _literal_string_values(
    node: ast.AST,
    literal_aliases: dict[str, set[str]] | None = None,
) -> set[str]:
    literal = _literal_string(node)
    if literal is not None:
        return {literal}
    if isinstance(node, ast.Name) and literal_aliases is not None:
        return set(literal_aliases.get(node.id, set()))
    return set()


def _literal_object(
    node: ast.AST,
    literal_objects: dict[str, object] | None = None,
) -> object | None:
    if isinstance(node, ast.Name) and literal_objects is not None and node.id in literal_objects:
        return literal_objects[node.id]
    try:
        return ast.literal_eval(node)
    except (TypeError, ValueError):
        return None


def _literal_split_parts(node: ast.AST) -> list[str] | None:
    if not isinstance(node, ast.Call):
        return None
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "split":
        return None
    if len(node.args) != 1 or node.keywords:
        return None
    value = _literal_string(node.func.value)
    sep = _literal_string(node.args[0])
    if value is None or sep != "/":
        return None
    return value.split("/")


def _path_values_from_call(
    call: ast.Call,
    literal_aliases: dict[str, set[str]] | None = None,
) -> set[str] | None:
    if isinstance(call.func, ast.Name) and call.func.id == "Path":
        pass
    elif (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "joinpath"
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "REPO_ROOT"
    ):
        pass
    else:
        return None

    if call.keywords:
        return None

    paths: set[str] = {""}
    for arg in call.args:
        if isinstance(arg, ast.Starred):
            if not isinstance(arg.value, ast.Call):
                return None
            split_call = arg.value
            if (
                not isinstance(split_call.func, ast.Attribute)
                or split_call.func.attr != "split"
                or len(split_call.args) != 1
                or split_call.keywords
                or _literal_string(split_call.args[0]) != "/"
            ):
                return None
            value_options = _literal_string_values(split_call.func.value, literal_aliases)
            if not value_options:
                return None
            next_paths: set[str] = set()
            for path in paths:
                for value in value_options:
                    next_path = path
                    for part in value.split("/"):
                        next_path = _join_repo_relative_parts(next_path, part)
                    next_paths.add(next_path)
            paths = next_paths
            continue

        literals = _literal_string_values(arg, literal_aliases)
        if not literals:
            return None
        next_paths = set()
        for path in paths:
            for literal in literals:
                next_paths.add(_join_repo_relative_parts(path, literal))
        paths = next_paths

    return paths


def _join_repo_relative_parts(left: str, right: str) -> str:
    if not left:
        return right.lstrip("/")
    if not right:
        return left.rstrip("/")
    return f"{left.rstrip('/')}/{right.lstrip('/')}"


def _repo_relative_literal_paths(
    node: ast.AST,
    literal_aliases: dict[str, set[str]] | None = None,
) -> set[str]:
    if isinstance(node, ast.Name) and node.id == "REPO_ROOT":
        return {""}

    literals = _literal_string_values(node, literal_aliases)
    if literals:
        return literals

    if isinstance(node, ast.Call):
        paths = _path_values_from_call(node, literal_aliases)
        return paths or set()

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        left = _repo_relative_literal_paths(node.left, literal_aliases)
        right = _repo_relative_literal_paths(node.right, literal_aliases)
        if not left or not right:
            return set()
        return {
            _join_repo_relative_parts(left_path, right_path)
            for left_path in left
            for right_path in right
        }

    return set()


def _repo_relative_literal_path(
    node: ast.AST,
    literal_aliases: dict[str, set[str]] | None = None,
) -> str | None:
    paths = _repo_relative_literal_paths(node, literal_aliases)
    if len(paths) != 1:
        return None
    return next(iter(paths))


def _bind_literal_target_values(
    target: ast.AST,
    value: object,
    literal_aliases: dict[str, set[str]],
) -> None:
    if isinstance(target, ast.Name):
        if isinstance(value, str):
            literal_aliases.setdefault(target.id, set()).add(value)
        elif isinstance(value, (list, tuple)) and all(isinstance(item, str) for item in value):
            literal_aliases.setdefault(target.id, set()).update(value)
        return

    if not isinstance(target, (ast.Tuple, ast.List)):
        return
    if not isinstance(value, (list, tuple)) or len(target.elts) != len(value):
        return

    for elt, child_value in zip(target.elts, value, strict=True):
        _bind_literal_target_values(elt, child_value, literal_aliases)


def _bind_literal_iterable_target_values(
    target: ast.AST,
    iterable: object,
    literal_aliases: dict[str, set[str]],
) -> None:
    if not isinstance(iterable, (list, tuple)):
        return

    if isinstance(target, ast.Name) and all(isinstance(item, str) for item in iterable):
        literal_aliases.setdefault(target.id, set()).update(iterable)
        return

    if not isinstance(target, (ast.Tuple, ast.List)):
        return

    slots: list[list[object]] = [[] for _ in target.elts]
    for item in iterable:
        if not isinstance(item, (list, tuple)) or len(item) != len(target.elts):
            return
        for index, child_value in enumerate(item):
            slots[index].append(child_value)

    for elt, slot_values in zip(target.elts, slots, strict=True):
        _bind_literal_target_values(elt, slot_values, literal_aliases)


def _infer_repo_relative_literal_aliases(statements: list[ast.stmt]) -> dict[str, set[str]]:
    literal_objects: dict[str, object] = {}
    for stmt in statements:
        for child in ast.walk(stmt):
            value: ast.AST | None = None
            if isinstance(child, ast.Assign):
                if len(child.targets) != 1 or not isinstance(child.targets[0], ast.Name):
                    continue
                value = child.value
                target_name = child.targets[0].id
            elif isinstance(child, ast.AnnAssign):
                if child.value is None or not isinstance(child.target, ast.Name):
                    continue
                value = child.value
                target_name = child.target.id
            else:
                continue

            literal = _literal_object(value, literal_objects)
            if literal is not None:
                literal_objects[target_name] = literal

    literal_aliases: dict[str, set[str]] = {}
    for stmt in statements:
        for child in ast.walk(stmt):
            if isinstance(child, ast.Assign):
                if len(child.targets) != 1:
                    continue
                literal = _literal_object(child.value, literal_objects)
                if literal is None:
                    continue
                _bind_literal_target_values(child.targets[0], literal, literal_aliases)
                continue

            if isinstance(child, ast.AnnAssign):
                if child.value is None:
                    continue
                literal = _literal_object(child.value, literal_objects)
                if literal is None:
                    continue
                _bind_literal_target_values(child.target, literal, literal_aliases)
                continue

            if isinstance(child, ast.For):
                literal = _literal_object(child.iter, literal_objects)
                if literal is None:
                    continue
                _bind_literal_iterable_target_values(child.target, literal, literal_aliases)

    return literal_aliases


def _repo_relative_param_names(
    node: ast.AST,
    param_names: set[str],
    local_aliases: dict[str, tuple[str | None, set[str]]] | None = None,
) -> set[str]:
    if isinstance(node, ast.Name) and node.id in param_names:
        return {node.id}
    if isinstance(node, ast.Name) and local_aliases is not None and node.id in local_aliases:
        return set(local_aliases[node.id][1])
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return _repo_relative_param_names(node.left, param_names, local_aliases) | _repo_relative_param_names(
            node.right,
            param_names,
            local_aliases,
        )
    if isinstance(node, ast.Call):
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "split"
            and len(node.args) == 1
            and not node.keywords
            and _literal_string(node.args[0]) == "/"
        ):
            return _repo_relative_param_names(node.func.value, param_names, local_aliases)

        if isinstance(node.func, ast.Name) and node.func.id == "Path":
            hits: set[str] = set()
            for arg in node.args:
                if isinstance(arg, ast.Starred):
                    hits |= _repo_relative_param_names(arg.value, param_names, local_aliases)
                    continue
                hits |= _repo_relative_param_names(arg, param_names, local_aliases)
            return hits

        if isinstance(node.func, ast.Attribute) and node.func.attr == "joinpath":
            hits = _repo_relative_param_names(node.func.value, param_names, local_aliases)
            for arg in node.args:
                if isinstance(arg, ast.Starred):
                    hits |= _repo_relative_param_names(arg.value, param_names, local_aliases)
                    continue
                hits |= _repo_relative_param_names(arg, param_names, local_aliases)
            return hits
    return set()


def _callable_target_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _callable_target_name(node.value)
        if base is None:
            return None
        return f"{base}.{node.attr}"
    return None


def _call_argument_by_position_or_name(
    node: ast.Call,
    position: int,
    param_name: str | None = None,
) -> ast.AST | None:
    if position < len(node.args):
        return node.args[position]
    if param_name is None:
        return None
    for keyword in node.keywords:
        if keyword.arg == param_name:
            return keyword.value
    return None


def _infer_repo_relative_local_aliases(
    func: ast.FunctionDef,
    param_names: set[str],
) -> dict[str, tuple[str | None, set[str]]]:
    aliases: dict[str, tuple[str | None, set[str]]] = {}

    for stmt in func.body:
        for child in ast.walk(stmt):
            if isinstance(child, ast.Assign):
                if len(child.targets) != 1 or not isinstance(child.targets[0], ast.Name):
                    continue
                target = child.targets[0].id
                value = child.value
            elif isinstance(child, ast.AnnAssign):
                if child.value is None or not isinstance(child.target, ast.Name):
                    continue
                target = child.target.id
                value = child.value
            else:
                continue

            rel = _repo_relative_literal_path(value)
            param_hits = _repo_relative_param_names(value, param_names, aliases)
            if rel is None and not param_hits:
                continue
            aliases[target] = (rel, param_hits)

    return aliases


def _repo_relative_target_info(
    node: ast.AST,
    param_names: set[str],
    local_aliases: dict[str, tuple[str | None, set[str]]] | None = None,
) -> tuple[str | None, set[str]]:
    if isinstance(node, ast.Name) and local_aliases is not None and node.id in local_aliases:
        rel, hits = local_aliases[node.id]
        return rel, set(hits)
    return (
        _repo_relative_literal_path(node),
        _repo_relative_param_names(node, param_names, local_aliases),
    )


def _infer_repo_target_helper_params(tree: ast.Module) -> dict[str, set[int]]:
    helper_params: dict[str, set[int]] = {}
    module_param_orders = {
        node.name: _function_param_order(node)
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
    }
    changed = True

    while changed:
        changed = False
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef):
                continue

            param_order = module_param_orders.get(node.name, _function_param_order(node))
            param_names = set(param_order)
            local_aliases = _infer_repo_relative_local_aliases(node, param_names)
            discovered: set[int] = set()

            for child in ast.walk(node):
                if not isinstance(child, ast.Call):
                    continue

                if isinstance(child.func, ast.Attribute) and child.func.attr in REPO_TARGET_FILE_SINKS:
                    rel, param_hits = _repo_relative_target_info(child.func.value, param_names, local_aliases)
                    if rel is not None or param_hits:
                        discovered.update(param_order.index(name) for name in param_hits if name in param_order)
                    continue

                if isinstance(child.func, ast.Name) and child.func.id == "open" and child.args:
                    rel, param_hits = _repo_relative_target_info(child.args[0], param_names, local_aliases)
                    if rel is not None or param_hits:
                        discovered.update(param_order.index(name) for name in param_hits if name in param_order)
                    continue

                if isinstance(child.func, ast.Name) and child.func.id in helper_params:
                    callee_params = module_param_orders.get(child.func.id, [])
                    for position in helper_params[child.func.id]:
                        param_name = callee_params[position] if position < len(callee_params) else None
                        arg = _call_argument_by_position_or_name(child, position, param_name)
                        if arg is None:
                            continue
                        _, param_hits = _repo_relative_target_info(arg, param_names, local_aliases)
                        discovered.update(param_order.index(name) for name in param_hits if name in param_order)

            if discovered and helper_params.get(node.name) != discovered:
                helper_params[node.name] = discovered
                changed = True

    return helper_params


def _tests_helper_module_path(module_name: str) -> Path | None:
    if not module_name.startswith("tests.helpers."):
        return None
    rel_parts = module_name.split(".")[2:]
    if not rel_parts:
        return None
    candidate = TESTS_ROOT / "helpers" / Path(*rel_parts)
    py_path = candidate.with_suffix(".py")
    if py_path.is_file():
        return py_path
    return None


def _infer_imported_repo_target_helper_params(tree: ast.Module) -> dict[str, dict[int, str | None]]:
    imported_params: dict[str, dict[int, str | None]] = {}

    def merge_module_alias(local_name: str, module_name: str) -> None:
        module_path = _tests_helper_module_path(module_name)
        if module_path is None:
            return
        helper_tree = ast.parse(module_path.read_text(encoding="utf-8", errors="strict"), filename=module_path.as_posix())
        helper_params = _infer_repo_target_helper_params(helper_tree)
        helper_param_orders = {
            node.name: _function_param_order(node)
            for node in helper_tree.body
            if isinstance(node, ast.FunctionDef)
        }
        for helper_name, positions in helper_params.items():
            param_order = helper_param_orders.get(helper_name, [])
            imported_params[f"{local_name}.{helper_name}"] = {
                position: param_order[position] if position < len(param_order) else None
                for position in positions
            }

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if not alias.name.startswith("tests.helpers."):
                    continue
                local_name = alias.asname or alias.name
                merge_module_alias(local_name, alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            if node.module.startswith("tests.helpers."):
                module_path = _tests_helper_module_path(node.module)
                if module_path is None:
                    continue
                helper_tree = ast.parse(module_path.read_text(encoding="utf-8", errors="strict"), filename=module_path.as_posix())
                helper_params = _infer_repo_target_helper_params(helper_tree)
                helper_param_orders = {
                    helper.name: _function_param_order(helper)
                    for helper in helper_tree.body
                    if isinstance(helper, ast.FunctionDef)
                }
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    positions = helper_params.get(alias.name)
                    if positions is None:
                        continue
                    param_order = helper_param_orders.get(alias.name, [])
                    imported_params[alias.asname or alias.name] = {
                        position: param_order[position] if position < len(param_order) else None
                        for position in positions
                    }
                continue

            if node.module == "tests.helpers":
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    merge_module_alias(alias.asname or alias.name, f"tests.helpers.{alias.name}")

    return imported_params


def _iter_repo_relative_targets(tree: ast.Module) -> list[tuple[str, int]]:
    targets: list[tuple[str, int]] = []
    helper_params = _infer_repo_target_helper_params(tree)
    module_param_orders = {
        node.name: _function_param_order(node)
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
    }
    imported_helper_params = _infer_imported_repo_target_helper_params(tree)

    def collect_scope_targets(
        scope: ast.AST,
        literal_aliases: dict[str, set[str]],
    ) -> None:
        for node in ast.walk(scope):
            if not isinstance(node, ast.Call):
                continue

            if isinstance(node.func, ast.Attribute) and node.func.attr in REPO_TARGET_FILE_SINKS:
                for rel in sorted(_repo_relative_literal_paths(node.func.value, literal_aliases)):
                    targets.append((rel, getattr(node, "lineno", 0)))
                continue

            if isinstance(node.func, ast.Name) and node.func.id == "open" and node.args:
                for rel in sorted(_repo_relative_literal_paths(node.args[0], literal_aliases)):
                    targets.append((rel, getattr(node, "lineno", 0)))
                continue

            if isinstance(node.func, ast.Name) and node.func.id in helper_params:
                callee_params = module_param_orders.get(node.func.id, [])
                for position in helper_params[node.func.id]:
                    param_name = callee_params[position] if position < len(callee_params) else None
                    arg = _call_argument_by_position_or_name(node, position, param_name)
                    if arg is None:
                        continue
                    for rel in sorted(_repo_relative_literal_paths(arg, literal_aliases)):
                        targets.append((rel, getattr(node, "lineno", 0)))
                continue

            call_target = _callable_target_name(node.func)
            if call_target is not None and call_target in imported_helper_params:
                for position, param_name in imported_helper_params[call_target].items():
                    arg = _call_argument_by_position_or_name(node, position, param_name)
                    if arg is None:
                        continue
                    for rel in sorted(_repo_relative_literal_paths(arg, literal_aliases)):
                        targets.append((rel, getattr(node, "lineno", 0)))

    module_statements = [
        stmt
        for stmt in tree.body
        if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]
    collect_scope_targets(ast.Module(body=module_statements, type_ignores=[]), _infer_repo_relative_literal_aliases(module_statements))

    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            collect_scope_targets(node, _infer_repo_relative_literal_aliases(node.body))

    return targets


def _lane_may_target_sweep_owned_parity(path: Path) -> bool:
    rel = path.relative_to(REPO_ROOT).as_posix()
    if rel == "tests/meta/test_sweep_semantics.py":
        return True
    return _classify_test_module(path) == "tools"


def test_repo_target_analyzer_tracks_literal_aliases_and_loop_unpacking() -> None:
    tree = ast.parse(
        """
def test_alias_paths() -> None:
    direct_rel = "belgi/_protocol_packs/v1/schemas/TrustAnchor.schema.json"
    (REPO_ROOT / direct_rel).read_bytes()

    pairs = [
        ("schemas/GenesisSealPayload.schema.json", "belgi/_protocol_packs/v1/schemas/GenesisSealPayload.schema.json"),
    ]

    for _, packaged_rel in pairs:
        REPO_ROOT.joinpath(*packaged_rel.split("/")).read_bytes()
"""
    )

    targets = {target for target, _ in _iter_repo_relative_targets(tree)}
    assert "belgi/_protocol_packs/v1/schemas/TrustAnchor.schema.json" in targets
    assert "belgi/_protocol_packs/v1/schemas/GenesisSealPayload.schema.json" in targets


def test_lane_topology_exists_with_single_root_owner_statement() -> None:
    assert (TESTS_ROOT / "README.md").is_file(), "missing suite owner statement: tests/README.md"
    assert (TESTS_ROOT / "serial" / "README.md").is_file(), "missing serial exception readme: tests/serial/README.md"

    child_dirs = {
        path.name
        for path in TESTS_ROOT.iterdir()
        if path.is_dir()
    }
    assert set(LANE_DIRS).issubset(child_dirs)
    assert child_dirs <= (set(LANE_DIRS) | NON_LANE_DIRS)


def test_every_test_module_lives_under_a_known_lane() -> None:
    relpaths = [path.relative_to(REPO_ROOT).as_posix() for path in _iter_test_modules()]
    assert relpaths, "expected tracked test modules"

    for relpath in relpaths:
        lane = _classify_test_module(relpath)
        assert lane in LANE_DIRS

    stray_root_modules = sorted(
        path.relative_to(REPO_ROOT).as_posix()
        for path in TESTS_ROOT.glob("test_*.py")
    )
    assert stray_root_modules == []


def test_test_modules_do_not_cross_import_other_owner_lanes() -> None:
    offenders: list[str] = []

    for path in _iter_test_modules():
        rel = path.relative_to(REPO_ROOT).as_posix()
        lane = _classify_test_module(path)
        tree = ast.parse(path.read_text(encoding="utf-8", errors="strict"), filename=rel)

        for target, lineno in _iter_import_targets(tree):
            imported_lane = _imported_test_lane(target)
            if imported_lane is None:
                continue
            if imported_lane != lane:
                offenders.append(f"{rel}:{lineno} crosses into tests/{imported_lane}/ via `{target}`")

    assert offenders == [], "\n".join(offenders)


def test_meta_lane_product_imports_stay_on_governance_and_sweep_surfaces() -> None:
    offenders: list[str] = []

    for path in sorted((TESTS_ROOT / "meta").glob("test_*.py")):
        rel = path.relative_to(REPO_ROOT).as_posix()
        allowed_imports = META_ALLOWED_PRODUCT_IMPORTS.get(rel, set())
        tree = ast.parse(path.read_text(encoding="utf-8", errors="strict"), filename=rel)

        for target, lineno in _iter_import_targets(tree):
            if target.startswith("tests."):
                if not any(_matches_prefix(target, prefix) for prefix in META_ALLOWED_TEST_PREFIXES):
                    offenders.append(f"{rel}:{lineno} imports non-governance test surface `{target}`")
                continue

            if _is_product_namespace(target) and target not in allowed_imports:
                offenders.append(f"{rel}:{lineno} imports non-meta owner surface `{target}`")

    assert offenders == [], "\n".join(offenders)


def test_pack_and_drift_owner_imports_stay_in_tools_or_exact_shipped_exceptions() -> None:
    offenders: list[str] = []

    for path in _iter_test_modules():
        rel = path.relative_to(REPO_ROOT).as_posix()
        lane = _classify_test_module(path)
        if lane == "tools":
            continue

        allowed_imports = NON_TOOLS_DRIFT_OWNER_IMPORT_EXCEPTIONS.get(rel, set())
        tree = ast.parse(path.read_text(encoding="utf-8", errors="strict"), filename=rel)
        for target, lineno in _iter_import_targets(tree):
            if target in DRIFT_OWNER_IMPORTS and target not in allowed_imports:
                offenders.append(f"{rel}:{lineno} imports tool/pack owner seam `{target}` outside tools lane")

    assert offenders == [], "\n".join(offenders)


def test_only_sweep_semantics_and_tools_lanes_may_target_sweep_owned_parity_roots() -> None:
    offenders: list[str] = []

    for path in _iter_test_modules():
        rel = path.relative_to(REPO_ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8", errors="strict"), filename=rel)
        targets = _iter_repo_relative_targets(tree)
        parity_hits = sorted(
            {
                root
                for root in SWEEP_OWNED_PARITY_TARGET_ROOTS
                if any(target == root or target.startswith(root) for target, _ in targets)
            }
        )
        if parity_hits and not _lane_may_target_sweep_owned_parity(path):
            offenders.append(
                f"{rel} targets sweep-owned parity roots {parity_hits} and re-owns sweep parity surface outside tools or tests/meta/test_sweep_semantics.py"
            )

    assert offenders == [], "\n".join(offenders)


def test_run_cli_lane_stays_subprocess_black_box() -> None:
    failures: list[str] = []

    for path in sorted(RUN_CLI_ROOT.rglob("test_*.py")):
        rel = path.relative_to(REPO_ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8", errors="strict"), filename=rel)

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in FORBIDDEN_RUN_CLI_HELPERS:
                        failures.append(f"{rel}: imports forbidden helper `{alias.name}`")
            elif isinstance(node, ast.ImportFrom):
                if node.module in FORBIDDEN_RUN_CLI_HELPERS:
                    failures.append(f"{rel}: imports forbidden helper `{node.module}`")
                if node.module == "tests.helpers":
                    for alias in node.names:
                        if alias.name == "run_cli_harness":
                            failures.append(f"{rel}: imports forbidden helper `tests.helpers.run_cli_harness`")
            elif isinstance(node, ast.FunctionDef):
                args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
                if any(arg.arg == "monkeypatch" for arg in args):
                    failures.append(f"{rel}: uses forbidden `monkeypatch` fixture in subprocess lane")
            elif isinstance(node, ast.Name) and node.id in FORBIDDEN_RUN_CLI_HANDLES:
                failures.append(f"{rel}: uses forbidden in-process runtime handle `{node.id}`")

    assert not failures, "\n".join(failures)
