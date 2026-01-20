from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import re
from datetime import datetime


@dataclass(frozen=True)
class SchemaError:
    path: str
    message: str


_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T"
    r"\d{2}:\d{2}:\d{2}"
    r"(?:\.\d{1,9})?"
    r"(?:Z|[+\-]\d{2}:\d{2})$"
)

def parse_rfc3339(dt: str) -> None:
    if not isinstance(dt, str) or not dt:
        raise ValueError("date-time missing/empty")
    if _RFC3339_RE.match(dt) is None:
        raise ValueError("invalid RFC3339 format")
    if dt.endswith("Z"):
        dt = dt[:-1] + "+00:00"
    parsed = datetime.fromisoformat(dt)
    if parsed.tzinfo is None:
        raise ValueError("missing timezone offset")



def validate_schema(obj: Any, schema: dict[str, Any], *, root_schema: dict[str, Any], path: str) -> list[SchemaError]:
    """Deterministic, stdlib-only validator sufficient for BELGI core schemas.

    Supported keywords (as used by this repo's schemas):
      - $ref (internal only)
      - type
      - required
      - properties
      - additionalProperties=false
      - minLength
      - minimum
      - pattern
      - enum
      - const
      - minItems/maxItems
      - items
      - allOf
      - if/then
      - oneOf (minimal)
      - format: date-time

    Returns a stable list of SchemaError objects.
    """

    import re

    errors: list[SchemaError] = []

    def err(p: str, msg: str) -> None:
        errors.append(SchemaError(path=p, message=msg))

    def json_type_name(v: Any) -> str:
        if v is None:
            return "null"
        if isinstance(v, bool):
            return "boolean"
        if isinstance(v, int) and not isinstance(v, bool):
            return "integer"
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return "number"
        if isinstance(v, str):
            return "string"
        if isinstance(v, list):
            return "array"
        if isinstance(v, dict):
            return "object"
        return type(v).__name__

    def resolve_json_pointer(root: Any, ptr: str) -> Any:
        # Supports only internal refs: '#/...'.
        if ptr == "#":
            return root
        if not ptr.startswith("#/"):
            raise ValueError(f"Unsupported $ref (only internal refs supported): {ptr}")
        parts = ptr[2:].split("/")
        cur: Any = root
        for raw in parts:
            part = raw.replace("~1", "/").replace("~0", "~")
            if isinstance(cur, dict):
                if part not in cur:
                    raise KeyError(f"Missing ref path segment: {part}")
                cur = cur[part]
            elif isinstance(cur, list):
                idx = int(part)
                cur = cur[idx]
            else:
                raise TypeError("Cannot traverse non-container")
        return cur

    def walk(cur_obj: Any, sch: Any, cur_path: str) -> None:
        if not isinstance(sch, dict):
            err(cur_path, "schema node is not an object")
            return

        if "$ref" in sch:
            ref = sch.get("$ref")
            if not isinstance(ref, str):
                err(cur_path, "$ref must be string")
                return
            try:
                target = resolve_json_pointer(root_schema, ref)
            except Exception as e:
                err(cur_path, f"unresolvable $ref: {e}")
                return
            walk(cur_obj, target, cur_path)
            return

        # Composition
        all_of = sch.get("allOf")
        if isinstance(all_of, list):
            for i, sub in enumerate(all_of):
                walk(cur_obj, sub, f"{cur_path}(allOf[{i}])")

        if_s = sch.get("if")
        then_s = sch.get("then")
        if isinstance(if_s, dict) and isinstance(then_s, dict):
            # Condition is satisfied if it yields no errors.
            cond_errors: list[SchemaError] = []

            before = len(errors)
            walk(cur_obj, if_s, cur_path)
            after = len(errors)
            if after > before:
                cond_errors.extend(errors[before:after])
                del errors[before:after]

            if len(cond_errors) == 0:
                walk(cur_obj, then_s, f"{cur_path}(then)")

        one_of = sch.get("oneOf")
        if isinstance(one_of, list):
            match_count = 0
            for sub in one_of:
                trial_errors: list[SchemaError] = []

                before = len(errors)
                walk(cur_obj, sub, cur_path)
                after = len(errors)
                if after > before:
                    trial_errors.extend(errors[before:after])
                    del errors[before:after]
                if len(trial_errors) == 0:
                    match_count += 1
            if match_count != 1:
                err(cur_path, f"oneOf match_count={match_count} (expected exactly 1)")

        # Type
        expected_type = sch.get("type")
        if expected_type is not None:
            if isinstance(expected_type, list):
                allowed = [str(x) for x in expected_type]
                if json_type_name(cur_obj) not in allowed:
                    err(cur_path, f"expected type in {allowed}, got {json_type_name(cur_obj)}")
                    return
            elif isinstance(expected_type, str):
                if json_type_name(cur_obj) != expected_type:
                    err(cur_path, f"expected type {expected_type}, got {json_type_name(cur_obj)}")
                    return

        # enum / const
        if "const" in sch:
            if cur_obj != sch.get("const"):
                err(cur_path, "const mismatch")
                return

        if "enum" in sch:
            enum_vals = sch.get("enum")
            if isinstance(enum_vals, list):
                if cur_obj not in enum_vals:
                    err(cur_path, "enum mismatch")
                    return

        # Scalars
        if isinstance(cur_obj, str):
            min_len = sch.get("minLength")
            if min_len is not None and len(cur_obj) < int(min_len):
                err(cur_path, f"minLength {min_len}")

            patt = sch.get("pattern")
            if isinstance(patt, str):
                if re.match(patt, cur_obj) is None:
                    err(cur_path, "pattern mismatch")

            fmt = sch.get("format")
            if fmt == "date-time":
                try:
                    parse_rfc3339(cur_obj)
                except Exception:
                    err(cur_path, "invalid date-time")

        if isinstance(cur_obj, (int, float)) and not isinstance(cur_obj, bool):
            minimum = sch.get("minimum")
            if minimum is not None and float(cur_obj) < float(minimum):
                err(cur_path, f"minimum {minimum}")

        # Objects
        if isinstance(cur_obj, dict):
            required = sch.get("required")
            if isinstance(required, list):
                for k in required:
                    if k not in cur_obj:
                        err(cur_path, f"missing required '{k}'")

            props = sch.get("properties")
            if isinstance(props, dict):
                # Deterministic iteration
                for k in sorted(props.keys()):
                    if k in cur_obj:
                        walk(cur_obj[k], props[k], f"{cur_path}.{k}")

                addl = sch.get("additionalProperties")
                if addl is False:
                    allowed_keys = set(props.keys())
                    extra = sorted([k for k in cur_obj.keys() if k not in allowed_keys])
                    for k in extra:
                        err(f"{cur_path}.{k}", "additionalProperties not allowed")

        # Arrays
        if isinstance(cur_obj, list):
            min_items = sch.get("minItems")
            if min_items is not None and len(cur_obj) < int(min_items):
                err(cur_path, f"minItems {min_items}")

            max_items = sch.get("maxItems")
            if max_items is not None and len(cur_obj) > int(max_items):
                err(cur_path, f"maxItems {max_items}")

            item_schema = sch.get("items")
            if isinstance(item_schema, dict):
                for i, item in enumerate(cur_obj):
                    walk(item, item_schema, f"{cur_path}[{i}]")

    walk(obj, schema, path)
    errors.sort(key=lambda e: (e.path, e.message))
    return errors
