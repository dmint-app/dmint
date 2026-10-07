"""Deterministic argument constraint evaluator for AI agent tool calls (Phase 6).

Constraints are evaluated by the pure policy evaluator before granting authorizations.
Any constraint violation (missing field, type mismatch, bound violation, regex mismatch)
deterministically results in Decision.DENY with code 'DMT_CONSTRAINT_VIOLATION'.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal, InvalidOperation
import functools
import math
import re
import sre_constants
import sre_parse
from typing import Any

from .errors import PolicyError

MAX_PATTERN_LENGTH = 256
MAX_STRING_INPUT_LENGTH = 4096
MAX_SAFE_INTEGER = 9007199254740991  # 2^53 - 1 per RFC 8785
MIN_SAFE_INTEGER = -9007199254740991
MAX_CONSTRAINT_DEPTH = 32
MAX_CONTAINER_SIZE = 1000

_TOP_LEVEL_KEYS = {"type", "required", "additionalProperties", "properties"}
_PROPERTY_KEYS = {
    "type",
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "minLength",
    "maxLength",
    "pattern",
    "enum",
    "minItems",
    "maxItems",
    "items",
    "required",
    "additionalProperties",
    "properties",
}
_SUPPORTED_TYPES = {"string", "number", "integer", "boolean", "array", "object"}

_NUMERIC_CONSTRAINT_KEYS = {"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"}
_STRING_CONSTRAINT_KEYS = {"minLength", "maxLength", "pattern"}
_ARRAY_CONSTRAINT_KEYS = {"minItems", "maxItems", "items"}
_OBJECT_CONSTRAINT_KEYS = {"required", "additionalProperties", "properties"}


def safe_compare(val: int | float, bound: int | float) -> int:
    """Compare two numeric values safely using Decimal without floating-point precision loss.

    Returns:
        -1 if val < bound
         0 if val == bound
         1 if val > bound
    """
    try:
        d_val = Decimal(str(val))
        d_bound = Decimal(str(bound))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise PolicyError(f"cannot compare invalid numbers: {val!r} vs {bound!r}") from exc

    if d_val < d_bound:
        return -1
    elif d_val > d_bound:
        return 1
    return 0


def _is_valid_number(val: Any) -> bool:
    """Check if value is a valid numeric type (strictly excluding bool, NaN, and Infinity)."""
    if type(val) is bool:
        return False
    if not isinstance(val, (int, float)):
        return False
    if math.isnan(val) or math.isinf(val):
        return False
    return True


def _is_valid_integer(val: Any) -> bool:
    """Check if value is a valid integer (strictly int, strictly excluding bool and float)."""
    if type(val) is bool:
        return False
    return type(val) is int


def validate_pattern_safety(pattern: str) -> None:
    """Validate regex pattern safety using sre_parse AST analysis.

    Rejects patterns that pose catastrophic backtracking (ReDoS) risk:
    - No nested repeats (repeat inside repeat)
    - No unbounded repeats inside groups
    - No alternation inside repeats
    - No excessive consecutive unbounded repeats
    - No backreferences
    - No lookarounds
    """
    try:
        parsed = sre_parse.parse(pattern)
    except Exception as exc:
        raise PolicyError(f"invalid regex pattern syntax: {exc}") from exc

    def check_seq(seq: Any, inside_repeat: bool = False, inside_group: bool = False) -> None:
        consecutive_repeats = 0
        for op, av in seq:
            if op in (sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT):
                _min_r, max_r, sub = av
                is_unbounded = max_r == sre_constants.MAXREPEAT
                if inside_repeat:
                    raise PolicyError("nested repeat is not allowed (catastrophic backtracking risk)")
                if inside_group and is_unbounded:
                    raise PolicyError("unbounded repeat inside group is not allowed (catastrophic backtracking risk)")
                consecutive_repeats += 1
                if consecutive_repeats > 2:
                    raise PolicyError("excessive consecutive repeats in sequence are not allowed (ReDoS risk)")
                check_seq(sub, inside_repeat=True, inside_group=inside_group)
            elif op == sre_constants.SUBPATTERN:
                consecutive_repeats = 0
                _group_num, _syn_flags, _val_flags, sub = av
                check_seq(sub, inside_repeat=inside_repeat, inside_group=True)
            elif op == sre_constants.BRANCH:
                consecutive_repeats = 0
                if inside_repeat:
                    raise PolicyError("alternation inside repeat is not allowed (catastrophic backtracking risk)")
                for alt in av[1]:
                    check_seq(alt, inside_repeat=inside_repeat, inside_group=inside_group)
            elif op in (sre_constants.GROUPREF, sre_constants.GROUPREF_EXISTS, sre_constants.GROUPREF_IGNORE):
                raise PolicyError("backreferences are not allowed")
            elif op in (sre_constants.ASSERT, sre_constants.ASSERT_NOT):
                raise PolicyError("lookaround assertions are not allowed")
            else:
                if op != sre_constants.AT:
                    consecutive_repeats = 0

    check_seq(parsed.data)


@functools.lru_cache(maxsize=512)
def _compile_anchored_pattern(pattern: str) -> re.Pattern[str]:
    """Compile pattern for anchored fullmatch evaluation."""
    return re.compile(pattern)


def validate_constraints_schema(schema: Any, depth: int = 0) -> None:
    """Validate constraints schema definition at policy loading time.

    Rejects unknown keys, unsupported types, invalid bounds, empty enums, and ReDoS regexes with PolicyError.
    Recursively validates nested properties and items.
    """
    if depth > MAX_CONSTRAINT_DEPTH:
        raise PolicyError("constraints schema exceeds maximum allowed nesting depth")

    if not isinstance(schema, Mapping):
        raise PolicyError("constraints must be an object mapping")

    unknown_top = set(schema) - _TOP_LEVEL_KEYS
    if unknown_top:
        raise PolicyError(f"unknown constraint field: {next(iter(unknown_top))}")

    if "type" in schema and schema["type"] != "object":
        raise PolicyError("top-level constraints type must be 'object'")

    if "required" in schema:
        req = schema["required"]
        if not isinstance(req, Sequence) or isinstance(req, (str, bytes)):
            raise PolicyError("'required' constraint must be an array of string field names")
        for item in req:
            if not isinstance(item, str) or not item.strip():
                raise PolicyError("required field names must be non-empty strings")

    if "additionalProperties" in schema and type(schema["additionalProperties"]) is not bool:
        raise PolicyError("'additionalProperties' constraint must be a boolean")

    if "properties" in schema:
        props = schema["properties"]
        if not isinstance(props, Mapping):
            raise PolicyError("'properties' constraint must be an object mapping")

        for prop_name, prop_spec in props.items():
            if not isinstance(prop_name, str) or not prop_name:
                raise PolicyError("property names in constraints must be non-empty strings")
            if not isinstance(prop_spec, Mapping):
                raise PolicyError(f"property constraint for '{prop_name}' must be an object mapping")

            unknown_prop_keys = set(prop_spec) - _PROPERTY_KEYS
            if unknown_prop_keys:
                raise PolicyError(
                    f"unknown constraint field '{next(iter(unknown_prop_keys))}' on argument '{prop_name}'"
                )

            # Validate type
            if "type" in prop_spec:
                type_name = prop_spec["type"]
                if type_name not in _SUPPORTED_TYPES:
                    raise PolicyError(f"unknown constraint type '{type_name}' on argument '{prop_name}'")

            # Validate numeric bounds
            bounds: dict[str, int | float] = {}
            for bound_key in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"):
                if bound_key in prop_spec:
                    b_val = prop_spec[bound_key]
                    if not _is_valid_number(b_val):
                        raise PolicyError(f"'{bound_key}' on argument '{prop_name}' must be a valid number")
                    bounds[bound_key] = b_val

            min_val = bounds.get("minimum", bounds.get("exclusiveMinimum"))
            max_val = bounds.get("maximum", bounds.get("exclusiveMaximum"))
            if min_val is not None and max_val is not None:
                if safe_compare(min_val, max_val) > 0:
                    raise PolicyError(
                        f"invalid constraint bounds on argument '{prop_name}': minimum cannot exceed maximum"
                    )

            # Validate string length bounds
            str_bounds: dict[str, int] = {}
            for len_key in ("minLength", "maxLength"):
                if len_key in prop_spec:
                    l_val = prop_spec[len_key]
                    if not _is_valid_integer(l_val) or l_val < 0:
                        raise PolicyError(f"'{len_key}' on argument '{prop_name}' must be a non-negative integer")
                    str_bounds[len_key] = l_val

            if "minLength" in str_bounds and "maxLength" in str_bounds:
                if str_bounds["minLength"] > str_bounds["maxLength"]:
                    raise PolicyError(
                        f"invalid constraint bounds on argument '{prop_name}': minLength cannot exceed maxLength"
                    )

            # Validate pattern
            if "pattern" in prop_spec:
                pat = prop_spec["pattern"]
                if not isinstance(pat, str) or not pat:
                    raise PolicyError(f"'pattern' on argument '{prop_name}' must be a non-empty string")
                if len(pat) > MAX_PATTERN_LENGTH:
                    raise PolicyError(
                        f"pattern on argument '{prop_name}' exceeds maximum allowed length of {MAX_PATTERN_LENGTH}"
                    )
                validate_pattern_safety(pat)
                try:
                    _compile_anchored_pattern(pat)
                except re.error as exc:
                    raise PolicyError(f"invalid regex pattern on argument '{prop_name}': {exc}") from exc

            # Validate enum
            if "enum" in prop_spec:
                enum_vals = prop_spec["enum"]
                if not isinstance(enum_vals, Sequence) or isinstance(enum_vals, (str, bytes)) or len(enum_vals) == 0:
                    raise PolicyError(f"'enum' on argument '{prop_name}' must be a non-empty array of values")
                if type(enum_vals) is tuple:
                    raise PolicyError(f"'enum' on argument '{prop_name}' cannot be a tuple (use a JSON array)")
                for val_cand in enum_vals:
                    if type(val_cand) is tuple:
                        raise PolicyError(f"'enum' candidate in '{prop_name}' cannot be a tuple")

            # Validate array item bounds
            for item_len_key in ("minItems", "maxItems"):
                if item_len_key in prop_spec:
                    it_val = prop_spec[item_len_key]
                    if not _is_valid_integer(it_val) or it_val < 0:
                        raise PolicyError(f"'{item_len_key}' on argument '{prop_name}' must be a non-negative integer")

            if "items" in prop_spec:
                if not isinstance(prop_spec["items"], Mapping):
                    raise PolicyError(f"'items' on argument '{prop_name}' must be a mapping")
                validate_constraints_schema(
                    {"type": "object", "properties": {"item": prop_spec["items"]}},
                    depth=depth + 1,
                )

            # Validate nested object properties
            if "properties" in prop_spec:
                if not isinstance(prop_spec["properties"], Mapping):
                    raise PolicyError(f"'properties' on argument '{prop_name}' must be a mapping")
                validate_constraints_schema(
                    {
                        "type": "object",
                        "properties": prop_spec["properties"],
                        "required": prop_spec.get("required", []),
                        "additionalProperties": prop_spec.get("additionalProperties", True),
                    },
                    depth=depth + 1,
                )


def evaluate_constraints(
    constraints: Mapping[str, Any],
    arguments: Mapping[str, Any],
    depth: int = 0,
) -> tuple[bool, str | None]:
    """Evaluate request arguments against rule constraints.

    Pure deterministic function: zero side effects, zero object mutation.
    Returns (True, None) if all constraints pass, or (False, reason) on any violation.
    """
    if depth > MAX_CONSTRAINT_DEPTH:
        return False, "argument evaluation exceeded maximum nesting depth"

    if not isinstance(arguments, Mapping):
        return False, "arguments must be a mapping"

    # 1. Required fields
    if "required" in constraints:
        for req_field in constraints["required"]:
            if req_field not in arguments:
                return False, f"missing required argument '{req_field}'"

    # 2. Additional properties
    if constraints.get("additionalProperties") is False:
        allowed_properties = set(constraints.get("properties", {}).keys())
        for arg_key in arguments:
            if arg_key not in allowed_properties:
                return False, f"additional argument '{arg_key}' is not allowed"

    # 3. Field-by-field property constraints
    properties = constraints.get("properties", {})
    for field_name, rule_spec in properties.items():
        if field_name not in arguments:
            continue
        val = arguments[field_name]

        # Inferred type requirements when 'type' is omitted
        has_numeric_constraints = bool(set(rule_spec) & _NUMERIC_CONSTRAINT_KEYS)
        has_string_constraints = bool(set(rule_spec) & _STRING_CONSTRAINT_KEYS)
        has_array_constraints = bool(set(rule_spec) & _ARRAY_CONSTRAINT_KEYS)
        has_object_constraints = bool(set(rule_spec) & _OBJECT_CONSTRAINT_KEYS)

        # Check explicit type or inferred type requirement
        expected_type = rule_spec.get("type")
        if expected_type == "string" or (expected_type is None and has_string_constraints):
            if type(val) is not str:
                return False, f"argument '{field_name}' must be a string"
        elif expected_type == "number" or (expected_type is None and has_numeric_constraints):
            if not _is_valid_number(val):
                return False, f"argument '{field_name}' must be a valid number"
        elif expected_type == "integer":
            if not _is_valid_integer(val):
                return False, f"argument '{field_name}' must be an integer"
            if val > MAX_SAFE_INTEGER or val < MIN_SAFE_INTEGER:
                return False, f"argument '{field_name}' exceeds safe integer range"
        elif expected_type == "boolean":
            if type(val) is not bool:
                return False, f"argument '{field_name}' must be a boolean"
        elif expected_type == "array" or (expected_type is None and has_array_constraints):
            if not isinstance(val, (list, tuple)):
                return False, f"argument '{field_name}' must be an array"
        elif expected_type == "object" or (expected_type is None and has_object_constraints):
            if not isinstance(val, Mapping):
                return False, f"argument '{field_name}' must be an object"

        # Depth/size cap check for containers
        if isinstance(val, (list, tuple)):
            if len(val) > MAX_CONTAINER_SIZE:
                return False, f"argument '{field_name}' array exceeds maximum container size of {MAX_CONTAINER_SIZE}"
        elif isinstance(val, Mapping):
            if len(val) > MAX_CONTAINER_SIZE:
                return False, f"argument '{field_name}' object exceeds maximum container size of {MAX_CONTAINER_SIZE}"

        # Numeric bounds
        if _is_valid_number(val):
            if "minimum" in rule_spec:
                if safe_compare(val, rule_spec["minimum"]) < 0:
                    return False, f"argument '{field_name}' must be >= {rule_spec['minimum']}"
            if "maximum" in rule_spec:
                if safe_compare(val, rule_spec["maximum"]) > 0:
                    return False, f"argument '{field_name}' must be <= {rule_spec['maximum']}"
            if "exclusiveMinimum" in rule_spec:
                if safe_compare(val, rule_spec["exclusiveMinimum"]) <= 0:
                    return False, f"argument '{field_name}' must be > {rule_spec['exclusiveMinimum']}"
            if "exclusiveMaximum" in rule_spec:
                if safe_compare(val, rule_spec["exclusiveMaximum"]) >= 0:
                    return False, f"argument '{field_name}' must be < {rule_spec['exclusiveMaximum']}"

        # String length & pattern
        if type(val) is str:
            if len(val) > MAX_STRING_INPUT_LENGTH:
                return False, f"argument '{field_name}' exceeds maximum allowed length of {MAX_STRING_INPUT_LENGTH}"
            if "minLength" in rule_spec and len(val) < rule_spec["minLength"]:
                return False, f"argument '{field_name}' length must be >= {rule_spec['minLength']}"
            if "maxLength" in rule_spec and len(val) > rule_spec["maxLength"]:
                return False, f"argument '{field_name}' length must be <= {rule_spec['maxLength']}"
            if "pattern" in rule_spec:
                pattern = _compile_anchored_pattern(rule_spec["pattern"])
                if not pattern.fullmatch(val):
                    return False, f"argument '{field_name}' does not match pattern '{rule_spec['pattern']}'"

        # Enum check with strict type-and-value equality (e.g. True does not match 1)
        if "enum" in rule_spec:
            if type(val) is tuple:
                return False, f"argument '{field_name}' contains tuple which is not allowed"
            matched_enum = False
            for enum_candidate in rule_spec["enum"]:
                if type(val) is type(enum_candidate) and val == enum_candidate:
                    matched_enum = True
                    break
            if not matched_enum:
                return False, f"argument '{field_name}' must be one of {rule_spec['enum']}"

        # Array length & items
        if isinstance(val, (list, tuple)):
            if "minItems" in rule_spec and len(val) < rule_spec["minItems"]:
                return False, f"argument '{field_name}' array length must be >= {rule_spec['minItems']}"
            if "maxItems" in rule_spec and len(val) > rule_spec["maxItems"]:
                return False, f"argument '{field_name}' array length must be <= {rule_spec['maxItems']}"
            if "items" in rule_spec and isinstance(rule_spec["items"], Mapping):
                item_spec = rule_spec["items"]
                for idx, elem in enumerate(val):
                    elem_ok, elem_err = evaluate_constraints(
                        {"properties": {"item": item_spec}},
                        {"item": elem},
                        depth=depth + 1,
                    )
                    if not elem_ok:
                        return False, f"element {idx} of argument '{field_name}' failed constraint: {elem_err}"

        # Nested object properties
        if isinstance(val, Mapping) and ("properties" in rule_spec or "required" in rule_spec):
            nested_schema = {
                "properties": rule_spec.get("properties", {}),
                "required": rule_spec.get("required", []),
                "additionalProperties": rule_spec.get("additionalProperties", True),
            }
            sub_ok, sub_err = evaluate_constraints(nested_schema, val, depth=depth + 1)
            if not sub_ok:
                return False, f"nested object in '{field_name}' failed constraint: {sub_err}"

    return True, None
