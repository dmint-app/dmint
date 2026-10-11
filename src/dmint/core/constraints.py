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
from typing import Any

from .errors import PolicyError

MAX_PATTERN_LENGTH = 256
MAX_STRING_INPUT_LENGTH = 4096
MAX_QUANTIFIER_BOUND = 64
MAX_TOTAL_QUANTIFIERS = 3
MAX_UNBOUNDED_QUANTIFIERS = 2
MAX_REPETITION_BUDGET = 1_000_000
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


class _RegexNode:
    pass


class _AnchorNode(_RegexNode):
    def __init__(self, char: str) -> None:
        self.char = char


class _AtomNode(_RegexNode):
    def __init__(self, text: str) -> None:
        self.text = text


class _CharClassNode(_RegexNode):
    def __init__(self, negated: bool, content: str) -> None:
        self.negated = negated
        self.content = content


class _QuantifierNode(_RegexNode):
    def __init__(self, child: _RegexNode, min_r: int, max_r: int | None, lazy: bool) -> None:
        self.child = child
        self.min_r = min_r
        self.max_r = max_r
        self.lazy = lazy

    @property
    def is_unbounded(self) -> bool:
        return self.max_r is None


class _GroupNode(_RegexNode):
    def __init__(self, branches: list[list[_RegexNode]], capturing: bool) -> None:
        self.branches = branches
        self.capturing = capturing


def _parse_regex_ast(pattern: str) -> list[list[_RegexNode]]:
    """Parse regex into AST of branches and nodes using strict allowlist grammar."""
    pos = 0
    length = len(pattern)

    # Strip recognized inline flags at start: (?i), (?s), (?m)
    while pos < length and pattern[pos : pos + 2] == "(?":
        flag_match = re.match(r"\(\?[aiLmsux]+(?:\-[imsx]+)?\)", pattern[pos:])
        if flag_match:
            pos += len(flag_match.group(0))
        else:
            break

    def parse_branches(until_paren: bool) -> list[list[_RegexNode]]:
        nonlocal pos
        branches: list[list[_RegexNode]] = [[]]
        while pos < length:
            c = pattern[pos]
            pos += 1
            if c == "|":
                branches.append([])
            elif c == ")":
                if until_paren:
                    return branches
                raise PolicyError("unmatched ')' in regex pattern")
            elif c in "^$":
                branches[-1].append(_AnchorNode(c))
            elif c == "\\":
                if pos >= length:
                    raise PolicyError("trailing backslash in regex pattern")
                nc = pattern[pos]
                pos += 1
                if nc in "123456789":
                    raise PolicyError("backreferences are not allowed")
                if nc == "g" and pos < length and pattern[pos] == "<":
                    raise PolicyError("backreferences are not allowed")
                branches[-1].append(_AtomNode("\\" + nc))
            elif c == "[":
                start_c = pos
                negated = False
                if pos < length and pattern[pos] == "^":
                    negated = True
                    pos += 1
                if pos < length and pattern[pos] == "]":
                    pos += 1
                while pos < length and pattern[pos] != "]":
                    if pattern[pos] == "\\":
                        pos += 2
                    else:
                        pos += 1
                if pos >= length:
                    raise PolicyError("unterminated character class '[...]'")
                content = pattern[start_c:pos]
                pos += 1
                branches[-1].append(_CharClassNode(negated, content))
            elif c == "(":
                if pos < length and pattern[pos] == "?":
                    if pattern[pos : pos + 2] in ("?=", "?!", "?<"):
                        raise PolicyError("lookaround assertions are not allowed")
                    if pattern[pos : pos + 3] in ("?<=", "?<!"):
                        raise PolicyError("lookaround assertions are not allowed")
                    if pattern[pos : pos + 3] == "?P=":
                        raise PolicyError("backreferences are not allowed")
                    if pattern[pos : pos + 3] == "?P<":
                        raise PolicyError("named capture groups with backreferences are not allowed")
                    if pattern[pos : pos + 2] == "?:":
                        pos += 2
                        capturing = False
                    else:
                        raise PolicyError(f"unsupported group construct '(?{pattern[pos]}'")
                else:
                    capturing = True
                inner_branches = parse_branches(until_paren=True)
                branches[-1].append(_GroupNode(inner_branches, capturing))
            elif c in "*+?{":
                if not branches[-1]:
                    raise PolicyError(f"quantifier '{c}' without preceding token")
                prev = branches[-1][-1]
                if isinstance(prev, (_AnchorNode, _QuantifierNode)):
                    raise PolicyError(f"cannot apply quantifier '{c}' to anchor or quantifier")
                if c == "*":
                    min_r, max_r = 0, None
                elif c == "+":
                    min_r, max_r = 1, None
                elif c == "?":
                    min_r, max_r = 0, 1
                else:
                    end_b = pattern.find("}", pos)
                    if end_b == -1:
                        raise PolicyError("unterminated range quantifier '{'")
                    spec = pattern[pos:end_b]
                    pos = end_b + 1
                    parts = spec.split(",")
                    if len(parts) == 1:
                        try:
                            min_r = max_r = int(parts[0].strip())
                        except ValueError:
                            raise PolicyError(f"invalid range quantifier '{{{spec}}}'")
                        if max_r > MAX_QUANTIFIER_BOUND:
                            raise PolicyError(
                                f"quantifier count {max_r} exceeds maximum limit of {MAX_QUANTIFIER_BOUND}"
                            )
                    elif len(parts) == 2:
                        try:
                            min_r = int(parts[0].strip()) if parts[0].strip() else 0
                            max_r = int(parts[1].strip()) if parts[1].strip() else None
                        except ValueError:
                            raise PolicyError(f"invalid range quantifier '{{{spec}}}'")
                        if min_r > MAX_QUANTIFIER_BOUND:
                            raise PolicyError(
                                f"quantifier lower bound {min_r} exceeds maximum limit of {MAX_QUANTIFIER_BOUND}"
                            )
                        if max_r is not None and max_r > MAX_QUANTIFIER_BOUND:
                            raise PolicyError(
                                f"quantifier upper bound {max_r} exceeds maximum limit of {MAX_QUANTIFIER_BOUND}"
                            )
                        if max_r is not None and min_r > max_r:
                            raise PolicyError(f"min repeat cannot exceed max repeat in '{{{spec}}}'")
                    else:
                        raise PolicyError(f"invalid range quantifier '{{{spec}}}'")
                lazy = False
                if pos < length and pattern[pos] == "?":
                    lazy = True
                    pos += 1
                branches[-1][-1] = _QuantifierNode(prev, min_r, max_r, lazy)
            else:
                branches[-1].append(_AtomNode(c))
        if until_paren:
            raise PolicyError("unterminated group '(' in regex pattern")
        return branches

    return parse_branches(until_paren=False)


def validate_pattern_safety(pattern: str) -> None:
    """Validate regex pattern safety using allowlist grammar AST analysis.

    Rejects patterns that pose catastrophic backtracking (ReDoS) risk:
    - Every bounded count capped at MAX_QUANTIFIER_BOUND (64)
    - Total quantifiers of ANY kind across pattern capped at MAX_TOTAL_QUANTIFIERS (3)
    - Total unbounded repeats (*, +, {m,}) capped at MAX_UNBOUNDED_QUANTIFIERS (2)
    - Multiple unbounded repeats cannot combine with other quantifiers
    - Repetition budget across bounded quantifiers capped below 1,000,000
    - No nested repeats (repeat inside repeat)
    - No alternation inside repeats
    - No backreferences
    - No lookarounds
    """
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise PolicyError(f"pattern exceeds maximum allowed length of {MAX_PATTERN_LENGTH}")

    try:
        branches = _parse_regex_ast(pattern)
    except PolicyError:
        raise
    except Exception as exc:
        raise PolicyError(f"invalid regex pattern syntax: {exc}") from exc

    total_quantifiers = 0
    total_unbounded = 0
    bounded_upper_product = 1

    def _check_node(node: _RegexNode, inside_repeat: bool) -> None:
        nonlocal total_quantifiers, total_unbounded, bounded_upper_product
        if isinstance(node, _QuantifierNode):
            if inside_repeat:
                raise PolicyError("nested repeat is not allowed (catastrophic backtracking risk)")
            total_quantifiers += 1
            if node.max_r is not None:
                if node.max_r > MAX_QUANTIFIER_BOUND:
                    raise PolicyError(
                        f"quantifier upper bound {node.max_r} exceeds maximum limit of {MAX_QUANTIFIER_BOUND}"
                    )
                bounded_upper_product *= max(1, node.max_r)
            else:
                total_unbounded += 1

            if isinstance(node.child, _GroupNode):
                if len(node.child.branches) > 1:
                    raise PolicyError("alternation inside repeat is not allowed (catastrophic backtracking risk)")
                for br in node.child.branches:
                    for el in br:
                        if isinstance(el, _QuantifierNode):
                            raise PolicyError("nested repeat is not allowed (catastrophic backtracking risk)")

            _check_node(node.child, inside_repeat=True)
        elif isinstance(node, _GroupNode):
            for br in node.branches:
                for el in br:
                    _check_node(el, inside_repeat=inside_repeat)

    for br in branches:
        saw_unbounded = False
        saw_delimiter = False
        for el in br:
            _check_node(el, inside_repeat=False)
            if isinstance(el, _QuantifierNode) and el.is_unbounded:
                if saw_unbounded and not saw_delimiter:
                    raise PolicyError(
                        "multiple unbounded quantifiers without intervening literal delimiter rejected (ReDoS protection)"
                    )
                saw_unbounded = True
                saw_delimiter = False
            elif isinstance(el, _AtomNode) and el.text:
                saw_delimiter = True

    if total_quantifiers > MAX_TOTAL_QUANTIFIERS:
        raise PolicyError(
            f"pattern exceeds maximum of {MAX_TOTAL_QUANTIFIERS} quantifiers of any kind: found {total_quantifiers}"
        )
    if total_unbounded > MAX_UNBOUNDED_QUANTIFIERS:
        raise PolicyError(
            f"pattern exceeds maximum of {MAX_UNBOUNDED_QUANTIFIERS} unbounded repeats: found {total_unbounded}"
        )
    if bounded_upper_product > MAX_REPETITION_BUDGET:
        raise PolicyError(
            f"repetition budget across bounded quantifiers ({bounded_upper_product}) exceeds maximum of {MAX_REPETITION_BUDGET}"
        )


@functools.lru_cache(maxsize=512)
def _compile_anchored_pattern(pattern: str) -> re.Pattern[str]:
    """Compile pattern for anchored fullmatch evaluation using the stdlib re engine."""
    return re.compile(pattern)


def _reject_tuples_in_schema(val: Any, path: str = "constraints") -> None:
    if type(val) is tuple:
        raise PolicyError(f"{path} cannot be a tuple; use a JSON array (list)")
    if isinstance(val, Mapping):
        for k, v in val.items():
            _reject_tuples_in_schema(v, f"{path}.{k}")
    elif isinstance(val, list):
        for idx, item in enumerate(val):
            _reject_tuples_in_schema(item, f"{path}[{idx}]")


def parse_constraints(data: str | bytes) -> dict[str, Any]:
    """Parse a constraints JSON definition, strictly rejecting duplicate keys at any depth."""
    import json

    raw_bytes = data.encode("utf-8") if isinstance(data, str) else data

    def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for k, v in pairs:
            if k in result:
                raise PolicyError(f"duplicate JSON key in constraints: {k!r}")
            result[k] = v
        return result

    try:
        parsed = json.loads(raw_bytes, object_pairs_hook=_reject_duplicate_keys)
    except Exception as exc:
        if isinstance(exc, PolicyError):
            raise
        raise PolicyError(f"invalid JSON for constraints: {exc}") from exc

    validate_constraints_schema(parsed)
    return parsed


def validate_constraints_schema(schema: Any, depth: int = 0) -> None:
    """Validate constraints schema definition at policy loading time.

    Rejects unknown keys, unsupported types, invalid bounds, empty enums, and ReDoS regexes with PolicyError.
    Recursively validates nested properties and items.
    """
    if depth > MAX_CONSTRAINT_DEPTH:
        raise PolicyError("constraints schema exceeds maximum allowed nesting depth")

    if not isinstance(schema, Mapping):
        raise PolicyError("constraints must be an object mapping")

    _reject_tuples_in_schema(schema)

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
            has_numeric = bool(set(prop_spec) & _NUMERIC_CONSTRAINT_KEYS)
            has_string = bool(set(prop_spec) & _STRING_CONSTRAINT_KEYS)
            has_array = bool(set(prop_spec) & _ARRAY_CONSTRAINT_KEYS)
            has_object = bool(set(prop_spec) & _OBJECT_CONSTRAINT_KEYS)

            if "type" in prop_spec:
                type_name = prop_spec["type"]
                if type_name not in _SUPPORTED_TYPES:
                    raise PolicyError(f"unknown constraint type '{type_name}' on argument '{prop_name}'")
            else:
                active_kinds = [
                    k
                    for k, active in (
                        ("numeric", has_numeric),
                        ("string", has_string),
                        ("array", has_array),
                        ("object", has_object),
                    )
                    if active
                ]
                if len(active_kinds) > 1:
                    raise PolicyError(
                        f"property '{prop_name}' has conflicting constraint types ({', '.join(active_kinds)}) without an explicit 'type'"
                    )

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
    *,
    default_additional_properties: bool = True,
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
    allow_additional = constraints.get("additionalProperties", default_additional_properties)
    if allow_additional is False:
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
                        default_additional_properties=default_additional_properties,
                        depth=depth + 1,
                    )
                    if not elem_ok:
                        return False, f"element {idx} of argument '{field_name}' failed constraint: {elem_err}"

        # Nested object properties
        if isinstance(val, Mapping) and ("properties" in rule_spec or "required" in rule_spec):
            nested_schema = {
                "properties": rule_spec.get("properties", {}),
                "required": rule_spec.get("required", []),
                "additionalProperties": rule_spec.get("additionalProperties", default_additional_properties),
            }
            sub_ok, sub_err = evaluate_constraints(
                nested_schema,
                val,
                default_additional_properties=default_additional_properties,
                depth=depth + 1,
            )
            if not sub_ok:
                return False, f"nested object in '{field_name}' failed constraint: {sub_err}"

    return True, None
