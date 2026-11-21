"""A JSON Schema 2020-12 check for the contract schemas the core vendors from papaia-kit.

papaia-ctl runs on the host with PyYAML as its only third-party package, so it cannot
use a full validator. This module implements the keywords the vendored schemas use
(tools/schemas/kit) and refuses any other keyword, so a newer schema that needs more
fails loudly instead of being half checked:

    type enum const pattern minLength maxLength minimum maximum
    minItems maxItems uniqueItems items contains
    required properties additionalProperties propertyNames minProperties maxProperties
    $ref (inside the document) allOf anyOf oneOf not if/then/else

Annotations (`title`, `description`, `default`, `format`, `$comment`, ...) are
ignored, as 2020-12 does by default. `pattern` uses Python's `re` with `search`
semantics, as JSON Schema asks; the kit writes every anchor so that Python and
ECMA-262 agree. A reference to the 2020-12 meta-schema (embedded schemas in
`exposes`) checks that the value is an object or a boolean; the kit's own rules
for embedded schemas (local references only, no `$id`) are part of the vendored
schema and are checked here like every other rule.

The first failure is raised as SchemaError with the JSON pointer of the value and
the rule it breaks.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache

META_SCHEMA = "https://json-schema.org/draft/2020-12/schema"

_ANNOTATIONS = frozenset(
    {
        "$schema", "$id", "$comment", "$defs", "title", "description", "default",
        "examples", "format", "deprecated", "readOnly", "writeOnly",
    }
)
_ASSERTIONS = frozenset(
    {
        "type", "enum", "const", "pattern", "minLength", "maxLength", "minimum",
        "maximum", "minItems", "maxItems", "uniqueItems", "items", "contains",
        "required", "properties", "additionalProperties", "propertyNames",
        "minProperties", "maxProperties", "$ref", "allOf", "anyOf", "oneOf", "not",
        "if", "then", "else",
    }
)


class SchemaError(ValueError):
    """The instance does not satisfy the schema. `path` is a JSON pointer."""

    def __init__(self, path: str, reason: str) -> None:
        super().__init__(f"{path or '/'}: {reason}")
        self.path = path
        self.reason = reason


def _pointer(path: str, key: object) -> str:
    return f"{path}/{str(key).replace('~', '~0').replace('/', '~1')}"


@lru_cache(maxsize=512)
def _regex(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


def _is_type(value: object, name: str) -> bool:
    if name == "object":
        return isinstance(value, dict)
    if name == "array":
        return isinstance(value, list)
    if name == "string":
        return isinstance(value, str)
    if name == "boolean":
        return isinstance(value, bool)
    if name == "null":
        return value is None
    if isinstance(value, bool):
        return False
    if name == "integer":
        return isinstance(value, int) or (isinstance(value, float) and value.is_integer())
    if name == "number":
        return isinstance(value, (int, float))
    raise ValueError(f"unsupported type {name!r}")


def _key(value: object) -> str:
    """Equality as JSON Schema defines it: 1 == 1.0, but true != 1."""

    def norm(v: object) -> object:
        if isinstance(v, bool) or v is None or isinstance(v, str):
            return [type(v).__name__, v]
        if isinstance(v, (int, float)):
            return ["number", float(v) if float(v) != int(v) else int(v)]
        if isinstance(v, list):
            return ["array", [norm(x) for x in v]]
        if isinstance(v, dict):
            return ["object", sorted((k, norm(x)) for k, x in v.items())]
        raise ValueError(f"{type(v).__name__} is not a JSON value")

    return json.dumps(norm(value), sort_keys=True)


def check_supported(schema: object, where: str = "") -> None:
    """Raise ValueError when `schema` uses a keyword this module does not implement."""
    if isinstance(schema, bool):
        return
    if not isinstance(schema, dict):
        raise ValueError(f"{where or '/'}: a schema is an object or a boolean")
    for keyword, value in schema.items():
        if keyword.startswith("x-"):
            continue
        if keyword not in _ASSERTIONS and keyword not in _ANNOTATIONS:
            raise ValueError(f"{where or '/'}: unsupported keyword {keyword!r}")
        if keyword in ("properties", "$defs"):
            for name, sub in value.items():
                check_supported(sub, f"{where}/{keyword}/{name}")
        elif keyword in ("allOf", "anyOf", "oneOf"):
            for index, sub in enumerate(value):
                check_supported(sub, f"{where}/{keyword}/{index}")
        elif keyword in (
            "items", "contains", "not", "if", "then", "else", "additionalProperties",
            "propertyNames",
        ):
            check_supported(value, f"{where}/{keyword}")


class _Validator:
    def __init__(self, root: dict) -> None:
        self.root = root

    def resolve(self, ref: str) -> object:
        if ref == META_SCHEMA:
            return {"type": ["object", "boolean"]}
        if not ref.startswith("#"):
            raise ValueError(f"unsupported reference {ref!r}")
        node: object = self.root
        for part in ref[1:].split("/")[1:]:
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(node, dict) or part not in node:
                raise ValueError(f"unresolvable reference {ref!r}")
            node = node[part]
        return node

    def check(self, value: object, schema: object, path: str) -> None:
        if schema is True:
            return
        if schema is False:
            raise SchemaError(path, "no value is allowed here")
        if not isinstance(schema, dict):
            raise ValueError(f"{path}: a schema is an object or a boolean")
        for keyword in schema:
            if keyword not in _ASSERTIONS and keyword not in _ANNOTATIONS and not (
                keyword.startswith("x-")
            ):
                raise ValueError(f"unsupported keyword {keyword!r}")
        if "$ref" in schema:
            self.check(value, self.resolve(schema["$ref"]), path)
        self._generic(value, schema, path)
        if isinstance(value, str):
            self._string(value, schema, path)
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            self._number(value, schema, path)
        elif isinstance(value, list):
            self._array(value, schema, path)
        elif isinstance(value, dict):
            self._object(value, schema, path)
        self._combinators(value, schema, path)

    def _generic(self, value: object, schema: dict, path: str) -> None:
        if "type" in schema:
            names = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
            if not any(_is_type(value, name) for name in names):
                raise SchemaError(path, f"must be of type {' or '.join(names)}")
        if "const" in schema and _key(value) != _key(schema["const"]):
            raise SchemaError(path, f"must be {json.dumps(schema['const'])}")
        if "enum" in schema and _key(value) not in {_key(v) for v in schema["enum"]}:
            allowed = ", ".join(json.dumps(v) for v in schema["enum"])
            raise SchemaError(path, f"must be one of {allowed}")

    def _string(self, value: str, schema: dict, path: str) -> None:
        if "minLength" in schema and len(value) < schema["minLength"]:
            raise SchemaError(path, f"must have at least {schema['minLength']} characters")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise SchemaError(path, f"must have at most {schema['maxLength']} characters")
        if "pattern" in schema and not _regex(schema["pattern"]).search(value):
            raise SchemaError(path, f"does not match {schema['pattern']}")

    def _number(self, value: float, schema: dict, path: str) -> None:
        if "minimum" in schema and value < schema["minimum"]:
            raise SchemaError(path, f"must be at least {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            raise SchemaError(path, f"must be at most {schema['maximum']}")

    def _array(self, value: list, schema: dict, path: str) -> None:
        if "minItems" in schema and len(value) < schema["minItems"]:
            raise SchemaError(path, f"must have at least {schema['minItems']} item(s)")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            raise SchemaError(path, f"must have at most {schema['maxItems']} item(s)")
        if schema.get("uniqueItems"):
            seen: set[str] = set()
            for index, item in enumerate(value):
                key = _key(item)
                if key in seen:
                    raise SchemaError(_pointer(path, index), "repeats an earlier item")
                seen.add(key)
        if "items" in schema:
            for index, item in enumerate(value):
                self.check(item, schema["items"], _pointer(path, index))
        if "contains" in schema and not any(
            self.passes(item, schema["contains"], _pointer(path, i)) for i, item in enumerate(value)
        ):
            raise SchemaError(path, "contains no item of the required form")

    def _object(self, value: dict, schema: dict, path: str) -> None:
        if "minProperties" in schema and len(value) < schema["minProperties"]:
            raise SchemaError(path, f"must have at least {schema['minProperties']} field(s)")
        if "maxProperties" in schema and len(value) > schema["maxProperties"]:
            raise SchemaError(path, f"must have at most {schema['maxProperties']} field(s)")
        for name in schema.get("required", ()):
            if name not in value:
                raise SchemaError(_pointer(path, name), "required field is missing")
        properties = schema.get("properties", {})
        for name, item in value.items():
            where = _pointer(path, name)
            if "propertyNames" in schema and not self.passes(name, schema["propertyNames"], where):
                raise SchemaError(where, "field name is not allowed")
            if name in properties:
                self.check(item, properties[name], where)
            elif schema.get("additionalProperties") is False:
                raise SchemaError(where, "unknown field")
            elif "additionalProperties" in schema:
                self.check(item, schema["additionalProperties"], where)

    def _combinators(self, value: object, schema: dict, path: str) -> None:
        for sub in schema.get("allOf", ()):
            self.check(value, sub, path)
        if "anyOf" in schema and not any(self.passes(value, s, path) for s in schema["anyOf"]):
            raise SchemaError(path, self._first_reason(value, schema["anyOf"], path))
        if "oneOf" in schema:
            matches = sum(1 for s in schema["oneOf"] if self.passes(value, s, path))
            if matches != 1:
                raise SchemaError(path, f"must match exactly one alternative, matches {matches}")
        if "not" in schema and self.passes(value, schema["not"], path):
            raise SchemaError(path, "has a form that is not allowed here")
        if "if" in schema:
            branch = "then" if self.passes(value, schema["if"], path) else "else"
            if branch in schema:
                self.check(value, schema[branch], path)

    def _first_reason(self, value: object, alternatives: list, path: str) -> str:
        """The failure of the alternative that got furthest (the deepest path)."""
        best: SchemaError | None = None
        for sub in alternatives:
            try:
                self.check(value, sub, path)
            except SchemaError as exc:
                if best is None or len(exc.path) > len(best.path):
                    best = exc
        if best is not None and best.path != path:
            return f"matches no allowed form ({best.path}: {best.reason})"
        return "matches no allowed form" + (f" ({best.reason})" if best else "")

    def passes(self, value: object, schema: object, path: str) -> bool:
        try:
            self.check(value, schema, path)
        except SchemaError:
            return False
        return True


def validate(instance: object, schema: dict, ref: str | None = None) -> None:
    """Check `instance` against `schema` (or the part of it `ref` points at, such as
    `#/$defs/Branding`). Raises SchemaError for the first violation, ValueError for a
    schema this module cannot evaluate."""
    validator = _Validator(schema)
    target = validator.resolve(ref) if ref else schema
    validator.check(instance, target, "")
