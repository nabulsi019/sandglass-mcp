"""Build a valid, harmless example input from a tool's JSON input schema (#22).

MCP tools describe their arguments with JSON Schema. Sandglass calls each
tool once, so it needs one input the tool will accept. The rules, in order:

  1. `const`, then the first `enum` value, then `default`, then `examples[0]`
  2. otherwise by type:
       string   "hello" (so the notes fixtures call read_note("hello")),
                padded to minLength / cut to maxLength, or a simple value for
                a common `format` (date, email, uri, ...)
       integer  1, moved inside minimum/maximum (and up to a multipleOf)
       number   1.0, the same way
       boolean  false
       null     None
       object   every property (required and optional), recursively; a
                required name with no description gets "hello"
       array    max(minItems, 1) items (none if maxItems is 0), from `items`
  3. `["string", "null"]` and `anyOf`/`oneOf`: the first option that isn't null.
     `allOf`: its parts merged into one schema.
  4. Local `$ref`s (`#/$defs/Name`, `#/definitions/Name`) are followed; pydantic
     puts nested models there. Nesting is capped at MAX_DEPTH, so a schema
     that refers to itself can't loop forever.

Anything else (a `pattern` we can't satisfy, an external $ref, ...) is not
guessed: InputError, and the client skips that tool and says why.
"""

import math

SAFE_STRING = "hello"
MAX_DEPTH = 10

# Simple valid values for common string formats.
FORMAT_EXAMPLES = {
    "date": "2026-01-01",
    "date-time": "2026-01-01T00:00:00Z",
    "time": "00:00:00Z",
    "email": "test@example.com",
    "uri": "https://example.com/",
    "url": "https://example.com/",
    "hostname": "example.com",
    "ipv4": "127.0.0.1",
    "uuid": "00000000-0000-4000-8000-000000000000",
}


class InputError(ValueError):
    """The schema asks for something we can't build a valid value for."""


def build_arguments(input_schema: dict) -> dict:
    """The arguments for one tool call: an example of its input schema."""
    value = example_value(input_schema or {"type": "object"}, input_schema or {})
    if not isinstance(value, dict):
        raise InputError("the input schema is not an object")
    return value


def example_value(schema, root: dict, depth: int = 0):
    """One valid example of `schema`. `root` is the whole schema, for $refs."""
    if depth > MAX_DEPTH:
        raise InputError(f"schema nested more than {MAX_DEPTH} levels (a $ref loop?)")
    if schema is True or schema == {}:
        return SAFE_STRING  # "anything goes"
    if not isinstance(schema, dict):
        raise InputError(f"not a schema: {schema!r}")

    if "$ref" in schema:
        return example_value(_resolve(schema["$ref"], root), root, depth + 1)

    # A value the schema itself gives us.
    if "const" in schema:
        return schema["const"]
    if schema.get("enum"):
        return schema["enum"][0]
    if "default" in schema:
        return schema["default"]
    if schema.get("examples"):
        return schema["examples"][0]

    if "allOf" in schema:
        merged = {k: v for k, v in schema.items() if k != "allOf"}
        for part in schema["allOf"]:
            part = _resolve(part["$ref"], root) if "$ref" in part else part
            merged = _merge(merged, part)
        return example_value(merged, root, depth + 1)
    for key in ("anyOf", "oneOf"):
        if key in schema:
            return example_value(_first_not_null(schema[key]), root, depth + 1)

    kind = schema.get("type")
    if isinstance(kind, list):
        kind = next((t for t in kind if t != "null"), "null")
    if kind is None:
        # No type: guess from the keywords that are there.
        kind = "object" if "properties" in schema else "array" if "items" in schema else "string"

    if kind == "string":
        return _string(schema)
    if kind == "integer":
        return int(_number(schema, 1, integer=True))
    if kind == "number":
        return float(_number(schema, 1.0, integer=False))
    if kind == "boolean":
        return False
    if kind == "null":
        return None
    if kind == "object":
        properties = schema.get("properties", {})
        value = {name: example_value(spec, root, depth + 1) for name, spec in properties.items()}
        for name in schema.get("required", []):
            value.setdefault(name, SAFE_STRING)  # required but not described: a plain string
        return value
    if kind == "array":
        count = max(schema.get("minItems", 0), 1)
        if "maxItems" in schema:
            count = min(count, schema["maxItems"])
        items = schema.get("items", {})
        if isinstance(items, list):  # old-style tuple: one schema per position
            return [example_value(item, root, depth + 1) for item in items]
        return [example_value(items, root, depth + 1) for _ in range(count)]
    raise InputError(f"unsupported type {kind!r}")


def _resolve(ref: str, root: dict) -> dict:
    """Follow a local $ref like "#/$defs/Address"."""
    if not ref.startswith("#/"):
        raise InputError(f"only local $refs are supported, not {ref!r}")
    node = root
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")  # JSON Pointer escapes
        if not isinstance(node, dict) or part not in node:
            raise InputError(f"$ref {ref!r} points nowhere")
        node = node[part]
    return node


def _first_not_null(options: list):
    """The first anyOf/oneOf option that isn't just {"type": "null"}."""
    for option in options:
        if not (isinstance(option, dict) and option.get("type") == "null"):
            return option
    return options[0] if options else {}


def _merge(a: dict, b: dict) -> dict:
    """allOf: combine two schemas (properties and required lists are joined)."""
    merged = {**a, **b}
    if "properties" in a or "properties" in b:
        merged["properties"] = {**a.get("properties", {}), **b.get("properties", {})}
    if "required" in a or "required" in b:
        merged["required"] = list(dict.fromkeys(a.get("required", []) + b.get("required", [])))
    return merged


def _string(schema: dict) -> str:
    if "pattern" in schema:
        raise InputError(f"can't build a string matching pattern {schema['pattern']!r}")
    value = FORMAT_EXAMPLES.get(schema.get("format"), SAFE_STRING)
    min_length, max_length = schema.get("minLength", 0), schema.get("maxLength")
    if len(value) < min_length:
        value += "x" * (min_length - len(value))
    if max_length is not None:
        value = value[:max_length]
    return value


def _number(schema: dict, value, integer: bool):
    """`value`, moved into [minimum, maximum] and onto a multipleOf."""
    step = 1 if integer else 0.5
    if "minimum" in schema:
        value = max(value, schema["minimum"])
    if "exclusiveMinimum" in schema and value <= schema["exclusiveMinimum"]:
        value = schema["exclusiveMinimum"] + step
    if "maximum" in schema:
        value = min(value, schema["maximum"])
    if "exclusiveMaximum" in schema and value >= schema["exclusiveMaximum"]:
        value = schema["exclusiveMaximum"] - step
    if schema.get("multipleOf"):
        value = math.ceil(value / schema["multipleOf"]) * schema["multipleOf"]
    if integer:
        value = math.ceil(value)
    return value
