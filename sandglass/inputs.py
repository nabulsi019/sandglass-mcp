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

Input modes (#145), chosen with --inputs; build_inputs() is the entry point:

  minimal    required arguments only, each a plain value for its type
             ("hello", 0, false, [], {}). The naive arm, for research.
  schema     exactly the rules above (build_arguments), unchanged since #22.
  described  (default) per top-level argument, the first source that gives a
             value of the right type:
               const > enum[0] > default > examples[0]
               > an example in the argument's description ("e.g. 'X'")
               > an http(s) URL in the tool's description (url/uri/link args)
               > a format hint > a value matching the pattern
               > the number bounds > the schema rules above (the fallback)

Every value is recorded with its source. Description examples come from the
server's own text, so a hostile server can choose its own inputs: that is
fine, Sandglass judges what the server does, not the inputs. Values are only
sent to the tool, never interpreted (no path is created, nothing executed),
and a description example is at most MAX_EXAMPLE_CHARS characters.
"""

import math
import re

SAFE_STRING = "hello"
MAX_DEPTH = 10

MODES = ("minimal", "schema", "described")
DEFAULT_MODE = "described"

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


# ---------------------------------------------------------------------------
# Input modes (#145): minimal, schema, described
# ---------------------------------------------------------------------------

# minimal mode: one plain value per type, nothing read from the schema.
PLAIN_VALUES = {"string": SAFE_STRING, "integer": 0, "number": 0, "boolean": False,
                "array": [], "object": {}, "null": None}

# described mode's format hints (#145's list; the schema mode keeps FORMAT_EXAMPLES).
DESCRIBED_FORMATS = {
    "date": "2024-01-15",
    "date-time": "2024-01-15T12:00:00Z",
    "uri": "https://example.com/",
    "url": "https://example.com/",
    "email": "user@example.com",
    "uuid": "123e4567-e89b-42d3-a456-426614174000",
    "time": "12:00",
}

# An example found in a description is used only if it is this short.
MAX_EXAMPLE_CHARS = 200

# Words that introduce an example in a description, e.g. "(e.g. 'America/New_York')".
EXAMPLE_MARKER = re.compile(r"\b(?:e\.g\.|eg\.|for example|example:|such as)", re.IGNORECASE)
# A quoted token: '...', "..." or `...` on one line. The opening quote must
# follow a space or one of ( [ { , : = (so the ' in "user's" isn't one), and
# the closing quote must not run into a letter or digit.
QUOTED = re.compile(r"(?<![^\s(\[{,:=])(['\"`])([^\n]*?)\1(?![A-Za-z0-9])")
# The end of a sentence: . ! or ? before whitespace, or a blank line.
SENTENCE_END = re.compile(r"[.!?](?=\s)|\n\s*\n")
# The first http(s) URL in a text, up to a space, a quote or a closing bracket.
URL = re.compile(r"https?://[^\s'\"`<>)\]}]+")
# Strings tried, in order, against a `pattern` we have no example for.
PATTERN_CANDIDATES = ["hello", "abc", "ABC", "a1", "123", "1", "2024-01-15", "12:00",
                      "user@example.com", "https://example.com/"]
NUMBER_BOUNDS = ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf")


def build_inputs(input_schema: dict, tool_description: str | None = None,
                 mode: str = DEFAULT_MODE) -> dict:
    """The inputs for one tool call in `mode`: {argument: {"value", "source"}}.

    `source` is where the value came from: const, enum, default, examples,
    param-description, tool-description, format, pattern, bounds or fallback.
    Raises InputError if the tool can't be given a valid input (the client
    then skips it, as before).
    """
    schema = input_schema or {"type": "object"}
    if mode == "minimal":
        return _minimal_inputs(schema)
    if mode == "schema":
        # Today's values (#22), unchanged; only the sources are worked out.
        args = build_arguments(input_schema)
        properties = schema.get("properties", {})
        return {name: {"value": value, "source": _schema_source(properties.get(name), schema)}
                for name, value in args.items()}
    if mode == "described":
        return _described_inputs(schema, tool_description or "")
    raise ValueError(f"unknown input mode {mode!r} (expected one of {', '.join(MODES)})")


def arguments_of(inputs: dict) -> dict:
    """The plain {argument: value} dict that is sent to the tool."""
    return {name: entry["value"] for name, entry in inputs.items()}


def _walk(spec, root: dict) -> tuple[tuple | None, dict]:
    """Follow $ref / allOf / anyOf / oneOf in the same order as example_value.

    Returns (given, schema): `given` is (value, source) if a const, enum,
    default or examples decides the value on the way, else None; `schema` is
    the schema reached, whose type decides the rest.
    """
    for _ in range(MAX_DEPTH):
        if not isinstance(spec, dict):
            return None, {}
        if "$ref" in spec:
            spec = _resolve(spec["$ref"], root)
            continue
        if "const" in spec:
            return (spec["const"], "const"), spec
        if spec.get("enum"):
            return (spec["enum"][0], "enum"), spec
        if "default" in spec:
            return (spec["default"], "default"), spec
        if spec.get("examples"):
            return (spec["examples"][0], "examples"), spec
        if "allOf" in spec:
            merged = {k: v for k, v in spec.items() if k != "allOf"}
            for part in spec["allOf"]:
                merged = _merge(merged, _resolve(part["$ref"], root) if "$ref" in part else part)
            spec = merged
            continue
        options = spec.get("anyOf", spec.get("oneOf"))
        if options is not None:
            spec = _first_not_null(options)
            continue
        return None, spec
    raise InputError(f"schema nested more than {MAX_DEPTH} levels (a $ref loop?)")


def _kind(schema: dict) -> str:
    """The schema's type, the way example_value picks it."""
    kind = schema.get("type")
    if isinstance(kind, list):
        kind = next((t for t in kind if t != "null"), "null")
    if kind is None:
        kind = "object" if "properties" in schema else "array" if "items" in schema else "string"
    return kind


def _schema_source(spec, root: dict) -> str:
    """Where the schema mode's value for one argument came from (for the report)."""
    if spec is None:
        return "fallback"  # required but not described: "hello"
    given, schema = _walk(spec, root)
    if given:
        return given[1]
    kind = _kind(schema)
    if kind == "string" and schema.get("format") in FORMAT_EXAMPLES:
        return "format"
    if kind in ("integer", "number") and any(key in schema for key in NUMBER_BOUNDS):
        return "bounds"
    return "fallback"


def _minimal_inputs(schema: dict) -> dict:
    """Required arguments only, each the plain value for its type."""
    properties = schema.get("properties", {})
    inputs = {}
    for name in schema.get("required", []):
        try:
            _, resolved = _walk(properties.get(name, {}), schema)
        except InputError:
            resolved = {}
        value = PLAIN_VALUES.get(_kind(resolved), SAFE_STRING)
        # A fresh list/dict each time, so no two calls share one object.
        inputs[name] = {"value": list(value) if isinstance(value, list) else
                        dict(value) if isinstance(value, dict) else value, "source": "fallback"}
    return inputs


def _described_inputs(schema: dict, tool_description: str) -> dict:
    """Every argument (required and optional, like the schema mode), from the
    first source that gives a value; the schema mode's value is the fallback."""
    properties = schema.get("properties", {})
    inputs = {}
    for name, spec in properties.items():
        value, source = _described_value(name, spec, schema, tool_description)
        inputs[name] = {"value": value, "source": source}
    for name in schema.get("required", []):
        inputs.setdefault(name, {"value": SAFE_STRING, "source": "fallback"})
    return inputs


def _described_value(name: str, spec, root: dict, tool_description: str) -> tuple:
    """(value, source) for one argument in described mode."""
    given, schema = _walk(spec, root)
    if given:
        return given
    kind = _kind(schema)
    description = (spec.get("description") if isinstance(spec, dict) else None) or schema.get("description")

    # An example in the argument's own description: "(e.g. 'America/New_York')".
    token = example_from_description(description)
    if token is not None:
        value = coerce(token, schema, kind, root)
        if value is not NO_VALUE:
            return value, "param-description"

    # A URL argument: the first http(s) URL in the tool's description.
    if any(word in name.lower() for word in ("url", "uri", "link")) or schema.get("format") in ("uri", "url"):
        url = first_url(tool_description)
        if url is not None:
            value = coerce(url, schema, kind, root)
            if value is not NO_VALUE:
                return value, "tool-description"

    if kind == "string" and schema.get("format") in DESCRIBED_FORMATS:
        return DESCRIBED_FORMATS[schema["format"]], "format"
    if kind == "string" and "pattern" in schema:
        value = pattern_value(schema)
        if value is not None:
            return value, "pattern"
    if kind in ("integer", "number") and any(key in schema for key in NUMBER_BOUNDS):
        start = schema.get("minimum", 1)  # the minimum if there is one, else 1
        value = _number(schema, start, integer=kind == "integer")
        return (int(value) if kind == "integer" else float(value)), "bounds"

    # Nothing in the descriptions: the schema mode's value (may raise InputError).
    return example_value(spec, root), "fallback"


def example_from_description(text: str | None) -> str | None:
    """The first quoted token after an example marker, in the same sentence.

    "IANA timezone name (e.g., 'America/New_York', 'Europe/London')" gives
    America/New_York; "(e.g. ['cs.LG', 'cs.AI'])" gives cs.LG (the caller
    makes it a one-element list for an array). None if there is no such
    token, or it is empty, has a newline, or is over MAX_EXAMPLE_CHARS.
    """
    if not isinstance(text, str):
        return None
    for marker in EXAMPLE_MARKER.finditer(text):
        rest = text[marker.end():]
        quoted = QUOTED.search(rest)
        if quoted is None:
            continue
        if SENTENCE_END.search(rest[:quoted.start()]):
            continue  # the token belongs to a later sentence
        token = quoted.group(2)
        if token.strip() and len(token) <= MAX_EXAMPLE_CHARS and "\n" not in token:
            return token
    return None


def first_url(text: str | None) -> str | None:
    """The first http(s) URL in the text, without trailing punctuation."""
    if not isinstance(text, str):
        return None
    match = URL.search(text)
    if match is None:
        return None
    url = match.group(0).rstrip(".,;:!?")
    return url if len(url) <= MAX_EXAMPLE_CHARS else None


# coerce() returns this when the token can't be the argument's type.
NO_VALUE = object()


def coerce(token: str, schema: dict, kind: str, root: dict):
    """The token as a value of the argument's type, or NO_VALUE.

    string: as is, if it fits minLength/maxLength (and the pattern, if any);
    integer / number: if it is written as one and is inside the bounds;
    boolean: "true" / "false"; array: a one-element list of the item type.
    """
    if kind == "string":
        if not schema.get("minLength", 0) <= len(token) <= schema.get("maxLength", len(token)):
            return NO_VALUE
        if "pattern" in schema and not _matches(schema["pattern"], token):
            return NO_VALUE
        return token
    if kind in ("integer", "number"):
        pattern = r"-?\d+" if kind == "integer" else r"-?\d+(\.\d+)?"
        if not re.fullmatch(pattern, token.strip()):
            return NO_VALUE
        value = int(token) if kind == "integer" else float(token)
        if _number(schema, value, integer=kind == "integer") != value:
            return NO_VALUE  # outside the bounds
        return value
    if kind == "boolean":
        lowered = token.strip().lower()
        return {"true": True, "false": False}.get(lowered, NO_VALUE)
    if kind == "array":
        items = schema.get("items", {})
        if not isinstance(items, dict) or schema.get("maxItems", 1) < 1:
            return NO_VALUE
        try:
            given, item_schema = _walk(items, root)
        except InputError:
            return NO_VALUE
        if given:
            return NO_VALUE  # the items have a const/enum: the description can't override it
        item = coerce(token, item_schema, _kind(item_schema), root)
        return NO_VALUE if item is NO_VALUE else [item]
    return NO_VALUE  # objects, null: no example from a single token


def pattern_value(schema: dict) -> str | None:
    """The first PATTERN_CANDIDATES string the schema's pattern accepts, or None."""
    for candidate in PATTERN_CANDIDATES:
        if (_matches(schema["pattern"], candidate)
                and schema.get("minLength", 0) <= len(candidate) <= schema.get("maxLength", len(candidate))):
            return candidate
    return None


def _matches(pattern, value: str) -> bool:
    """Does the JSON Schema pattern (unanchored) match? A pattern that isn't a
    valid Python regex, or is over MAX_EXAMPLE_CHARS, matches nothing."""
    if not isinstance(pattern, str) or len(pattern) > MAX_EXAMPLE_CHARS:
        return False
    try:
        return re.search(pattern, value) is not None
    except re.error:
        return False
