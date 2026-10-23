"""Schema-based tool inputs (#22): every generated input must be valid.

Each test checks the exact value AND validates it with jsonschema (installed
with the mcp package), so "valid" is checked by a real validator, not by us.
"""

import jsonschema
import pytest

from sandglass.inputs import InputError, build_arguments, example_value


def args_for(schema: dict) -> dict:
    """Build the arguments, and fail the test if they don't validate."""
    args = build_arguments(schema)
    jsonschema.validate(args, schema)
    return args


def test_required_string_is_hello():
    # The notes fixtures depend on this: read_note("hello").
    schema = {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}
    assert args_for(schema) == {"name": "hello"}


def test_required_and_optional_properties_are_all_filled():
    schema = {"type": "object", "required": ["path"],
              "properties": {"path": {"type": "string"}, "recursive": {"type": "boolean"}}}
    assert args_for(schema) == {"path": "hello", "recursive": False}


def test_enum_uses_its_first_value():
    schema = {"type": "object", "required": ["unit"],
              "properties": {"unit": {"type": "string", "enum": ["celsius", "fahrenheit"]}}}
    assert args_for(schema) == {"unit": "celsius"}


@pytest.mark.parametrize("spec, expected", [
    ({"type": "integer"}, 1),
    ({"type": "integer", "minimum": 5}, 5),
    ({"type": "integer", "maximum": 0}, 0),
    ({"type": "integer", "exclusiveMinimum": 1}, 2),
    ({"type": "integer", "minimum": 3, "multipleOf": 10}, 10),
    ({"type": "number", "minimum": 0.5, "maximum": 0.75}, 0.75),
    ({"type": "number", "exclusiveMaximum": 0}, -0.5),
])
def test_integers_and_numbers_respect_their_bounds(spec, expected):
    schema = {"type": "object", "required": ["n"], "properties": {"n": spec}}
    assert args_for(schema) == {"n": expected}


def test_nested_object_through_a_ref_like_pydantic_makes():
    # What pydantic generates for `def search(query: str, filters: Filters)`.
    schema = {
        "type": "object",
        "$defs": {"Filters": {"type": "object", "required": ["since", "limit"], "properties": {
            "since": {"type": "string", "format": "date"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            "tags": {"anyOf": [{"type": "array", "items": {"type": "string"}}, {"type": "null"}],
                     "default": None},
        }}},
        "required": ["query", "filters"],
        "properties": {"query": {"type": "string"}, "filters": {"$ref": "#/$defs/Filters"}},
    }
    assert args_for(schema) == {"query": "hello",
                                "filters": {"since": "2026-01-01", "limit": 1, "tags": None}}


@pytest.mark.parametrize("spec, expected", [
    ({"type": "array", "items": {"type": "string"}}, ["hello"]),
    ({"type": "array", "items": {"type": "integer"}, "minItems": 3}, [1, 1, 1]),
    ({"type": "array", "maxItems": 0}, []),
    ({"type": "array", "items": {"type": "object", "properties": {"id": {"type": "integer"}},
                                 "required": ["id"]}}, [{"id": 1}]),
])
def test_arrays_get_valid_items(spec, expected):
    schema = {"type": "object", "required": ["xs"], "properties": {"xs": spec}}
    assert args_for(schema) == {"xs": expected}


@pytest.mark.parametrize("spec, expected", [
    ({"type": ["string", "null"]}, "hello"),
    ({"anyOf": [{"type": "null"}, {"type": "integer"}]}, 1),
    ({"oneOf": [{"type": "boolean"}, {"type": "string"}]}, False),
    ({"const": "fixed"}, "fixed"),
    ({"type": "string", "default": "notes"}, "notes"),
    ({"type": "string", "examples": ["README"]}, "README"),
    ({"type": "string", "minLength": 8}, "helloxxx"),
    ({"type": "string", "maxLength": 2}, "he"),
    ({"type": "string", "format": "email"}, "test@example.com"),
    ({"allOf": [{"type": "object", "properties": {"a": {"type": "integer"}}},
                {"properties": {"b": {"type": "string"}}, "required": ["b"]}]}, {"a": 1, "b": "hello"}),
])
def test_other_schema_shapes(spec, expected):
    schema = {"type": "object", "required": ["x"], "properties": {"x": spec}}
    assert args_for(schema) == {"x": expected}


def test_tool_without_arguments():
    assert args_for({"type": "object", "properties": {}}) == {}
    assert build_arguments({}) == {}


@pytest.mark.parametrize("schema, message", [
    ({"type": "string", "pattern": "^[A-Z]{3}$"}, "pattern"),
    ({"$ref": "https://example.com/schema.json"}, "only local"),
    ({"$ref": "#/$defs/Missing"}, "points nowhere"),
    ({"type": "tuple"}, "unsupported type"),
])
def test_unsupported_schemas_are_refused_not_guessed(schema, message):
    with pytest.raises(InputError, match=message):
        example_value(schema, schema)


def test_a_self_referencing_schema_does_not_loop():
    schema = {"$defs": {"Node": {"type": "object", "required": ["child"],
                                 "properties": {"child": {"$ref": "#/$defs/Node"}}}},
              "$ref": "#/$defs/Node"}
    with pytest.raises(InputError, match="nested more than"):
        build_arguments(schema)
