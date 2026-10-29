"""Input modes (#145): minimal, schema and described, and where each value came from.

The "real server" schemas below are test data, written from the tool and
argument descriptions those packages publish (the descriptions are the
exact texts #145 quotes). Nothing is downloaded: no real package is used.
Every input the described mode builds is also checked with jsonschema.
"""

import json
from pathlib import Path

import jsonschema
import pytest

from sandglass import PROJECT_ROOT, client
from sandglass.compare import _markdown, build_report
from sandglass.inputs import (DEFAULT_MODE, MAX_EXAMPLE_CHARS, NO_VALUE, InputError, arguments_of,
                              build_arguments, build_inputs, coerce, example_from_description,
                              first_url)
from tests.test_sandbox_pipeline import EXITED, LAUNCH, NOTE_READ, run, sandbox_policy


def described(schema: dict, tool_description: str = "") -> dict:
    """The described mode's inputs, after checking they validate."""
    inputs = build_inputs(schema, tool_description, "described")
    jsonschema.validate(arguments_of(inputs), schema)
    return inputs


def one_arg(spec: dict, name: str = "x", tool_description: str = "") -> dict:
    """{"value", "source"} for one required argument in described mode."""
    schema = {"type": "object", "required": [name], "properties": {name: spec}}
    return described(schema, tool_description)[name]


# --- the real servers #145 names (schemas as test data) ---------------------------

TZ_DESCRIPTION = ("IANA timezone name (e.g., 'America/New_York', 'Europe/London'). "
                  "Use 'Etc/UTC' as local timezone if no timezone provided by the user.")
GET_CURRENT_TIME = {"type": "object", "required": ["timezone"],
                    "properties": {"timezone": {"type": "string", "description": TZ_DESCRIPTION}}}
CONVERT_TIME = {"type": "object", "required": ["source_timezone", "time", "target_timezone"], "properties": {
    "source_timezone": {"type": "string", "description": TZ_DESCRIPTION},
    "time": {"type": "string", "description": "Time to convert in 24-hour format (HH:MM)"},
    "target_timezone": {"type": "string", "description": TZ_DESCRIPTION},
}}
DOWNLOAD_PAPER = {"type": "object", "required": ["paper_id"], "properties": {
    "paper_id": {"type": "string", "description": "The arXiv ID of the paper to download (e.g. '2103.12345')"},
}}
SEARCH_PAPERS = {"type": "object", "required": ["query"], "properties": {
    "query": {"type": "string", "description": "Search query"},
    "categories": {"type": "array", "items": {"type": "string"},
                   "description": "arXiv category filters (e.g. ['cs.LG', 'cs.AI']). Strongly improves relevance."},
}}
READ_DOCUMENTATION = {"type": "object", "required": ["url"], "properties": {
    "url": {"type": "string", "description": "URL of the AWS documentation page to read"},
}}
READ_DOCUMENTATION_TOOL = (
    "Fetch and convert an AWS documentation page to markdown format.\n\n"
    "## Usage\n- URL must be from the docs.aws.amazon.com domain\n- URL must end with .html\n\n"
    "## Example URLs\n- https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html\n"
    "- https://docs.aws.amazon.com/lambda/latest/dg/lambda-invocation.html")


def test_mcp_server_time_gets_a_real_timezone():
    assert described(GET_CURRENT_TIME) == {
        "timezone": {"value": "America/New_York", "source": "param-description"}}


def test_mcp_server_time_convert_time_has_no_example_for_time():
    # "(HH:MM)" isn't a quoted example after a marker: honestly the fallback.
    inputs = described(CONVERT_TIME)
    assert inputs["source_timezone"] == {"value": "America/New_York", "source": "param-description"}
    assert inputs["time"] == {"value": "hello", "source": "fallback"}


def test_arxiv_download_paper_gets_the_example_id():
    assert described(DOWNLOAD_PAPER)["paper_id"] == {"value": "2103.12345", "source": "param-description"}


def test_arxiv_categories_get_the_first_list_element_as_a_list():
    inputs = described(SEARCH_PAPERS)
    assert inputs["categories"] == {"value": ["cs.LG"], "source": "param-description"}
    assert inputs["query"] == {"value": "hello", "source": "fallback"}


def test_aws_docs_url_comes_from_the_tool_description():
    assert described(READ_DOCUMENTATION, READ_DOCUMENTATION_TOOL)["url"] == {
        "value": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html",
        "source": "tool-description"}


def test_a_parameter_without_hints_gets_the_fallback():
    assert one_arg({"type": "string"}) == {"value": "hello", "source": "fallback"}
    assert one_arg({"type": "string", "description": "The note's name."}) == {"value": "hello",
                                                                             "source": "fallback"}


# --- each source, and the priority order -------------------------------------------

@pytest.mark.parametrize("spec, value, source", [
    ({"const": "fixed", "description": "e.g. 'other'"}, "fixed", "const"),
    ({"type": "string", "enum": ["a", "b"], "default": "b"}, "a", "enum"),
    ({"type": "string", "default": "notes", "examples": ["README"]}, "notes", "default"),
    ({"type": "string", "examples": ["README"], "description": "e.g. 'other'"}, "README", "examples"),
    ({"type": "string", "description": "e.g. 'from-param'", "format": "email"}, "from-param", "param-description"),
    ({"type": "string", "format": "date"}, "2024-01-15", "format"),
    ({"type": "string", "format": "date-time"}, "2024-01-15T12:00:00Z", "format"),
    ({"type": "string", "format": "uri"}, "https://example.com/", "format"),
    ({"type": "string", "format": "email"}, "user@example.com", "format"),
    ({"type": "string", "format": "uuid"}, "123e4567-e89b-42d3-a456-426614174000", "format"),
    ({"type": "string", "format": "time"}, "12:00", "format"),
    ({"type": "string", "pattern": "^[A-Z]{3}$"}, "ABC", "pattern"),
    ({"type": "string", "pattern": "^\\d+$"}, "123", "pattern"),
    ({"type": "integer", "minimum": 0}, 0, "bounds"),
    ({"type": "integer", "minimum": 5, "maximum": 9}, 5, "bounds"),
    ({"type": "integer", "exclusiveMinimum": 1}, 2, "bounds"),
    ({"type": "integer", "maximum": 0}, 0, "bounds"),
    ({"type": "number", "minimum": 0.25}, 0.25, "bounds"),
    ({"type": "number", "exclusiveMaximum": 0}, -0.5, "bounds"),
    ({"type": "integer"}, 1, "fallback"),
    ({"type": "boolean"}, False, "fallback"),
])
def test_each_source_and_its_priority(spec, value, source):
    assert one_arg(spec) == {"value": value, "source": source}


def test_param_description_beats_the_tool_description_url():
    spec = {"type": "string", "description": "Page to read, e.g. 'https://a.example/x.html'"}
    assert one_arg(spec, "url", "See https://b.example/y.html") == {
        "value": "https://a.example/x.html", "source": "param-description"}


def test_tool_description_beats_the_format_hint():
    spec = {"type": "string", "format": "uri"}
    assert one_arg(spec, "page", "Reads https://docs.example/page.html.") == {
        "value": "https://docs.example/page.html", "source": "tool-description"}


@pytest.mark.parametrize("name", ["url", "source_uri", "docLink", "URL"])
def test_tool_description_url_only_for_url_names_or_uri_format(name):
    assert one_arg({"type": "string"}, name, "See https://docs.example/a.html")["source"] == "tool-description"


def test_tool_description_url_not_used_for_other_arguments():
    assert one_arg({"type": "string"}, "query", "See https://docs.example/a.html") == {
        "value": "hello", "source": "fallback"}


def test_examples_in_a_ref_and_anyof_are_found_like_the_schema_mode():
    # What pydantic makes for `tags: list[str] | None = None` and a $ref'd enum.
    schema = {"type": "object", "required": ["kind"], "$defs": {"Kind": {"enum": ["fast", "slow"]}},
              "properties": {"kind": {"$ref": "#/$defs/Kind"},
                             "tags": {"anyOf": [{"type": "array", "items": {"type": "string"}}, {"type": "null"}],
                                      "default": None, "description": "e.g. ['x']"}}}
    assert described(schema) == {"kind": {"value": "fast", "source": "enum"},
                                 "tags": {"value": None, "source": "default"}}


def test_an_optional_argument_in_anyof_takes_its_description_example():
    spec = {"anyOf": [{"type": "string"}, {"type": "null"}], "description": "Region, e.g. 'eu-west-1'"}
    schema = {"type": "object", "properties": {"region": spec}}
    assert described(schema) == {"region": {"value": "eu-west-1", "source": "param-description"}}


# --- the extraction rule -------------------------------------------------------------

@pytest.mark.parametrize("text, token", [
    ("A name (e.g. 'notes')", "notes"),
    ('A name, eg. "notes"', "notes"),
    ("A name, for example `notes`.", "notes"),
    ("Example: 'notes'", "notes"),
    ("Formats such as 'csv' or 'json'", "csv"),
    ("FOR EXAMPLE 'Upper'", "Upper"),
    ("(e.g., 'America/New_York', 'Europe/London')", "America/New_York"),
    ("Some ids. The first one, e.g. 'b', is used.", "b"),
    ("Categories (e.g. ['cs.LG', 'cs.AI'])", "cs.LG"),
    ("e.g. the user's 'home' folder", "home"),  # the ' in user's is not a quote
    ("No example here. Use 'x' e.g. 'y'", "y"),
])
def test_the_first_quoted_token_after_a_marker(text, token):
    assert example_from_description(text) == token


@pytest.mark.parametrize("text", [
    None,
    "",
    "No marker: 'notes'",
    "Time to convert in 24-hour format (HH:MM)",
    "e.g. ''",                                   # empty
    "e.g. '   '",                                # only spaces
    "e.g. '" + "x" * (MAX_EXAMPLE_CHARS + 1) + "'",  # too long
    "e.g. 'first\nsecond'",                      # a newline inside
    "Something, e.g. a name. Later: 'notes'",    # the quote is in the next sentence
    "e.g. a name\n\nNext paragraph 'notes'",     # a blank line ends the sentence
    "e.g. it's fine",                            # an apostrophe isn't a token
    "e.g. 'unclosed",
])
def test_junk_is_rejected(text):
    assert example_from_description(text) is None


def test_the_200_character_cap_is_inclusive():
    token = "x" * MAX_EXAMPLE_CHARS
    assert example_from_description(f"e.g. '{token}'") == token


def test_a_rejected_first_marker_tries_the_next():
    assert example_from_description("e.g. something. Or, for example, 'two'") == "two"


@pytest.mark.parametrize("text, url", [
    ("Read https://docs.example/a.html.", "https://docs.example/a.html"),
    ("(see https://docs.example/a.html)", "https://docs.example/a.html"),
    ("Open 'http://x.example/p?q=1', then", "http://x.example/p?q=1"),
    ("ftp://no.example and https://yes.example/", "https://yes.example/"),
    ("no url here", None),
    (None, None),
    ("https://x.example/" + "a" * MAX_EXAMPLE_CHARS, None),
])
def test_first_url(text, url):
    assert first_url(text) == url


# --- coercion ----------------------------------------------------------------------

@pytest.mark.parametrize("token, schema, kind, value", [
    ("abc", {"type": "string"}, "string", "abc"),
    ("abc", {"type": "string", "maxLength": 2}, "string", NO_VALUE),
    ("ab", {"type": "string", "minLength": 3}, "string", NO_VALUE),
    ("abc", {"type": "string", "pattern": "^[0-9]+$"}, "string", NO_VALUE),
    ("42", {"type": "integer"}, "integer", 42),
    ("-3", {"type": "integer"}, "integer", -3),
    ("4.5", {"type": "integer"}, "integer", NO_VALUE),
    ("ten", {"type": "integer"}, "integer", NO_VALUE),
    ("200", {"type": "integer", "maximum": 100}, "integer", NO_VALUE),
    ("4.5", {"type": "number"}, "number", 4.5),
    ("7", {"type": "number"}, "number", 7.0),
    ("1e999", {"type": "number"}, "number", NO_VALUE),
    ("true", {"type": "boolean"}, "boolean", True),
    ("False", {"type": "boolean"}, "boolean", False),
    ("yes", {"type": "boolean"}, "boolean", NO_VALUE),
    ("cs.LG", {"type": "array", "items": {"type": "string"}}, "array", ["cs.LG"]),
    ("3", {"type": "array", "items": {"type": "integer"}}, "array", [3]),
    ("x", {"type": "array", "items": {"type": "integer"}}, "array", NO_VALUE),
    ("x", {"type": "array", "items": {"type": "string"}, "maxItems": 0}, "array", NO_VALUE),
    ("x", {"type": "array", "items": {"enum": ["a"]}}, "array", NO_VALUE),
    ("x", {"type": "object"}, "object", NO_VALUE),
])
def test_coercion(token, schema, kind, value):
    assert coerce(token, schema, kind, schema) == value


def test_a_failed_coercion_falls_through_to_the_next_source():
    # "e.g. 'ten'" can't be an integer: the bounds are used instead.
    assert one_arg({"type": "integer", "minimum": 2, "description": "Count, e.g. 'ten'"}) == {
        "value": 2, "source": "bounds"}
    assert one_arg({"type": "integer", "description": "Count, e.g. '25'"}) == {
        "value": 25, "source": "param-description"}
    # Too long for maxLength: the fallback.
    assert one_arg({"type": "string", "maxLength": 3, "description": "e.g. 'toolong'"}) == {
        "value": "hel", "source": "fallback"}


def test_an_unmatched_pattern_still_skips_the_tool():
    with pytest.raises(InputError, match="pattern"):
        build_inputs({"type": "object", "required": ["c"],
                      "properties": {"c": {"type": "string", "pattern": "^Q{9}$"}}}, "", "described")


@pytest.mark.parametrize("pattern", ["(", "a" * (MAX_EXAMPLE_CHARS + 1)])
def test_a_broken_or_huge_pattern_matches_nothing(pattern):
    with pytest.raises(InputError, match="pattern"):
        build_inputs({"type": "object", "required": ["c"],
                      "properties": {"c": {"type": "string", "pattern": pattern}}}, "", "described")


# --- the three modes ---------------------------------------------------------------

MIXED = {"type": "object", "required": ["name", "count", "ratio", "flag", "tags", "opts", "unit"], "properties": {
    "name": {"type": "string", "description": "e.g. 'notes'"},
    "count": {"type": "integer", "minimum": 5},
    "ratio": {"type": "number"},
    "flag": {"type": "boolean"},
    "tags": {"type": "array", "items": {"type": "string"}},
    "opts": {"type": "object", "properties": {"limit": {"type": "integer"}}},
    "unit": {"type": "string", "enum": ["celsius", "fahrenheit"]},
    "optional": {"type": "string", "format": "date"},
}}


def test_minimal_mode_required_arguments_plain_values():
    inputs = build_inputs(MIXED, "", "minimal")
    assert arguments_of(inputs) == {"name": "hello", "count": 0, "ratio": 0, "flag": False,
                                    "tags": [], "opts": {}, "unit": "hello"}
    assert {entry["source"] for entry in inputs.values()} == {"fallback"}


def test_minimal_mode_follows_refs_and_anyof_for_the_type():
    schema = {"type": "object", "required": ["a", "b", "c"], "$defs": {"N": {"type": "integer"}},
              "properties": {"a": {"$ref": "#/$defs/N"}, "b": {"anyOf": [{"type": "null"}, {"type": "array"}]},
                             "c": {"$ref": "#/$defs/Missing"}}}
    assert arguments_of(build_inputs(schema, "", "minimal")) == {"a": 0, "b": [], "c": "hello"}


def test_minimal_mode_lists_are_not_shared_between_calls():
    first = build_inputs(MIXED, "", "minimal")
    first["tags"]["value"].append("x")
    assert build_inputs(MIXED, "", "minimal")["tags"]["value"] == []


def test_schema_mode_is_exactly_build_arguments():
    for schema in (MIXED, GET_CURRENT_TIME, CONVERT_TIME, DOWNLOAD_PAPER, SEARCH_PAPERS, READ_DOCUMENTATION):
        assert arguments_of(build_inputs(schema, READ_DOCUMENTATION_TOOL, "schema")) == build_arguments(schema)


def test_schema_mode_records_its_sources():
    inputs = build_inputs(MIXED, "", "schema")
    assert {name: entry["source"] for name, entry in inputs.items()} == {
        "name": "fallback", "count": "bounds", "ratio": "fallback", "flag": "fallback", "tags": "fallback",
        "opts": "fallback", "unit": "enum", "optional": "format"}
    # The schema mode never reads descriptions: timezone stays "hello".
    assert build_inputs(GET_CURRENT_TIME, "", "schema") == {"timezone": {"value": "hello", "source": "fallback"}}


def test_schema_mode_skips_a_pattern_like_before():
    with pytest.raises(InputError, match="pattern"):
        build_inputs({"type": "object", "required": ["c"],
                      "properties": {"c": {"type": "string", "pattern": "^[A-Z]{3}$"}}}, "", "schema")


def test_described_mode_fills_every_argument():
    assert arguments_of(described(MIXED)) == {
        "name": "notes", "count": 5, "ratio": 1.0, "flag": False, "tags": ["hello"],
        "opts": {"limit": 1}, "unit": "celsius", "optional": "2024-01-15"}


def test_the_default_mode_is_described():
    assert DEFAULT_MODE == "described"
    assert build_inputs(GET_CURRENT_TIME) == build_inputs(GET_CURRENT_TIME, None, "described")


def test_an_unknown_mode_is_refused():
    with pytest.raises(ValueError, match="unknown input mode"):
        build_inputs(MIXED, "", "clever")


@pytest.mark.parametrize("mode", ["minimal", "schema", "described"])
def test_no_arguments_in_every_mode(mode):
    assert build_inputs({"type": "object", "properties": {}}, "", mode) == {}
    assert build_inputs({}, "", mode) == {}


def test_the_notes_fixtures_still_get_hello_in_every_mode():
    # The protected fixtures' read_note(name): no hints, so "hello" everywhere.
    read_note = {"type": "object", "required": ["name"], "title": "read_noteArguments",
                 "properties": {"name": {"title": "Name", "type": "string"}}}
    for mode in ("minimal", "schema", "described"):
        assert build_inputs(read_note, "Read a text note by name from the notes folder.", mode) == {
            "name": {"value": "hello", "source": "fallback"}}


# --- the CLI, the reproduce command and the report ----------------------------------

POLICY = PROJECT_ROOT / "policies" / "templates" / "no_network.v1.yaml"


@pytest.mark.parametrize("argv, mode", [([], "described"), (["--inputs", "minimal"], "minimal"),
                                        (["--inputs=schema"], "schema")])
def test_scan_passes_the_mode_on(monkeypatch, argv, mode):
    seen = {}
    monkeypatch.setattr(client, "run_scan", lambda *a: seen.update(args=a) or {"verdict": "CLEAN"})
    with pytest.raises(SystemExit):
        client.scan_main(["pypi:x@1.0", "--policy", str(POLICY), *argv])
    assert seen["args"][-1] == mode


def test_the_sandbox_run_passes_the_mode_on(monkeypatch):
    seen = {}
    monkeypatch.setattr(client, "run_sandboxed", lambda *a: seen.update(args=a) or {"verdict": "CLEAN"})
    server = PROJECT_ROOT / "test_servers" / "good_notes_server.py"
    monkeypatch.setattr("sys.argv", ["sandglass", str(server), "--policy", str(POLICY), "--sandbox",
                                     "--inputs", "minimal"])
    with pytest.raises(SystemExit):
        client.main()
    assert seen["args"][-1] == "minimal"


def test_an_unknown_mode_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as exc:
        client.scan_main(["pypi:x@1.0", "--policy", str(POLICY), "--inputs", "clever"])
    assert exc.value.code == 2
    assert "invalid choice: 'clever'" in capsys.readouterr().err


@pytest.mark.parametrize("mode", ["minimal", "schema", "described"])
def test_the_reproduce_command_names_the_mode(mode):
    setup = client.server_setup(["sandglass", "scan", "pypi:x@1.0", "--policy", "p.yaml"], ["stdio"], {}, mode)
    assert setup["inputs"] == mode
    assert setup["command"] == f"sandglass scan pypi:x@1.0 --policy p.yaml --inputs {mode} --server-arg=stdio"


def test_the_report_records_the_mode_and_every_source():
    setup = client.server_setup(["sandglass", "scan", "pypi:x@1.0", "--policy", "p.yaml"], [], {}, "described")
    inputs = {"get_current_time": {"timezone": {"value": "America/New_York", "source": "param-description"}}}
    session = {"tools": [{"name": "get_current_time"}], "inputs": inputs,
               "calls": [{"tool": "get_current_time", "arguments": {"timezone": "America/New_York"},
                          "status": "OK", "result": "12:00"}]}
    report = build_report("x", "t", sandbox_policy(), session, run([LAUNCH, NOTE_READ, EXITED], session=session),
                          Path("trace.txt"), {}, {"name": "b", "file": "f", "multiarch": "m"}, None, setup)
    assert report["input_mode"] == "described"
    assert report["inputs"] == inputs
    assert json.loads(json.dumps(report))["inputs"] == inputs  # JSON-safe
    md = _markdown(report)
    assert '- Inputs: `described` mode (where each value came from: "Tools exercised")' in md
    assert "| Tool | Input | Input sources | Status | Result |" in md
    assert ('| `get_current_time` | `{"timezone": "America/New_York"}` | `timezone`: param-description '
            "| OK | 12:00 |") in md
    assert "--inputs described" in md


def test_a_pipe_in_an_input_does_not_break_the_table():
    session = {"tools": [{"name": "t"}], "inputs": {"t": {"q": {"value": "a|b", "source": "param-description"}}},
               "calls": [{"tool": "t", "arguments": {"q": "a|b"}, "status": "OK", "result": "x"}]}
    report = build_report("x", "t", sandbox_policy(), session, run([LAUNCH, EXITED], session=session),
                          Path("trace.txt"), {}, {"name": "b", "file": "f", "multiarch": "m"})
    assert '| `t` | `{"q": "a\\|b"}` | `q`: param-description | OK | x |' in _markdown(report)
