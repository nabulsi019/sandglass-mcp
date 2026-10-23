"""The trace is read line by line, with a size limit (#83)."""

import inspect

from sandglass import client, trace_parser
from sandglass.compare import compare
from sandglass.trace_parser import parse_trace, parse_trace_file
from tests.test_sandbox_pipeline import (EXITED, LAUNCH, NOTE_READ, RELAY_END, RELAY_START,
                                         SESSION_OK, SINK_LINES, TOOL_CALL, sandbox_policy)

# A complete, clean run (what run() in test_sandbox_pipeline builds).
CLEAN_RUN = [LAUNCH] + SINK_LINES + RELAY_START + [NOTE_READ, TOOL_CALL] + RELAY_END + [EXITED]


def write(tmp_path, lines):
    path = tmp_path / "trace.txt"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_file_parsed_line_by_line_gives_the_same_events(tmp_path):
    events, cut_short = parse_trace_file(write(tmp_path, CLEAN_RUN))
    assert events == parse_trace("\n".join(CLEAN_RUN))
    assert cut_short is False


def test_a_missing_trace_file_gives_no_events(tmp_path):
    assert parse_trace_file(tmp_path / "nope.txt") == ([], False)


def test_reading_stops_at_the_limit(tmp_path):
    path = write(tmp_path, CLEAN_RUN)
    # A limit that ends inside the 3rd line: only 2 whole lines are kept.
    limit = sum(len(line) + 1 for line in CLEAN_RUN[:2]) + 5
    events, cut_short = parse_trace_file(path, max_bytes=limit)
    assert cut_short is True
    assert events == parse_trace("\n".join(CLEAN_RUN[:2]))


def test_a_trace_cut_short_is_incomplete_never_clean(tmp_path):
    events, _ = parse_trace_file(write(tmp_path, CLEAN_RUN))
    assert compare(events, sandbox_policy(), SESSION_OK)["verdict"] == "CLEAN"
    result = compare(events, sandbox_policy(), SESSION_OK, trace_cut_short=True)
    assert result["verdict"] == "INCOMPLETE"
    assert result["incomplete_reasons"] == [
        "the trace is larger than 256 MiB; only the first 256 MiB were checked, so later events are missing"]


def test_the_client_never_reads_the_whole_trace_at_once():
    source = inspect.getsource(client._trace_and_report)  # used by fixtures and scans
    assert "parse_trace_file(" in source and "read_text" not in source
    assert trace_parser.MAX_TRACE_BYTES == 256 * 1024 * 1024
