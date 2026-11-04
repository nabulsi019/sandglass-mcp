"""The depth label and the KB sizes (#174).

Every report says which scan ran, in the terminal summary and the Markdown
header, with the owner's wording; a download under 0.1 MB reads in KB.
Report text only: the verdict never depends on either.
"""

import pytest

from sandglass.compare import DEPTH_LABELS, _markdown, _size, depth_line, duration_line, summary_lines
from tests.test_deep_budget import report_for

KB = 1024
MB = 1024 * 1024
DURATIONS = {"total": 2.0, "download": 0.5, "install": None, "run": 1.0, "analysis": 0.5}


def test_the_wording_is_exact():
    assert DEPTH_LABELS == {"quick": "quick scan: a first look",
                            "deep": "deep scan: recommended before approving a server"}


@pytest.mark.parametrize("depth", ["quick", "deep"])
def test_the_label_in_the_terminal_and_the_markdown(depth):
    report = report_for(depth, {"seconds": 120, "per_tool": 30, "tools": 1} if depth == "deep" else None)
    report["durations"] = DURATIONS
    lines = summary_lines(report)
    label = f"Depth: {DEPTH_LABELS[depth]}"
    # Verdict first, Depth just before Duration, Duration last.
    assert lines[0].startswith("Verdict: ")
    assert lines[-2] == label
    assert lines[-1].startswith("Duration: ")
    assert f"\n- {label}\n" in _markdown(report)


def test_without_durations_the_label_is_last():
    report = report_for("quick")
    assert summary_lines(report)[-1] == "Depth: quick scan: a first look"


def test_a_report_without_depth_was_a_quick_scan():
    assert depth_line({}) == "Depth: quick scan: a first look"


def test_the_verdict_is_the_same_whichever_label():
    assert report_for("quick")["verdict"] == report_for("deep", {"seconds": 120, "per_tool": 30,
                                                                  "tools": 1})["verdict"]


@pytest.mark.parametrize("size, text", [
    (1, "1 KB"),                       # at least 1 KB
    (3 * KB, "3 KB"),
    (int(0.1 * MB) - 1, "102 KB"),     # just under 0.1 MB
    (int(0.1 * MB) + 1, "0.1 MB"),     # at 0.1 MB
    (10 * MB - 1, "10.0 MB"),          # just under 10 MB: one decimal (rounds up)
    (int(9.5 * MB), "9.5 MB"),
    (10 * MB, "10 MB"),                # at 10 MB: whole MB
    (int(114.6 * MB), "114 MB"),       # markitdown's 114.6 MB, still 114 MB
])
def test_size_boundaries(size, text):
    assert _size([{"size": size}]) == text


def test_the_test_packages_read_in_kb():
    # Our test packages are a few KB: "download 0.5 s (3 KB)", not "(0.0 MB)".
    assert duration_line(DURATIONS, [{"size": 3 * KB}]) == "Duration: 2.0 s (download 0.5 s (3 KB), run 1.0, analysis 0.5)"
