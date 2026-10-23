"""Tracing can be detected (#82): a known limitation, stated in every report."""

from pathlib import Path

from sandglass import PROJECT_ROOT
from sandglass.compare import TRACING_NOTE, _markdown, build_report, not_run
from tests.test_sandbox_pipeline import EXITED, LAUNCH, run, sandbox_policy

BASELINE = {"name": "b", "file": "f", "multiarch": "m"}


def test_every_report_has_the_tracing_note():
    fixture = build_report("x", "t", sandbox_policy(), {"tools": [], "calls": []},
                           run([LAUNCH, EXITED]), Path("trace.txt"), {}, BASELINE)
    scan_not_run = build_report("pypi_x_1", "t", sandbox_policy(), {"tools": [], "calls": []},
                                not_run("pip download failed"), None, {}, BASELINE,
                                {"spec": "pypi:x@1", "source": "PyPI", "files": [], "entry": None})
    for report in (fixture, scan_not_run):
        assert report["tracing_note"] == TRACING_NOTE
        assert f"- Note: {TRACING_NOTE}" in _markdown(report)


def test_the_note_says_what_clean_means():
    assert "TracerPid" in TRACING_NOTE and "CLEAN verdict only covers what it did while traced" in TRACING_NOTE


def test_readme_documents_the_limitation():
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    limitations = readme[readme.index("## Known limitations"):]
    assert "TracerPid" in limitations and "#82" in limitations
