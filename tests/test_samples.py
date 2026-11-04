"""Sample files and a sample git repo for deep scans (#171).

The samples themselves (scripts/build_samples.py, the Dockerfile's repo),
the deep-only copy step in the sandbox's sh script, which sample a tool's
argument gets (sandglass/inputs.py), and how reads of samples are judged
(sandglass/compare.py): only reads of the exact sample paths Sandglass passed
in, or of files under a passed directory; writes and programs run as usual.
"""

import asyncio
import csv
import importlib.util
import io
import json
import re
import subprocess
import sys
import zipfile
import zlib
from pathlib import Path
from xml.etree import ElementTree

import pytest
from mcp import StdioServerParameters

from sandglass import PROJECT_ROOT, client, sandbox
from sandglass.inputs import SAMPLES_DIR, choose_sample, sample_inputs, sample_path
from tests.test_sandbox_pipeline import EXITED, LAUNCH, run

spec = importlib.util.spec_from_file_location("build_samples", PROJECT_ROOT / "scripts" / "build_samples.py")
build_samples = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_samples)

SERVER = PROJECT_ROOT / "test_servers" / "sample_reader_server.py"
DOCKERFILE = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")
NAMES = {"notes.txt", "notes.md", "table.csv", "data.json", "book.xlsx", "doc.pdf", "image.png"}


# --- the samples ----------------------------------------------------------------

def test_the_build_is_repeatable(tmp_path):
    first = {p.name: p.read_bytes() for p in build_samples.build(tmp_path / "a")}
    second = {p.name: p.read_bytes() for p in build_samples.build(tmp_path / "b")}
    assert set(first) == NAMES
    assert first == second


def test_each_sample_is_small_and_parses(tmp_path):
    files = {p.name: p.read_bytes() for p in build_samples.build(tmp_path)}
    assert all(len(data) < 10 * 1024 for data in files.values())
    assert files["notes.txt"].decode().startswith("Sample note")
    assert files["notes.md"].decode().startswith("# Sample note")
    assert list(csv.reader(io.StringIO(files["table.csv"].decode())))[0] == ["id", "name", "amount"]
    assert json.loads(files["data.json"])["title"] == "Sample note"
    with zipfile.ZipFile(io.BytesIO(files["book.xlsx"])) as book:
        for name in book.namelist():
            ElementTree.fromstring(book.read(name))  # every part is well-formed XML
        assert "xl/worksheets/sheet1.xml" in book.namelist()
    pdf = files["doc.pdf"]
    assert pdf.startswith(b"%PDF-1.4") and pdf.rstrip().endswith(b"%%EOF")
    # Every offset in the cross-reference table points at its object.
    xref = int(pdf.rsplit(b"startxref\n", 1)[1].split()[0])
    offsets = [int(line.split()[0]) for line in pdf[xref:].split(b"\n")[3:8]]
    assert [pdf[o:].split(b" ", 1)[0] for o in offsets] == [b"1", b"2", b"3", b"4", b"5"]
    png = files["image.png"]
    assert png.startswith(b"\x89PNG\r\n\x1a\n")
    idat = png[png.index(b"IDAT") + 4:png.index(b"IEND") - 8]
    assert len(zlib.decompress(idat)) == 8 * (8 + 1)  # 8 rows of a filter byte + 8 pixels


def test_no_sample_looks_like_a_credential_or_names_sandglass(tmp_path):
    for path in build_samples.build(tmp_path):
        text = path.read_bytes().decode("latin-1")
        for word in ("AKIA", "PRIVATE KEY", "password", "secret", "token"):
            assert word.lower() not in text.lower(), f"{path.name} contains {word!r}"
        assert "sandglass" not in text.lower()  # (#159) nothing that names the tester


def test_the_image_builds_the_samples_and_a_two_commit_repo():
    block = DOCKERFILE[DOCKERFILE.index("COPY scripts/build_samples.py"):DOCKERFILE.index("USER 10001:10001")]
    assert f"python /tmp/build_samples.py {sandbox.IMAGE_SAMPLES}" in block
    assert "rm /tmp/build_samples.py" in block  # the script itself isn't kept
    assert block.count("git commit") == 2
    assert 'GIT_AUTHOR_NAME="Sample Author" GIT_AUTHOR_EMAIL="sample@example.com"' in block
    assert re.findall(r'GIT_AUTHOR_DATE="([^"]+)"', block) == ["2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"]
    # Built as root, before the image switches to the sandbox user: read-only for the server.
    assert DOCKERFILE.index("COPY scripts/build_samples.py") < DOCKERFILE.rindex("USER 10001:10001")


# --- the copy step: deep only ----------------------------------------------------------

def test_quick_has_no_copy_step():
    quick = sandbox.docker_command(SERVER)[1]
    assert "cp -R" not in " ".join(quick)
    assert quick == sandbox.docker_command(SERVER, samples=False)[1]


def test_deep_copies_the_samples_before_strace(tmp_path):
    # The real sh script with a fake `strace`, a fake image folder and the
    # work dir moved into tmp_path: the copy is made before strace starts.
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    strace = fake_bin / "strace"
    strace.write_text(f"#!{sys.executable}\nimport os\nprint(sorted(os.listdir('samples')))\n")
    strace.chmod(0o755)
    image = tmp_path / "image-samples"
    build_samples.build(image)
    args = sandbox.docker_command(SERVER, samples=True)[1]
    i = args.index("sh")
    workdir = tmp_path / "work"
    script = (args[i + 2].replace(str(sandbox.IMAGE_SAMPLES), str(image))
              .replace(str(sandbox.CONTAINER_WORKDIR), str(workdir)))
    assert script.index("cp -R") < script.index("exec strace")
    out = subprocess.run(["sh", "-c", script, *args[i + 3:]], capture_output=True, text=True,
                         cwd=tmp_path, env={"PATH": f"{fake_bin}:/usr/bin:/bin"}, check=True)
    assert out.stdout.strip() == str(sorted(NAMES))


def test_the_sample_folder_matches_the_inputs():
    assert str(sandbox.CONTAINER_SAMPLES) == SAMPLES_DIR == "/tmp/work/samples"


# --- which sample an argument gets ------------------------------------------------------

def schema(**properties):
    return {"type": "object", "properties": properties, "required": list(properties)}


STRING = {"type": "string"}


@pytest.mark.parametrize("texts, sample", [
    (("filepath Path to the Excel file",), "book.xlsx"),
    (("path", "convert_pdf Convert a PDF"), "doc.pdf"),
    (("csv_path",), "table.csv"),
    (("path", "load_json"), "data.json"),
    (("path The markdown file",), "notes.md"),
    (("image_path",), "image.png"),
    (("repo_path",), "repo"),
    (("repoPath",), "repo"),
    (("directory",), ""),
    (("path", "read_text Read a file"), "notes.txt"),
])
def test_file_choice_per_word(texts, sample):
    assert choose_sample(*texts) == (f"{SAMPLES_DIR}/{sample}" if sample else SAMPLES_DIR)


def test_the_argument_text_wins_over_the_tool_text():
    # The argument says csv, the tool says excel: the argument's word wins.
    inputs = sample_inputs(schema(csv_file=STRING), "Export to Excel.", "export")
    assert inputs == {"csv_file": {"value": f"{SAMPLES_DIR}/table.csv", "source": "sample-file"}}


def test_only_path_like_string_arguments():
    inputs = sample_inputs(schema(path=STRING, name=STRING, count={"type": "integer"},
                                  file_count={"type": "integer"}), "", "tool")
    assert set(inputs) == {"path"}


def test_uris_are_file_uris():
    assert sample_inputs(schema(uri=STRING), "Convert a URI to markdown.", "convert")["uri"]["value"] == \
        f"file://{SAMPLES_DIR}/notes.md"
    assert sample_inputs(schema(source={"type": "string", "format": "uri"}), "", "t")["source"]["value"] == \
        f"file://{SAMPLES_DIR}/notes.txt"


def test_a_url_stays_a_web_url_unless_the_text_names_file():
    assert sample_inputs(schema(url=STRING), "Fetch https://example.com/ pages.", "fetch") == {}
    assert sample_inputs(schema(url=STRING), "Load an http: or file: URL.", "load")["url"]["value"] == \
        f"file://{SAMPLES_DIR}/notes.txt"


def test_a_const_or_enum_is_kept():
    assert sample_inputs(schema(path={"type": "string", "enum": ["/data"]}), "", "t") == {}
    assert sample_inputs(schema(path={"type": "string", "const": "/data"}), "", "t") == {}


@pytest.mark.parametrize("description", [
    "Path to read, e.g. '/home/sandglass/.aws/credentials'",
    "Read /etc/passwd or ../../secrets (file: /root/x)",
])
def test_a_description_can_never_choose_a_path(description):
    # The server's text only picks among the fixed samples.
    value = sample_inputs({"type": "object", "properties": {"path": {"type": "string", "description": description}}},
                          description, "read")["path"]["value"]
    assert sample_path(value) is not None
    assert value.removeprefix("file://").removeprefix(SAMPLES_DIR).lstrip("/") in NAMES | {"repo", ""}


def test_sample_path():
    assert sample_path(f"file://{SAMPLES_DIR}/repo") == f"{SAMPLES_DIR}/repo"
    assert sample_path(f"{SAMPLES_DIR}/notes.txt") == f"{SAMPLES_DIR}/notes.txt"
    assert sample_path("/tmp/work/samplesX") is None and sample_path("hello") is None and sample_path(3) is None


# --- the client: deep passes samples and records them -------------------------------------

def host_session(depth: str) -> dict:
    """One session with sample_reader_server.py on the host (no Docker, so
    the samples don't exist there: the calls return errors, which is fine)."""
    params = StdioServerParameters(command=sys.executable, args=[str(SERVER)])
    return asyncio.run(client.run(params, "sample_reader_server", depth=depth))


def test_deep_passes_samples_and_records_them():
    record = host_session("deep")
    # (#172) The sample-file variant of each tool, among its other calls.
    assert [c["arguments"] for c in record["calls"] if c["variant"] == "sample-file"] == [
        {"path": f"{SAMPLES_DIR}/notes.txt"}, {"repo_path": f"{SAMPLES_DIR}/repo"},
        {"path": f"{SAMPLES_DIR}/notes.txt"}]
    assert record["sample_paths"] == [f"{SAMPLES_DIR}/notes.txt", f"{SAMPLES_DIR}/repo"]
    sample_call = next(c for c in record["calls"] if c["tool"] == "repo_head" and c["variant"] == "sample-file")
    assert sample_call["inputs"]["repo_path"]["source"] == "sample-file"


def test_quick_passes_no_samples():
    record = host_session("quick")
    assert [c["arguments"] for c in record["calls"]] == [{"path": "hello"}, {"repo_path": "hello"},
                                                          {"path": "hello"}]
    assert "sample_paths" not in record


# --- how reads of samples are judged (the owner's boundaries) ---------------------------

def read_line(path: str, mode: str = "O_RDONLY") -> str:
    return f'10 10:00:00.000100 openat(AT_FDCWD, "{path}", {mode}|O_CLOEXEC) = 8'


PASSED = {"tools": [{"name": "t"}], "calls": [{"tool": "t"}],
          "sample_paths": [f"{SAMPLES_DIR}/notes.txt", f"{SAMPLES_DIR}/repo"]}


def judged(*lines: str, session: dict = PASSED) -> tuple[list, list]:
    """(violations, sample reads) of a trace under notes_readonly, which allows none of /tmp."""
    result = run([LAUNCH, *lines, EXITED], session=session)
    return [(v["mode"], v["target"]) for v in result["violations"]], [v["target"] for v in result["sample_reads"]]


def test_a_passed_file_and_files_under_a_passed_directory_are_sample_reads():
    violations, reads = judged(read_line(f"{SAMPLES_DIR}/notes.txt"), read_line(f"{SAMPLES_DIR}/repo/.git/HEAD"))
    assert violations == []
    assert reads == [f"{SAMPLES_DIR}/notes.txt", f"{SAMPLES_DIR}/repo/.git/HEAD"]


def test_a_sample_that_was_not_passed_is_judged_normally():
    violations, reads = judged(read_line(f"{SAMPLES_DIR}/table.csv"))
    assert violations == [("read", f"{SAMPLES_DIR}/table.csv")] and reads == []


def test_a_write_under_a_passed_directory_is_judged_normally():
    violations, reads = judged(read_line(f"{SAMPLES_DIR}/repo/x", "O_WRONLY|O_CREAT|O_TRUNC"),
                               read_line(f"{SAMPLES_DIR}/notes.txt", "O_RDWR"))
    assert violations == [("write", f"{SAMPLES_DIR}/repo/x"), ("write", f"{SAMPLES_DIR}/notes.txt")]
    assert reads == []


def test_running_a_program_from_a_passed_directory_is_judged_normally():
    run_it = (f'10 10:00:00.000200 execve("{SAMPLES_DIR}/repo/hook", ["{SAMPLES_DIR}/repo/hook"],'
              ' 0x0 /* 8 vars */) = 0')
    violations, _ = judged(run_it)
    assert violations == [(None, f"{SAMPLES_DIR}/repo/hook")]


def test_a_passed_file_does_not_cover_its_neighbours_or_its_folder():
    violations, reads = judged(read_line(f"{SAMPLES_DIR}/notes.txt.copy"), read_line(SAMPLES_DIR, "O_RDONLY|O_DIRECTORY"))
    assert violations == [("read", f"{SAMPLES_DIR}/notes.txt.copy"), ("list", SAMPLES_DIR)] and reads == []


def test_a_read_through_a_symlink_to_elsewhere_is_judged_normally():
    # Requested a passed sample, really opened the credentials (strace -y): a violation.
    line = (f'10 10:00:00.000100 openat(AT_FDCWD, "{SAMPLES_DIR}/notes.txt", O_RDONLY|O_CLOEXEC)'
            ' = 8</home/sandglass/.aws/credentials>')
    violations, reads = judged(line)
    # One record per open, naming the first bad path (#122); never a sample read.
    assert violations == [("read", f"{SAMPLES_DIR}/notes.txt")] and reads == []
    result = run([LAUNCH, line, EXITED], session=PASSED)
    assert "opened /home/sandglass/.aws/credentials" in result["violations"][0]["reason"]


def test_without_passed_samples_nothing_changes():
    # Quick runs have no sample_paths: every read is judged as before.
    session = {"tools": [{"name": "t"}], "calls": [{"tool": "t"}]}
    violations, reads = judged(read_line(f"{SAMPLES_DIR}/notes.txt"), session=session)
    assert violations == [("read", f"{SAMPLES_DIR}/notes.txt")] and reads == []
