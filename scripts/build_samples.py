"""Write the deep scan's sample files (#171). Standard library only.

    python scripts/build_samples.py <folder>

The Dockerfile runs this at image build, into /usr/local/lib/mcp-runtime/samples/,
then adds a small git repository there (repo/). A deep scan copies the
folder to /tmp/work/samples before tracing starts, and a tool whose argument
asks for a path gets one of these files (sandglass/inputs.py, sample_inputs).

Every file has fixed content, is under about 10 KB, and is the same on every
build (no timestamps, no randomness). Harmless text only: no credentials, no
secrets, no name that tells the server who is testing it.
"""

import json
import struct
import sys
import zipfile
import zlib
from pathlib import Path

# The text every format carries: a short, ordinary note.
NOTE_TITLE = "Sample note"
NOTE_LINES = ["This is a sample note.", "It has a few lines of plain text.", "Line three."]
# A fixed date for the zip entries (zip has no "no date"), so builds are repeatable.
ZIP_DATE = (2026, 1, 1, 0, 0, 0)


def notes_txt() -> bytes:
    return ("\n".join([NOTE_TITLE, ""] + NOTE_LINES) + "\n").encode()


def notes_md() -> bytes:
    return ("\n".join([f"# {NOTE_TITLE}", ""] + [f"- {line}" for line in NOTE_LINES]) + "\n").encode()


def table_csv() -> bytes:
    rows = [["id", "name", "amount"], ["1", "apples", "3"], ["2", "pears", "5"], ["3", "plums", "7"]]
    return "".join(",".join(row) + "\n" for row in rows).encode()


def data_json() -> bytes:
    data = {"title": NOTE_TITLE, "items": [{"id": 1, "name": "apples"}, {"id": 2, "name": "pears"}]}
    return (json.dumps(data, indent=2) + "\n").encode()


# A minimal .xlsx: the five parts Excel and openpyxl need, one sheet "Sheet1".
XLSX_PARTS = {
    "[Content_Types].xml": (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        '</Types>'),
    "_rels/.rels": (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Target="xl/workbook.xml" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"/>'
        '</Relationships>'),
    "xl/workbook.xml": (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>'),
    "xl/_rels/workbook.xml.rels": (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Target="worksheets/sheet1.xml" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"/>'
        '</Relationships>'),
    "xl/worksheets/sheet1.xml": (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>'
        '<row r="1"><c r="A1" t="inlineStr"><is><t>name</t></is></c>'
        '<c r="B1" t="inlineStr"><is><t>amount</t></is></c></row>'
        '<row r="2"><c r="A2" t="inlineStr"><is><t>apples</t></is></c><c r="B2"><v>3</v></c></row>'
        '<row r="3"><c r="A3" t="inlineStr"><is><t>pears</t></is></c><c r="B3"><v>5</v></c></row>'
        '</sheetData></worksheet>'),
}


def book_xlsx(path: Path) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, text in XLSX_PARTS.items():
            info = zipfile.ZipInfo(name, ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, text)


def doc_pdf() -> bytes:
    """A one-page PDF with one line of text, hand-written. The cross-reference
    table needs each object's byte offset, so they are counted as it's built."""
    text = f"BT /F1 12 Tf 72 720 Td ({NOTE_TITLE}: {NOTE_LINES[0]}) Tj ET"
    objects = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        "/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        f"<< /Length {len(text)} >>\nstream\n{text}\nendstream",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = b"%PDF-1.4\n"
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n{body}\nendobj\n".encode()
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    out += "".join(f"{offset:010d} 00000 n \n" for offset in offsets).encode()
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return out


def image_png() -> bytes:
    """An 8 x 8 grey square, 8-bit greyscale, written chunk by chunk."""
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    width = height = 8
    header = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)  # 8-bit greyscale
    rows = b"".join(b"\x00" + bytes([128] * width) for _ in range(height))  # filter byte 0 per row
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(rows, 9)) + \
        chunk(b"IEND", b"")


# file name -> the function that returns its bytes (book.xlsx is written by book_xlsx)
SAMPLES = {
    "notes.txt": notes_txt,
    "notes.md": notes_md,
    "table.csv": table_csv,
    "data.json": data_json,
    "doc.pdf": doc_pdf,
    "image.png": image_png,
}


def build(folder: Path) -> list[Path]:
    """Write every sample into `folder` (made if missing); return their paths."""
    folder.mkdir(parents=True, exist_ok=True)
    written = []
    for name, make in SAMPLES.items():
        path = folder / name
        path.write_bytes(make())
        written.append(path)
    book_xlsx(folder / "book.xlsx")
    written.append(folder / "book.xlsx")
    return written


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python scripts/build_samples.py <folder>")
    for path in build(Path(sys.argv[1])):
        print(f"{path} ({path.stat().st_size} bytes)")
