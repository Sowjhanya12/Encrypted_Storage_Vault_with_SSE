"""
tests/test_textextract.py -- pure unit tests for client/textextract.py.

Same category as test_tokenizer.py / test_indexer.py (per the project's
own testing-strategy notes: "Unit: crypto.py, keymgmt.py, tokenizer.py,
indexer.py, search.py -- pure functions, no network"). No Flask app, no
live cloud -- just bytes in, text (or None) out.

_make_minimal_pdf() below hand-builds a tiny, valid single-page PDF
containing one text-showing operator, without pulling in a full PDF-
generation dependency (e.g. reportlab) just to produce test input --
this project already adds one new dependency for this feature
(pypdf, for *reading* PDFs); it does not need a second one just to
*write* a two-line test fixture.
"""

import io
import os
import sys
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import client.textextract as textextract  # noqa: E402
from client.textextract import (  # noqa: E402
    extract_indexable_text,
    extract_pdf_text,
    extract_zip_text,
    is_pdf,
    is_zip,
)


def _make_zip(files: "dict[str, bytes]") -> bytes:
    """A real zip archive (via the standard library's own writer, not
    hand-built) containing one entry per `files` key/value."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _make_minimal_pdf(text: str = "") -> bytes:
    """A minimal, valid single-page PDF whose content stream shows
    `text` (or nothing, if `text` is empty) via one Tj operator.
    Byte offsets in the xref table are computed for real, so this is a
    well-formed PDF, not a truncated/fake one."""
    content = f"BT /F1 18 Tf 10 100 Td ({text}) Tj ET".encode("latin-1")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> "
        b"/MediaBox [0 0 300 200] /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(content)).encode("ascii") + b" >>\nstream\n" + content + b"\nendstream",
    ]

    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = [0]
    for i, obj in enumerate(objects, start=1):
        offsets.append(out.tell())
        out.write(f"{i} 0 obj\n".encode("ascii"))
        out.write(obj)
        out.write(b"\nendobj\n")
    xref_offset = out.tell()
    n = len(objects) + 1
    out.write(f"xref\n0 {n}\n".encode("ascii"))
    out.write(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        out.write(f"{off:010d} 00000 n \n".encode("ascii"))
    out.write(f"trailer\n<< /Size {n} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF".encode("ascii"))
    return out.getvalue()


# ---------------------------------------------------------------------------
# is_pdf
# ---------------------------------------------------------------------------

class TestIsPdf:
    def test_detects_pdf_magic_bytes(self):
        assert is_pdf(_make_minimal_pdf("hello")) is True

    def test_utf8_text_is_not_a_pdf(self):
        assert is_pdf("quarterly report".encode("utf-8")) is False

    def test_arbitrary_binary_is_not_a_pdf(self):
        assert is_pdf(b"\xff\xfe\x00\x01binary garbage") is False


# ---------------------------------------------------------------------------
# extract_pdf_text
# ---------------------------------------------------------------------------

class TestExtractPdfText:
    def test_extracts_real_text(self):
        pdf_bytes = _make_minimal_pdf("searchablepdfkeyword tokentwo")
        assert extract_pdf_text(pdf_bytes) == "searchablepdfkeyword tokentwo"

    def test_empty_text_layer_returns_empty_string_not_none(self):
        # A page with no text-showing operator at all -- the PDF
        # analogue of an empty .txt file: valid, storable, zero
        # keywords, not a rejected upload.
        pdf_bytes = _make_minimal_pdf("")
        assert extract_pdf_text(pdf_bytes) == ""

    def test_corrupted_pdf_bytes_return_none(self):
        assert extract_pdf_text(b"%PDF-1.4\nthis is not a real pdf body at all") is None

    def test_non_pdf_bytes_return_none(self):
        assert extract_pdf_text(b"not a pdf") is None


# ---------------------------------------------------------------------------
# extract_indexable_text -- the single entry point client_app.py calls
# ---------------------------------------------------------------------------

class TestExtractIndexableText:
    def test_utf8_text_passthrough(self):
        raw = "quarterly financial report".encode("utf-8")
        assert extract_indexable_text(raw) == "quarterly financial report"

    def test_pdf_extracts_text(self):
        pdf_bytes = _make_minimal_pdf("board meeting minutes")
        assert extract_indexable_text(pdf_bytes) == "board meeting minutes"

    def test_pdf_with_no_text_layer_returns_empty_string(self):
        assert extract_indexable_text(_make_minimal_pdf("")) == ""

    def test_non_utf8_non_pdf_binary_returns_none(self):
        assert extract_indexable_text(b"\xff\xfe\x00\x01binary garbage") is None

    def test_corrupted_pdf_bytes_return_none(self):
        assert extract_indexable_text(b"%PDF-1.4\nnot actually a valid pdf body") is None

    def test_zip_delegates_to_extract_zip_text(self):
        zip_bytes = _make_zip({"notes.txt": b"quarterly board minutes"})
        assert extract_indexable_text(zip_bytes) == "quarterly board minutes"


# ---------------------------------------------------------------------------
# is_zip
# ---------------------------------------------------------------------------

class TestIsZip:
    def test_detects_a_real_zip(self):
        assert is_zip(_make_zip({"a.txt": b"hello"})) is True

    def test_utf8_text_is_not_a_zip(self):
        assert is_zip(b"quarterly report") is False

    def test_pdf_is_not_a_zip(self):
        assert is_zip(_make_minimal_pdf("x")) is False

    def test_truncated_garbage_starting_with_pk_is_not_a_zip(self):
        # A real structural check (looks for the end-of-central-
        # directory record), not a naive "starts with PK" guess.
        assert is_zip(b"PK\x03\x04not actually a real zip body") is False


# ---------------------------------------------------------------------------
# extract_zip_text
# ---------------------------------------------------------------------------

class TestExtractZipText:
    def test_extracts_text_from_a_single_txt_member(self):
        zip_bytes = _make_zip({"notes.txt": b"searchablezipkeyword"})
        assert extract_zip_text(zip_bytes) == "searchablezipkeyword"

    def test_combines_text_from_multiple_members(self):
        zip_bytes = _make_zip({
            "a.txt": b"alpha keyword",
            "b.txt": b"beta keyword",
        })
        text = extract_zip_text(zip_bytes)
        assert "alpha keyword" in text
        assert "beta keyword" in text

    def test_extracts_text_from_a_pdf_member(self):
        zip_bytes = _make_zip({"report.pdf": _make_minimal_pdf("pdfinsidezipkeyword")})
        assert extract_zip_text(zip_bytes) == "pdfinsidezipkeyword"

    def test_unreadable_member_is_skipped_not_fatal(self):
        zip_bytes = _make_zip({
            "photo.png": b"\x89PNG\r\n\x1a\nnot really a png but binary-ish",
            "notes.txt": b"readablekeyword",
        })
        assert extract_zip_text(zip_bytes) == "readablekeyword"

    def test_zip_of_only_unreadable_members_returns_empty_string_not_none(self):
        zip_bytes = _make_zip({"photo.png": b"\xff\xfe\x00\x01binary garbage"})
        assert extract_zip_text(zip_bytes) == ""

    def test_directory_entries_are_not_treated_as_members(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("folder/", b"")  # a directory entry, no content
            zf.writestr("folder/notes.txt", b"nested folder keyword")
        assert extract_zip_text(buf.getvalue()) == "nested folder keyword"

    def test_corrupted_zip_bytes_return_none(self):
        assert extract_zip_text(b"not a zip at all") is None

    def test_office_document_disguised_as_zip_is_rejected(self):
        # Every real .docx/.pptx/.xlsx carries this exact member --
        # simulating just enough of one to trigger the OOXML guard.
        zip_bytes = _make_zip({
            "[Content_Types].xml": b"<Types xmlns='http://example/content-types'/>",
            "word/document.xml": b"<w:document>some document body text</w:document>",
        })
        assert extract_zip_text(zip_bytes) is None

    def test_nested_zip_member_is_skipped_not_recursed(self):
        inner_zip = _make_zip({"secret.txt": b"nestedzipkeyword"})
        outer_zip = _make_zip({
            "inner.zip": inner_zip,
            "outer.txt": b"outerzipkeyword",
        })
        text = extract_zip_text(outer_zip)
        assert "outerzipkeyword" in text
        assert "nestedzipkeyword" not in text

    def test_too_many_members_is_rejected(self, monkeypatch):
        monkeypatch.setattr(textextract, "MAX_ZIP_MEMBERS", 2)
        zip_bytes = _make_zip({"a.txt": b"a", "b.txt": b"b", "c.txt": b"c"})
        assert extract_zip_text(zip_bytes) is None

    def test_oversized_total_content_is_rejected(self, monkeypatch):
        monkeypatch.setattr(textextract, "MAX_ZIP_UNCOMPRESSED_BYTES", 10)
        zip_bytes = _make_zip({"big.txt": b"x" * 1000})
        assert extract_zip_text(zip_bytes) is None
