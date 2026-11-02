"""
client/textextract.py -- turns raw uploaded bytes into indexable text.

Section 05's tokenizer needs a Python `str`; an uploaded file only ever
arrives as raw bytes. This module is the ONE place that decides how to
get from "bytes on disk" to "text tokenize() can chew on" for every
file type this project accepts -- both client_app.py's upload route
and its index-rebuild path call this instead of each re-deciding the
question separately (the same "one shared function" discipline
tokenizer.py's own docstring insists on for keyword extraction itself).

Three source formats are supported:

  * UTF-8 text -- the original format. Decoded directly.
  * PDF -- detected by its own magic bytes (b"%PDF-", ISO 32000-1
    7.5.2), not by filename extension, since a filename is just a
    string the uploader chose and proves nothing about the bytes.
    Text is extracted per-page with `pypdf` and joined with newlines.
    A PDF that is scanned page images with no text layer (no OCR)
    extracts to an empty string -- that is not an error, the document
    just contributes zero keywords to the index, exactly like
    uploading an empty .txt file would.
  * ZIP -- detected with the standard library's own zipfile.is_zipfile
    (a real structural check, not a naive magic-byte guess). Every
    file inside is read and run through the SAME UTF-8/PDF detection
    above (never re-implemented per format), and every extracted
    piece of text is joined into one indexable blob for the zip as a
    whole -- the zip stays ONE vault document, exactly like a .txt or
    .pdf, not one document per file inside it. A file inside the zip
    that isn't UTF-8 or PDF is skipped, not fatal, exactly like a
    scanned PDF page: the zip still uploads, that one member just
    contributes no keywords. Three deliberate limits, each documented
    at its check below: no recursion into a zip nested inside a zip,
    a real Word/Excel/PowerPoint file (itself a zip, per OOXML) is
    rejected rather than mis-indexed as XML noise, and a cap on member
    count / total uncompressed size guards against a decompression
    ("zip bomb") attack.

Anything else -- a real binary that is neither valid UTF-8 nor a
parseable PDF or zip (a .docx/.pptx/.xlsx, a .png, a corrupted file,
an encrypted PDF this project does not attempt to unlock) -- is
rejected by returning None. Callers turn that into an HTTP 400
(upload) or an index-rebuild failure (rebuild, matching how a
decryption failure is already handled: never silently drop coverage).
This keeps "what can I upload" an honest, explicit answer instead of
silently mis-indexing garbage bytes as keywords.
"""

from __future__ import annotations

import io
import zipfile

from pypdf import PdfReader
from pypdf.errors import PdfReadError

PDF_MAGIC = b"%PDF-"

# course-project-scale limits on zip extraction (Section 10-style named
# trade-off, not an oversight): large enough for any realistic upload
# to this vault, small enough that even a maliciously crafted archive
# (a "zip bomb" -- a small file that decompresses to gigabytes) cannot
# make one upload request read an unbounded amount of data into memory.
MAX_ZIP_MEMBERS = 200
MAX_ZIP_UNCOMPRESSED_BYTES = 50 * 1024 * 1024  # 50 MiB


def is_pdf(raw_bytes: bytes) -> bool:
    """PDF files always start with this 5-byte magic number -- checking
    it is far cheaper and more reliable than attempting a full parse
    just to learn the format, and it is what lets extract_indexable_text
    below decide PDF-vs-reject without paying pypdf's parse cost twice."""
    return raw_bytes.startswith(PDF_MAGIC)


def extract_pdf_text(raw_bytes: bytes) -> "str | None":
    """Best-effort text extraction from a PDF's pages.

    Returns "" (not None) for a PDF that parses fine but has no
    extractable text layer -- a legitimate, storable document with
    zero search hits, not an error. Returns None only when the bytes
    cannot be parsed as a PDF at all: corrupted/truncated input, or a
    PDF encrypted with its own password -- a second password concept
    this project's single vault-password model does not have, so it is
    rejected cleanly rather than silently indexed as empty.
    """
    try:
        reader = PdfReader(io.BytesIO(raw_bytes))
        if reader.is_encrypted:
            return None
        pages_text = [page.extract_text() or "" for page in reader.pages]
        return "\n".join(pages_text)
    except (PdfReadError, ValueError, KeyError):
        return None


def is_zip(raw_bytes: bytes) -> bool:
    """zipfile.is_zipfile does a real structural check (it looks for a
    valid end-of-central-directory record), not a naive 2-byte "PK"
    magic-number guess -- a truncated or corrupted file that merely
    starts with the right bytes correctly reports False here rather
    than being handed to ZipFile and failing later."""
    return zipfile.is_zipfile(io.BytesIO(raw_bytes))


def _is_office_document(zf: "zipfile.ZipFile") -> bool:
    """A real Word/Excel/PowerPoint file (.docx/.pptx/.xlsx) IS,
    internally, a zip archive (the OOXML format) -- so is_zip() alone
    cannot tell one apart from a "plain" zip this project knows how to
    index. Every OOXML file carries this exact member by spec (ECMA-376
    Part 2); checking for it is the standard, cheap way to recognise
    one without guessing from the filename. Without this check, a
    .docx upload would silently "succeed" by indexing its internal XML
    markup as if it were the document's real text -- worse than a
    clean rejection, because a search would return noisy hits full of
    XML-schema words that have nothing to do with the document's
    actual content."""
    return "[Content_Types].xml" in zf.namelist()


def _extract_leaf_text(raw_bytes: bytes) -> "str | None":
    """Text extraction for ONE file's bytes -- UTF-8 or PDF, same rule
    as extract_indexable_text below, but deliberately does NOT also
    check for a zip. Used for every file found inside an outer zip, so
    a zip nested inside a zip is treated as an unreadable member
    (skipped, not fatal to the outer upload) rather than being
    unzipped itself. This is what bounds zip handling to exactly one
    level of archive expansion, no matter how many layers an uploaded
    file actually contains -- the other half (alongside the size/
    member-count caps below) of this module's zip-bomb defence, and a
    simple, defensible answer if asked why nested archives aren't
    supported: unbounded recursive expansion of untrusted, attacker-
    controlled archives is exactly the shape of a decompression-bomb
    vulnerability, and this project has no use case that needs it.
    """
    if is_pdf(raw_bytes):
        return extract_pdf_text(raw_bytes)
    try:
        return raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None


def extract_zip_text(raw_bytes: bytes) -> "str | None":
    """Best-effort text extraction from every file inside a zip,
    joined into one blob -- the zip stays a single vault document; see
    the module docstring for why that (rather than one document per
    file inside it) is the model this project uses.

    Returns None (a whole-zip rejection, exactly like a corrupted PDF)
    when: the archive itself cannot be opened; it is actually an
    OOXML Word/Excel/PowerPoint document (_is_office_document above);
    or it exceeds the member-count / total-uncompressed-size limits.
    These are checked BEFORE reading any member's bytes, from the
    zip's own central directory metadata, precisely so an oversized or
    malicious archive is rejected without ever decompressing it.

    Returns "" (not None, and a successful upload) for a zip that
    opens fine but contains no file this project can read as text --
    e.g. a zip of nothing but images -- exactly like a scanned PDF
    with no text layer: a legitimate document with zero search hits,
    not an error.
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw_bytes))
    except (zipfile.BadZipFile, ValueError):
        return None

    if _is_office_document(zf):
        return None

    members = [info for info in zf.infolist() if not info.is_dir()]
    if len(members) > MAX_ZIP_MEMBERS:
        return None
    if sum(info.file_size for info in members) > MAX_ZIP_UNCOMPRESSED_BYTES:
        return None

    parts = []
    for info in members:
        try:
            member_bytes = zf.read(info)
        except (zipfile.BadZipFile, RuntimeError):
            # RuntimeError covers a password-protected member (zipfile's
            # own exception for "encrypted, password required") -- this
            # project has no per-member password concept, so an
            # encrypted entry is skipped exactly like an unreadable one,
            # never fatal to the rest of the archive.
            continue
        text = _extract_leaf_text(member_bytes)
        if text:
            parts.append(text)
    return "\n".join(parts)


def extract_indexable_text(raw_bytes: bytes) -> "str | None":
    """The single entry point both upload and index-rebuild call.

    Returns the text to tokenize, or None if `raw_bytes` is none of
    the supported formats -- the caller's signal to reject (upload) or
    treat as a failure (rebuild), exactly like the original UTF-8-only
    implementation treated any non-UTF-8 file before PDF/zip support
    existed.

    Checks zip, then PDF, BEFORE attempting a UTF-8 decode -- not the
    other way around. Both a zip's local-file-header bytes and a
    PDF's own structural syntax (object headers, dictionary
    punctuation, stream markers) are often themselves plain ASCII,
    which is always valid UTF-8, so decode-first would happily
    "succeed" on either and hand back raw container bytes as if they
    were the document's text, silently skipping real extraction
    entirely. Checking format first makes detection unambiguous.
    """
    if is_zip(raw_bytes):
        return extract_zip_text(raw_bytes)
    if is_pdf(raw_bytes):
        return extract_pdf_text(raw_bytes)
    try:
        return raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None
