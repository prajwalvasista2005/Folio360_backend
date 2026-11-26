"""Magic-byte sniffing and bounded structural validation for Document Vault uploads."""

from typing import get_args
import zlib

from fastapi import status

from app.core.exceptions import AppException, ValidationAppError
from app.schemas.document import DocumentMimeType

SUPPORTED_DOCUMENT_MIME_TYPES: frozenset[str] = frozenset(get_args(DocumentMimeType))

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_PNG_ALLOWED_BIT_DEPTHS: dict[int, frozenset[int]] = {
    0: frozenset({1, 2, 4, 8, 16}),
    2: frozenset({8, 16}),
    3: frozenset({1, 2, 4, 8}),
    4: frozenset({8, 16}),
    6: frozenset({8, 16}),
}
_PDF_STRUCTURE_MARKERS: tuple[bytes, ...] = (b"endobj", b"xref", b"/Root")


def _raise_malformed(message: str) -> None:
    raise ValidationAppError(
        message=message,
        public_message="Uploaded file is malformed or truncated.",
        error_code="MALFORMED_FILE",
    )


def sniff_mime_type(data: bytes) -> DocumentMimeType:
    """Identify supported document MIME types strictly from magic-byte signatures."""
    if data.startswith(b"%PDF-"):
        return "application/pdf"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith(_PNG_SIGNATURE):
        return "image/png"
    raise AppException(
        message="Unsupported document file signature",
        status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
        public_message="Unsupported file format. Only PDF, JPEG, and PNG files are allowed.",
        error_code="UNSUPPORTED_FILE_TYPE",
    )


def _validate_pdf_structure(data: bytes) -> None:
    """Validate bounded PDF header, trailer EOF marker, and basic object structure."""
    if len(data) < 20 or len(data) < 8:
        _raise_malformed("PDF payload is too short to be structurally valid")
    if not (data.startswith(b"%PDF-1.") or data.startswith(b"%PDF-2.")):
        _raise_malformed("PDF header does not declare a valid PDF 1.x or 2.x version")
    if not (0x30 <= data[7] <= 0x39):
        _raise_malformed("PDF minor version byte is not an ASCII digit")

    tail = data[-1024:]
    if b"%%EOF" not in tail:
        _raise_malformed("PDF file is truncated or missing %%EOF trailer")
    if not any(marker in data for marker in _PDF_STRUCTURE_MARKERS):
        _raise_malformed("PDF file lacks required structural object or xref markers")


def _validate_png_structure(data: bytes) -> None:
    """Walk PNG chunks, verify CRC32 checksums, valid IHDR, and terminating IEND chunk."""
    total_len = len(data)
    if total_len < 8 + 12 + 13 + 12:
        _raise_malformed("PNG file is truncated")

    pos = 8
    seen_ihdr = False
    seen_iend = False

    while pos < total_len:
        if pos + 12 > total_len:
            _raise_malformed("PNG chunk header is truncated")

        chunk_len = int.from_bytes(data[pos : pos + 4], "big")
        chunk_type = data[pos + 4 : pos + 8]
        data_start = pos + 8
        data_end = data_start + chunk_len
        crc_end = data_end + 4

        if crc_end > total_len:
            _raise_malformed("PNG chunk payload is truncated")

        expected_crc = zlib.crc32(data[pos + 4 : data_end]) & 0xFFFFFFFF
        actual_crc = int.from_bytes(data[data_end:crc_end], "big")
        if actual_crc != expected_crc:
            _raise_malformed("PNG chunk CRC verification failed")

        if not seen_ihdr:
            if chunk_type != b"IHDR" or chunk_len != 13:
                _raise_malformed("PNG must begin with a 13-byte IHDR chunk")
            ihdr = data[data_start:data_end]
            width = int.from_bytes(ihdr[0:4], "big")
            height = int.from_bytes(ihdr[4:8], "big")
            bit_depth = ihdr[8]
            color_type = ihdr[9]
            if width <= 0 or height <= 0:
                _raise_malformed("PNG dimensions must be positive")
            allowed_depths = _PNG_ALLOWED_BIT_DEPTHS.get(color_type)
            if allowed_depths is None or bit_depth not in allowed_depths:
                _raise_malformed("PNG IHDR specifies an invalid color type or bit depth")
            seen_ihdr = True

        pos = crc_end
        if chunk_type == b"IEND":
            if chunk_len != 0 or pos != total_len:
                _raise_malformed("PNG IEND chunk must have zero length and terminate file")
            seen_iend = True
            break

    if not seen_ihdr or not seen_iend:
        _raise_malformed("PNG file is missing required IHDR or IEND chunk")


def _validate_jpeg_structure(data: bytes) -> None:
    """Walk JPEG marker framing cleanly through SOS entropy data and require EOI (0xFFD9)."""
    total_len = len(data)
    if total_len < 12 or not data.startswith(b"\xff\xd8\xff"):
        _raise_malformed("JPEG payload is truncated or lacks SOI header")

    pos = 2
    seen_eoi = False

    while pos < total_len:
        if data[pos] != 0xFF:
            _raise_malformed("JPEG framing error: expected marker prefix")

        while pos < total_len and data[pos] == 0xFF:
            pos += 1
        if pos >= total_len:
            _raise_malformed("JPEG ended abruptly inside marker")

        marker = data[pos]
        pos += 1

        if marker == 0x00:
            _raise_malformed("Unexpected byte-stuffed marker outside entropy stream")
        if marker == 0xD9:  # EOI
            seen_eoi = True
            break
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:  # TEM or RSTn
            continue

        if pos + 2 > total_len:
            _raise_malformed("JPEG segment length header is truncated")
        seg_len = int.from_bytes(data[pos : pos + 2], "big")
        if seg_len < 2 or pos + seg_len > total_len:
            _raise_malformed("JPEG segment length is invalid or truncated")
        pos += seg_len

        if marker == 0xDA:  # SOS -> scan entropy-coded data until next real marker
            while pos < total_len:
                if data[pos] != 0xFF:
                    pos += 1
                    continue
                if pos + 1 >= total_len:
                    _raise_malformed("JPEG entropy stream is truncated before EOI")
                next_byte = data[pos + 1]
                if next_byte == 0x00:
                    pos += 2
                    continue
                if next_byte == 0xFF:
                    pos += 1
                    continue
                if 0xD0 <= next_byte <= 0xD7:
                    pos += 2
                    continue
                break

    if not seen_eoi:
        _raise_malformed("JPEG file is truncated or missing EOI marker")


def sniff_and_validate_document_bytes(data: bytes) -> DocumentMimeType:
    """Sniff magic bytes and verify bounded structural integrity for PDF/JPEG/PNG."""
    detected = sniff_mime_type(data)
    if detected == "application/pdf":
        _validate_pdf_structure(data)
    elif detected == "image/png":
        _validate_png_structure(data)
    elif detected == "image/jpeg":
        _validate_jpeg_structure(data)
    return detected
