"""Unit tests for Phase 2 Stage 5 validation, quarantine promotion, state machine, and ClamAV adapter."""

from io import BytesIO
from pathlib import Path
import socket
import struct
import threading
import time
from unittest.mock import MagicMock
import uuid
import zlib

from botocore.exceptions import ClientError
import pytest

from app.core.config import Settings
from app.core.exceptions import AppException, ValidationAppError
from app.models.document import Document
from app.services.document_service import (
    InvalidDocumentStateTransitionError,
    _assert_document_accessible,
    transition_document_status,
)
from app.services.file_validation import sniff_and_validate_document_bytes
from app.services.malware_scanner import (
    EICAR_TEST_SIGNATURE,
    ClamAVScanner,
    MockMalwareScanner,
    ScannerProtocolError,
    ScannerTimeoutError,
    ScannerUnavailableError,
    build_malware_scanner,
)
from app.services.storage_service import (
    LocalFilesystemStorage,
    S3CompatibleStorage,
    build_quarantine_storage_key,
    build_trusted_storage_key,
    is_trusted_storage_key,
)


def _valid_png_bytes() -> bytes:
    def _chunk(chunk_type: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
        return struct.pack("!I", len(data)) + chunk_type + data + struct.pack("!I", crc)

    ihdr = struct.pack("!IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00\xff\x00\x00")
    return b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b"")


VALID_PDF = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF\n"
VALID_PNG = _valid_png_bytes()
VALID_JPEG = (
    b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    b"\xff\xda\x00\x08\x01\x01\x00\x00?\x00\x00\xff\xd9"
)


def _make_doc(
    *,
    processing_status: str = "pending_scan",
    storage_state: str = "quarantine",
    storage_key: str | None = None,
) -> Document:
    uid = uuid.uuid4()
    did = uuid.uuid4()
    return Document(
        id=did,
        user_id=uid,
        title="Doc",
        original_filename="doc.pdf",
        category="marksheet",
        mime_type="application/pdf",
        size_bytes=len(VALID_PDF),
        sha256="a" * 64,
        storage_backend="local",
        storage_key=storage_key or f"quarantine/{uid}/{did}",
        storage_state=storage_state,
        processing_status=processing_status,
    )


def test_document_state_machine_allowed_and_disallowed_transitions() -> None:
    """State machine allows only canonical Stage 5 transitions and blocks shortcuts."""
    doc = _make_doc(processing_status="pending_scan")
    transition_document_status(doc, "scanning")
    assert doc.processing_status == "scanning"
    transition_document_status(doc, "scan_failed")
    assert doc.processing_status == "scan_failed"
    transition_document_status(doc, "scanning")
    transition_document_status(doc, "ready")
    assert doc.processing_status == "ready"

    # Terminal states cannot transition anywhere
    for terminal in ("ready", "rejected"):
        for target in ("pending_scan", "scanning", "ready", "rejected", "scan_failed"):
            doc = _make_doc(processing_status=terminal)
            with pytest.raises(InvalidDocumentStateTransitionError) as exc_info:
                transition_document_status(doc, target)
            assert exc_info.value.status_code == 409
            assert exc_info.value.error_code == "INVALID_STATE_TRANSITION"

    # Shortcuts directly from pending_scan -> ready must fail
    pending = _make_doc(processing_status="pending_scan")
    with pytest.raises(InvalidDocumentStateTransitionError):
        transition_document_status(pending, "ready")


def test_structural_file_validation_pdf_png_jpeg() -> None:
    """Valid PDF/PNG/JPEG pass while truncated or corrupted structures raise 422 MALFORMED_FILE."""
    assert sniff_and_validate_document_bytes(VALID_PDF) == "application/pdf"
    assert sniff_and_validate_document_bytes(VALID_PNG) == "image/png"
    assert sniff_and_validate_document_bytes(VALID_JPEG) == "image/jpeg"

    malformed_samples = [
        b"%PDF-1.7\nno eof or objects",
        b"%PDF-9.9\n1 0 obj\n<<>>\nendobj\n%%EOF\n",
        b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n",  # truncated PDF without %%EOF
        VALID_PNG[:-12],  # truncated PNG missing IEND
        VALID_PNG[:-5] + b"\x00\x00\x00\x00" + VALID_PNG[-1:],  # corrupt CRC in IEND / truncated
        VALID_PNG[:20] + b"\xff" + VALID_PNG[21:],  # corrupt IHDR CRC
        VALID_JPEG[:-2],  # truncated JPEG without EOI
        b"\xff\xd8\xff\xe0\x00\x99bad_len",  # truncated JPEG segment
    ]
    for sample in malformed_samples:
        with pytest.raises(ValidationAppError) as exc_info:
            sniff_and_validate_document_bytes(sample)
        assert exc_info.value.status_code == 422
        assert exc_info.value.error_code == "MALFORMED_FILE"


def test_clamav_scanner_instream_protocol_responses_timeouts_and_unavailability() -> None:
    """ClamAVScanner speaks zINSTREAM and fails closed on infected, timeout, error, or down daemon."""

    def _serve_once(reply: bytes, *, delay_seconds: float = 0.0) -> tuple[int, list[bytes]]:
        received: list[bytes] = []
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def _worker() -> None:
            conn, _addr = srv.accept()
            with conn:
                conn.settimeout(2.0)
                buf = b""
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    if buf.endswith(b"\x00\x00\x00\x00"):
                        break
                received.append(buf)
                if delay_seconds > 0:
                    time.sleep(delay_seconds)
                if reply:
                    conn.sendall(reply)
            srv.close()

        thread = threading.Thread(target=_worker, daemon=True)
        thread.start()
        return port, received

    # Clean verdict + verify framing
    port_clean, wire_clean = _serve_once(b"stream: OK\x00")
    res_clean = ClamAVScanner(host="127.0.0.1", port=port_clean, timeout_seconds=2.0).scan_bytes(
        b"%PDF-1.7\nhello"
    )
    assert res_clean.verdict == "clean"
    assert res_clean.signature is None
    assert wire_clean[0].startswith(b"zINSTREAM\x00")
    assert wire_clean[0].endswith(b"\x00\x00\x00\x00")

    # Infected verdict
    port_inf, _ = _serve_once(b"stream: Win.Test.EICAR_HDB-1 FOUND\x00")
    res_inf = ClamAVScanner(host="127.0.0.1", port=port_inf, timeout_seconds=2.0).scan_bytes(
        EICAR_TEST_SIGNATURE
    )
    assert res_inf.verdict == "infected"
    assert res_inf.signature == "Win.Test.EICAR_HDB-1"

    # Unexpected protocol error -> ScannerProtocolError (never clean)
    port_err, _ = _serve_once(b"stream: UNKNOWN COMMAND ERROR\x00")
    with pytest.raises(ScannerProtocolError):
        ClamAVScanner(host="127.0.0.1", port=port_err, timeout_seconds=2.0).scan_bytes(b"abc")

    # Slow response -> ScannerTimeoutError
    port_slow, _ = _serve_once(b"stream: OK\x00", delay_seconds=0.4)
    with pytest.raises(ScannerTimeoutError):
        ClamAVScanner(host="127.0.0.1", port=port_slow, timeout_seconds=0.1).scan_bytes(b"abc")

    # Unreachable port -> ScannerUnavailableError
    unused_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    unused_sock.bind(("127.0.0.1", 0))
    dead_port = unused_sock.getsockname()[1]
    unused_sock.close()
    with pytest.raises(ScannerUnavailableError):
        ClamAVScanner(host="127.0.0.1", port=dead_port, timeout_seconds=0.5).scan_bytes(b"abc")


def test_production_forbids_mock_scanner_and_namespace_collisions() -> None:
    """Production/staging runtime validation and factory refuse mock scanner and duplicate namespaces."""
    with pytest.raises(ValueError):
        Settings(
            _env_file=None,
            DOCUMENT_QUARANTINE_NAMESPACE="same",
            DOCUMENT_TRUSTED_NAMESPACE="same",
        )

    prod_mock_settings = Settings(
        _env_file=None,
        ENVIRONMENT="production",
        MALWARE_SCANNER_BACKEND="mock",
    )
    with pytest.raises(RuntimeError):
        build_malware_scanner(prod_mock_settings)

    with pytest.raises(RuntimeError):
        Settings(
            _env_file=None,
            ENVIRONMENT="production",
            DATABASE_URL="postgresql+psycopg://u:p@db:5432/d",
            JWT_SECRET_KEY="a" * 32,
            RESEND_API_KEY="re_prod_key",
            EMAIL_FROM_ADDRESS="noreply@folio360.com",
            FRONTEND_BASE_URL="https://app.folio360.com",
            CORS_ORIGINS=["https://app.folio360.com"],
            MALWARE_SCANNER_BACKEND="mock",
        ).validate_runtime_requirements()

    mock_scanner = MockMalwareScanner(mode="eicar")
    assert mock_scanner.scan_bytes(VALID_PDF).verdict == "clean"
    assert mock_scanner.scan_bytes(VALID_PDF + EICAR_TEST_SIGNATURE).verdict == "infected"


def test_storage_quarantine_promotion_and_failure_cleanup(tmp_path: Path) -> None:
    """LocalFilesystemStorage and S3CompatibleStorage enforce quarantine->trusted promotion."""
    settings = Settings(
        _env_file=None,
        ENVIRONMENT="testing",
        STORAGE_BACKEND="local",
        DOCUMENT_LOCAL_STORAGE_DIR=str(tmp_path),
    )
    local = LocalFilesystemStorage(root_dir=str(tmp_path), settings=settings)
    uid, did = uuid.uuid4(), uuid.uuid4()
    q_key = build_quarantine_storage_key(uid, did)
    t_key = build_trusted_storage_key(uid, did)
    assert is_trusted_storage_key(t_key) is True
    assert is_trusted_storage_key(q_key) is False

    local.put_object(storage_key=q_key, data=VALID_PDF, content_type="application/pdf")
    assert (tmp_path / q_key).exists()
    local.promote_object(source_key=q_key, destination_key=t_key, content_type="application/pdf")
    assert not (tmp_path / q_key).exists()
    assert local.read_bytes(storage_key=t_key) == VALID_PDF

    # S3 mocked promote_object + failure keeps quarantine untouched
    mock_client = MagicMock()
    mock_client.get_object.return_value = {"Body": BytesIO(VALID_PDF)}
    s3_settings = Settings(
        _env_file=None,
        ENVIRONMENT="production",
        STORAGE_BACKEND="s3",
        S3_BUCKET_NAME="folio360-private",
        S3_ACCESS_KEY_ID="k",
        S3_SECRET_ACCESS_KEY="s",
    )
    s3 = S3CompatibleStorage(settings=s3_settings, client=mock_client)
    assert s3.read_bytes(storage_key=q_key) == VALID_PDF
    s3.promote_object(source_key=q_key, destination_key=t_key, content_type="application/pdf")
    mock_client.copy_object.assert_called_once()
    mock_client.delete_object.assert_called_once_with(Bucket="folio360-private", Key=q_key)

    mock_client.reset_mock()
    mock_client.copy_object.side_effect = ClientError(
        {"Error": {"Code": "InternalError", "Message": "S3 copy failed"}},
        "CopyObject",
    )
    with pytest.raises(AppException) as exc_info:
        s3.promote_object(source_key=q_key, destination_key=t_key, content_type="application/pdf")
    assert exc_info.value.status_code == 502
    mock_client.delete_object.assert_not_called()


def test_assert_document_accessible_blocks_non_ready_or_quarantined_keys() -> None:
    """Signed URL and content assertions fail closed for non-ready statuses or non-trusted keys."""
    for status_name in ("pending_scan", "scanning", "scan_failed", "rejected"):
        doc = _make_doc(
            processing_status=status_name,
            storage_state="quarantine",
        )
        with pytest.raises(AppException):
            _assert_document_accessible(doc, trusted_namespace="trusted")

    # Even if DB status were ready, mismatched storage_state or quarantine storage_key blocks access
    mismatched = _make_doc(processing_status="ready", storage_state="quarantine")
    with pytest.raises(AppException):
        _assert_document_accessible(mismatched, trusted_namespace="trusted", for_content_stream=True)

    wrong_ns = _make_doc(
        processing_status="ready",
        storage_state="trusted",
        storage_key=f"quarantine/{uuid.uuid4()}/{uuid.uuid4()}",
    )
    with pytest.raises(AppException):
        _assert_document_accessible(wrong_ns, trusted_namespace="trusted", for_content_stream=True)
