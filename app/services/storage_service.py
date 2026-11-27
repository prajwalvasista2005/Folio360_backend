"""Storage backends (local filesystem + boto3 S3/R2) and signed URL helpers for Document Vault."""

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import logging
import os
from pathlib import Path
import re
import secrets
import tempfile
import time
from typing import Literal, Protocol
from urllib.parse import quote
import uuid

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import status

from app.core.config import Settings, normalize_api_v1_prefix
from app.core.exceptions import AppException, ResourceNotFoundError

logger = logging.getLogger("folio360.storage")

_STORAGE_KEY_RE = re.compile(
    r"\A(?:[a-z0-9][a-z0-9_-]{0,31}/)?"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
_NAMESPACE_RE = re.compile(r"\A[a-z0-9][a-z0-9_-]{0,31}\Z")
_DEV_EPHEMERAL_SIGNING_SECRET = secrets.token_bytes(32)


def _validate_namespace(namespace: str) -> str:
    cleaned = namespace.strip().lower()
    if not _NAMESPACE_RE.fullmatch(cleaned):
        raise AppException(
            message="Invalid document storage namespace",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
    return cleaned


def build_quarantine_storage_key(
    user_id: uuid.UUID,
    document_id: uuid.UUID,
    *,
    namespace: str = "quarantine",
) -> str:
    """Build a server-controlled quarantine storage key `<namespace>/<user_id>/<doc_id>`."""
    ns = _validate_namespace(namespace)
    key = f"{ns}/{user_id}/{document_id}"
    return validate_storage_key(key)


def build_trusted_storage_key(
    user_id: uuid.UUID,
    document_id: uuid.UUID,
    *,
    namespace: str = "trusted",
) -> str:
    """Build a server-controlled trusted storage key `<namespace>/<user_id>/<doc_id>`."""
    ns = _validate_namespace(namespace)
    key = f"{ns}/{user_id}/{document_id}"
    return validate_storage_key(key)


def is_trusted_storage_key(
    storage_key: str,
    *,
    trusted_namespace: str = "trusted",
) -> bool:
    """Verify that storage_key resides strictly inside the trusted namespace."""
    try:
        validate_storage_key(storage_key)
        ns = _validate_namespace(trusted_namespace)
    except AppException:
        return False
    return storage_key.startswith(f"{ns}/")


def validate_storage_key(storage_key: str) -> str:
    """Validate that storage_key strictly follows server-generated `[ns/]<uuid>/<uuid>` format."""
    if not isinstance(storage_key, str) or not _STORAGE_KEY_RE.fullmatch(storage_key):
        raise AppException(
            message="Invalid document storage key format",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
    return storage_key


def safe_content_disposition(
    disposition: Literal["inline", "attachment"],
    filename: str,
) -> str:
    """Build a safe Content-Disposition header value without header injection or raw paths."""
    base = Path(filename).name if filename else "document"
    cleaned = "".join(
        ch for ch in base if ord(ch) >= 0x20 and ord(ch) != 0x7F and ch not in {'"', "\\", ";", "\r", "\n"}
    ).strip()
    if not cleaned:
        cleaned = "document"
    ascii_fallback = "".join(ch if 0x20 <= ord(ch) <= 0x7E else "_" for ch in cleaned) or "document"
    encoded_utf8 = quote(cleaned, safe="")
    return f'{disposition}; filename="{ascii_fallback}"; filename*=UTF-8\'\'{encoded_utf8}'


def _resolve_signing_secret(settings: Settings) -> bytes:
    if settings.DOCUMENT_SIGNING_SECRET is not None:
        raw = settings.DOCUMENT_SIGNING_SECRET.get_secret_value().strip()
        if raw:
            return raw.encode("utf-8")
    if settings.JWT_SECRET_KEY is not None:
        raw = settings.JWT_SECRET_KEY.get_secret_value().strip()
        if raw:
            return raw.encode("utf-8")
    if settings.ENVIRONMENT == "production":
        raise RuntimeError(
            "DOCUMENT_SIGNING_SECRET or JWT_SECRET_KEY must be configured in production"
        )
    return _DEV_EPHEMERAL_SIGNING_SECRET


def generate_local_content_token(
    *,
    document_id: uuid.UUID,
    disposition: Literal["inline", "attachment"],
    expires_at_ts: int,
    settings: Settings,
) -> str:
    """Generate a short-lived, document- and disposition-bound HMAC-SHA256 token."""
    secret = _resolve_signing_secret(settings)
    payload = f"{document_id}:{disposition}:{expires_at_ts}".encode("utf-8")
    digest = hmac.new(secret, payload, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"{expires_at_ts}.{sig_b64}"


def verify_local_content_token(
    token: str,
    *,
    document_id: uuid.UUID,
    disposition: Literal["inline", "attachment"],
    settings: Settings,
) -> bool:
    """Verify HMAC signature and expiry of a local document content token."""
    if not isinstance(token, str) or "." not in token:
        return False
    exp_str, sig_b64 = token.split(".", 1)
    if not exp_str.isdigit() or not sig_b64:
        return False
    expires_at_ts = int(exp_str)
    if expires_at_ts < int(time.time()):
        return False

    secret = _resolve_signing_secret(settings)
    payload = f"{document_id}:{disposition}:{expires_at_ts}".encode("utf-8")
    expected_digest = hmac.new(secret, payload, hashlib.sha256).digest()
    expected_b64 = base64.urlsafe_b64encode(expected_digest).decode("ascii").rstrip("=")
    return hmac.compare_digest(sig_b64, expected_b64)


def generate_scoped_content_token(
    *,
    scope: str,
    resource_id: uuid.UUID,
    expires_at_ts: int,
    settings: Settings,
) -> str:
    """Generate a short-lived HMAC-SHA256 token bound to a storage resource scope and ID."""
    secret = _resolve_signing_secret(settings)
    payload = f"{scope}:{resource_id}:{expires_at_ts}".encode("utf-8")
    digest = hmac.new(secret, payload, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"{expires_at_ts}.{sig_b64}"


def verify_scoped_content_token(
    token: str,
    *,
    scope: str,
    resource_id: uuid.UUID,
    settings: Settings,
) -> bool:
    """Verify HMAC signature and expiry of a scoped content access token."""
    if not isinstance(token, str) or "." not in token:
        return False
    exp_str, sig_b64 = token.split(".", 1)
    if not exp_str.isdigit() or not sig_b64:
        return False
    expires_at_ts = int(exp_str)
    if expires_at_ts < int(time.time()):
        return False
    secret = _resolve_signing_secret(settings)
    payload = f"{scope}:{resource_id}:{expires_at_ts}".encode("utf-8")
    expected_digest = hmac.new(secret, payload, hashlib.sha256).digest()
    expected_b64 = base64.urlsafe_b64encode(expected_digest).decode("ascii").rstrip("=")
    return hmac.compare_digest(sig_b64, expected_b64)


class StorageBackend(Protocol):
    """Abstract interface for private document binary storage."""

    backend_name: Literal["local", "s3"]

    def put_object(self, *, storage_key: str, data: bytes, content_type: str) -> None:
        """Persist document bytes privately under storage_key."""
        ...

    def read_bytes(self, *, storage_key: str) -> bytes:
        """Read private document bytes stored at storage_key."""
        ...

    def promote_object(
        self,
        *,
        source_key: str,
        destination_key: str,
        content_type: str,
    ) -> None:
        """Promote a scanned object from quarantine namespace to trusted namespace."""
        ...

    def delete_object(self, *, storage_key: str) -> None:
        """Delete document object at storage_key idempotently."""
        ...

    def generate_signed_url(
        self,
        *,
        document_id: uuid.UUID,
        storage_key: str,
        filename: str,
        content_type: str,
        disposition: Literal["inline", "attachment"],
        ttl_seconds: int,
    ) -> tuple[str, datetime]:
        """Generate an expiring URL and its UTC expiry timestamp."""
        ...


class LocalFilesystemStorage:
    """Local disk storage backend for development and automated tests."""

    backend_name: Literal["local", "s3"] = "local"

    def __init__(self, *, root_dir: str, settings: Settings) -> None:
        self._root_dir = Path(root_dir).resolve()
        self._settings = settings

    def _resolve_path(self, storage_key: str) -> Path:
        validate_storage_key(storage_key)
        target = (self._root_dir / storage_key).resolve()
        if not target.is_relative_to(self._root_dir):
            raise AppException(
                message="Resolved storage path escaped root directory",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        return target

    def put_object(self, *, storage_key: str, data: bytes, content_type: str) -> None:
        del content_type
        target = self._resolve_path(storage_key)
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=target.parent,
                prefix=".tmp_",
                delete=False,
            ) as tmp_file:
                tmp_path = tmp_file.name
                tmp_file.write(data)
                tmp_file.flush()
                os.fsync(tmp_file.fileno())
            os.chmod(tmp_path, 0o640)
            os.replace(tmp_path, target)
            tmp_path = None
        except OSError as exc:
            logger.error(
                "Local document storage write failed: exception=%s",
                type(exc).__name__,
            )
            raise AppException(
                message="Failed to write document to local storage",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            ) from None
        finally:
            if tmp_path is not None:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    def read_bytes(self, *, storage_key: str) -> bytes:
        target = self._resolve_path(storage_key)
        try:
            return target.read_bytes()
        except FileNotFoundError:
            raise ResourceNotFoundError(
                message="Document object missing from local storage",
                public_message="Document content not found.",
                error_code="DOCUMENT_NOT_FOUND",
            ) from None
        except OSError as exc:
            logger.error(
                "Local document storage read failed: exception=%s",
                type(exc).__name__,
            )
            raise AppException(
                message="Failed to read document from local storage",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            ) from None

    def delete_object(self, *, storage_key: str) -> None:
        target = self._resolve_path(storage_key)
        try:
            target.unlink(missing_ok=True)
        except OSError as exc:
            logger.warning(
                "Local document storage delete failed: exception=%s",
                type(exc).__name__,
            )

    def promote_object(
        self,
        *,
        source_key: str,
        destination_key: str,
        content_type: str,
    ) -> None:
        """Copy quarantined object atomically into trusted path, then remove quarantine object."""
        self._resolve_path(source_key)
        self._resolve_path(destination_key)
        data = self.read_bytes(storage_key=source_key)
        self.put_object(
            storage_key=destination_key,
            data=data,
            content_type=content_type,
        )
        self.delete_object(storage_key=source_key)

    def generate_signed_url(
        self,
        *,
        document_id: uuid.UUID,
        storage_key: str,
        filename: str,
        content_type: str,
        disposition: Literal["inline", "attachment"],
        ttl_seconds: int,
    ) -> tuple[str, datetime]:
        del filename, content_type
        validate_storage_key(storage_key)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        expires_at_ts = int(expires_at.timestamp())
        token = generate_local_content_token(
            document_id=document_id,
            disposition=disposition,
            expires_at_ts=expires_at_ts,
            settings=self._settings,
        )
        prefix = normalize_api_v1_prefix(self._settings.API_V1_PREFIX)
        base = self._settings.BACKEND_BASE_URL.rstrip("/")
        url = (
            f"{base}{prefix}/documents/{document_id}/content"
            f"?token={quote(token, safe='.')}&disposition={disposition}"
        )
        return url, expires_at


class S3CompatibleStorage:
    """Private S3-compatible object storage backend (AWS S3 & Cloudflare R2 via boto3)."""

    backend_name: Literal["local", "s3"] = "s3"

    def __init__(self, *, settings: Settings, client: object | None = None) -> None:
        if not settings.S3_BUCKET_NAME:
            raise RuntimeError("S3_BUCKET_NAME must be configured for S3 storage")
        self._bucket = settings.S3_BUCKET_NAME
        if client is not None:
            self._client = client
            return

        if settings.S3_ACCESS_KEY_ID is None or settings.S3_SECRET_ACCESS_KEY is None:
            raise RuntimeError(
                "S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY must be configured for S3 storage"
            )

        addressing_style = "path" if settings.S3_FORCE_PATH_STYLE else "auto"
        self._client = boto3.client(
            "s3",
            endpoint_url=settings.S3_ENDPOINT_URL,
            region_name=settings.S3_REGION,
            aws_access_key_id=settings.S3_ACCESS_KEY_ID.get_secret_value(),
            aws_secret_access_key=settings.S3_SECRET_ACCESS_KEY.get_secret_value(),
            config=BotoConfig(
                signature_version="s3v4",
                s3={"addressing_style": addressing_style},
            ),
        )

    def put_object(self, *, storage_key: str, data: bytes, content_type: str) -> None:
        validate_storage_key(storage_key)
        try:
            self._client.put_object(  # type: ignore[attr-defined]
                Bucket=self._bucket,
                Key=storage_key,
                Body=data,
                ContentType=content_type,
            )
        except (BotoCoreError, ClientError) as exc:
            logger.error(
                "S3 put_object failed: exception=%s",
                type(exc).__name__,
            )
            raise AppException(
                message="Failed to store document object in S3 storage",
                status_code=status.HTTP_502_BAD_GATEWAY,
            ) from None

    def read_bytes(self, *, storage_key: str) -> bytes:
        validate_storage_key(storage_key)
        try:
            response = self._client.get_object(  # type: ignore[attr-defined]
                Bucket=self._bucket,
                Key=storage_key,
            )
            body = response["Body"]
            return bytes(body.read())
        except ClientError as exc:
            error_code = str(exc.response.get("Error", {}).get("Code", ""))
            if error_code in {"NoSuchKey", "404"}:
                raise ResourceNotFoundError(
                    message="Document object missing from S3 storage",
                    public_message="Document content not found.",
                    error_code="DOCUMENT_NOT_FOUND",
                ) from None
            logger.error(
                "S3 get_object failed: exception=%s",
                type(exc).__name__,
            )
            raise AppException(
                message="Failed to read document object from S3 storage",
                status_code=status.HTTP_502_BAD_GATEWAY,
            ) from None
        except BotoCoreError as exc:
            logger.error(
                "S3 get_object failed: exception=%s",
                type(exc).__name__,
            )
            raise AppException(
                message="Failed to read document object from S3 storage",
                status_code=status.HTTP_502_BAD_GATEWAY,
            ) from None

    def promote_object(
        self,
        *,
        source_key: str,
        destination_key: str,
        content_type: str,
    ) -> None:
        validate_storage_key(source_key)
        validate_storage_key(destination_key)
        try:
            self._client.copy_object(  # type: ignore[attr-defined]
                Bucket=self._bucket,
                CopySource={"Bucket": self._bucket, "Key": source_key},
                Key=destination_key,
                ContentType=content_type,
                MetadataDirective="REPLACE",
            )
        except (BotoCoreError, ClientError) as exc:
            logger.error(
                "S3 promote_object copy failed: exception=%s",
                type(exc).__name__,
            )
            raise AppException(
                message="Failed to promote document object in S3 storage",
                status_code=status.HTTP_502_BAD_GATEWAY,
            ) from None
        self.delete_object(storage_key=source_key)

    def delete_object(self, *, storage_key: str) -> None:
        validate_storage_key(storage_key)
        try:
            self._client.delete_object(  # type: ignore[attr-defined]
                Bucket=self._bucket,
                Key=storage_key,
            )
        except (BotoCoreError, ClientError) as exc:
            logger.warning(
                "S3 delete_object failed: exception=%s",
                type(exc).__name__,
            )

    def generate_signed_url(
        self,
        *,
        document_id: uuid.UUID,
        storage_key: str,
        filename: str,
        content_type: str,
        disposition: Literal["inline", "attachment"],
        ttl_seconds: int,
    ) -> tuple[str, datetime]:
        del document_id
        validate_storage_key(storage_key)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        try:
            url = self._client.generate_presigned_url(  # type: ignore[attr-defined]
                "get_object",
                Params={
                    "Bucket": self._bucket,
                    "Key": storage_key,
                    "ResponseContentType": content_type,
                    "ResponseContentDisposition": safe_content_disposition(
                        disposition,
                        filename,
                    ),
                },
                ExpiresIn=ttl_seconds,
            )
        except (BotoCoreError, ClientError) as exc:
            logger.error(
                "S3 generate_presigned_url failed: exception=%s",
                type(exc).__name__,
            )
            raise AppException(
                message="Failed to generate document access URL",
                status_code=status.HTTP_502_BAD_GATEWAY,
            ) from None
        return str(url), expires_at


def build_storage_backend(settings: Settings) -> StorageBackend:
    """Instantiate the configured Document Vault storage backend."""
    if settings.STORAGE_BACKEND == "s3":
        return S3CompatibleStorage(settings=settings)
    return LocalFilesystemStorage(
        root_dir=settings.DOCUMENT_LOCAL_STORAGE_DIR,
        settings=settings,
    )
