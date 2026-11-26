"""PostgreSQL ORM constraint, default, repr, and cascade tests for Document and EducationDocument."""

from datetime import datetime, timezone
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.document import Document, EducationDocument
from app.models.education import Education
from app.models.user import User


def _create_user(db_session: Session, email: str = "doc.model@example.com") -> User:
    user = User(
        id=uuid.uuid4(),
        email=email,
        is_active=True,
        is_email_verified=True,
        email_verified_at=datetime.now(timezone.utc),
    )
    db_session.add(user)
    db_session.flush()
    return user


@pytest.mark.db
def test_document_and_education_link_persistence_defaults_repr_and_cascade(
    db_session: Session,
) -> None:
    """Verify Document creation, defaults, EducationDocument link, safe repr, and CASCADE."""
    user = _create_user(db_session)
    edu = Education(
        id=uuid.uuid4(),
        user_id=user.id,
        institution="RV College of Engineering",
        degree="B.E.",
    )
    doc = Document(
        id=uuid.uuid4(),
        user_id=user.id,
        title="Semester 5 Marksheet",
        original_filename="sem5_marksheet.pdf",
        category="marksheet",
        mime_type="application/pdf",
        size_bytes=2048,
        sha256="a" * 64,
        storage_backend="local",
        storage_key=f"{user.id}/{uuid.uuid4()}",
        notes="Verified copy",
    )
    db_session.add_all([edu, doc])
    db_session.flush()

    link = EducationDocument(education_id=edu.id, document_id=doc.id, display_order=0)
    db_session.add(link)
    db_session.flush()
    db_session.refresh(doc)

    assert doc.processing_status == "pending_scan"
    assert doc.storage_state == "quarantine"
    assert doc.scan_attempts == 0
    assert doc.failure_reason is None
    assert doc.show_in_education is True
    assert doc.created_at is not None
    assert "Semester 5" not in repr(doc)
    assert "sem5_marksheet" not in repr(doc)
    assert str(doc.id) in repr(doc)

    # Deleting user cascades to documents, educations, and education_documents
    db_session.delete(user)
    db_session.flush()
    assert (
        db_session.execute(select(Document).where(Document.id == doc.id)).scalar_one_or_none()
        is None
    )
    assert (
        db_session.execute(
            select(EducationDocument).where(EducationDocument.document_id == doc.id)
        ).scalar_one_or_none()
        is None
    )


@pytest.mark.db
def test_document_db_check_constraints_and_hide_parameters(db_session: Session) -> None:
    """Verify PostgreSQL check constraints reject invalid documents and hide SQL parameters."""
    user = _create_user(db_session, "doc.constraints@example.com")

    def _valid_base(uid: uuid.UUID) -> dict[str, object]:
        return {
            "user_id": uid,
            "title": "Valid Title",
            "original_filename": "file.pdf",
            "category": "marksheet",
            "mime_type": "application/pdf",
            "size_bytes": 100,
            "sha256": "b" * 64,
            "storage_backend": "local",
            "storage_key": f"{uid}/{uuid.uuid4()}",
        }

    bad_overrides = [
        {"title": "   "},
        {"original_filename": ""},
        {"category": "invalid_cat"},
        {"mime_type": "text/html"},
        {"size_bytes": 0},
        {"page_count": 0},
        {"sha256": "not-hex"},
        {"storage_backend": "ftp"},
        {"storage_key": "   "},
        {"processing_status": "unknown_status"},
        {"storage_state": "public"},
        {"scan_attempts": -1},
        {"failure_reason": "unknown_reason"},
        {"processing_status": "ready", "storage_state": "quarantine"},
        {"processing_status": "pending_scan", "storage_state": "trusted"},
    ]

    for override in bad_overrides:
        fields = _valid_base(user.id)
        fields.update(override)
        db_session.add(Document(**fields))
        with pytest.raises(IntegrityError) as exc_info:
            db_session.flush()
        assert "[SQL parameters hidden due to hide_parameters=True]" in str(exc_info.value)
        db_session.rollback()
        user = _create_user(db_session, f"doc.constraints.{uuid.uuid4().hex[:8]}@example.com")
