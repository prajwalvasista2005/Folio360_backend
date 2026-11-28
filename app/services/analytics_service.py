"""Owner-scoped Overview dashboard aggregation service."""

from datetime import datetime, timedelta, timezone
import uuid

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.models.certificate import Achievement, Certificate
from app.models.document import Document
from app.models.document_analysis import DocumentAnalysis
from app.models.education import Education
from app.models.experience import Experience
from app.models.profile import UserProfile
from app.models.project import Project
from app.models.skill import Skill
from app.models.user import User
from app.schemas.analytics import (
    ActivityVerb,
    DashboardActivityEvent,
    DashboardCompleteness,
    DashboardContinueItem,
    DashboardCounts,
    DashboardSummaryResponse,
)

_MAX_CONTINUE_ITEMS = 4
_MAX_RECENT_ACTIVITY = 8
_UPDATE_THRESHOLD = timedelta(seconds=1)


def _normalize_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _resolve_first_name(profile: UserProfile | None, user: User) -> str:
    if profile is not None and profile.full_name:
        cleaned = profile.full_name.strip()
        if cleaned:
            return cleaned.split()[0]
    if profile is not None and profile.slug:
        cleaned_slug = profile.slug.strip()
        if cleaned_slug:
            return cleaned_slug
    local_part = user.email.split("@", 1)[0].strip() if user.email else ""
    return local_part or "there"


def _count_for_user(db: Session, model: type, user_id: uuid.UUID) -> int:
    return int(
        db.execute(
            select(func.count()).select_from(model).where(model.user_id == user_id)
        ).scalar_one()
    )


def _count_pending_reviews(db: Session, *, user_id: uuid.UUID) -> int:
    """Count distinct user-owned documents awaiting scan or AI analysis completion."""
    pending_analysis_doc_ids = select(DocumentAnalysis.document_id).where(
        DocumentAnalysis.user_id == user_id,
        DocumentAnalysis.status.in_(("pending", "processing")),
    )
    return int(
        db.execute(
            select(func.count(Document.id)).where(
                Document.user_id == user_id,
                or_(
                    Document.processing_status.in_(("pending_scan", "scanning")),
                    Document.id.in_(pending_analysis_doc_ids),
                ),
            )
        ).scalar_one()
    )


def _has_profile_details(profile: UserProfile | None) -> bool:
    if profile is None:
        return False
    return bool(
        profile.bio
        or profile.profile_picture_url
        or profile.interests
        or profile.activities
    )


def _compute_completeness_percent(
    *,
    profile: UserProfile | None,
    education_count: int,
    projects_count: int,
    skills_count: int,
    experience_count: int,
    credentials_count: int,
    documents_count: int,
) -> int:
    score = 0
    if profile is not None and profile.profile_completed:
        score += 10
    if _has_profile_details(profile):
        score += 10
    if education_count > 0:
        score += 15
    if projects_count > 0:
        score += 15
    if skills_count > 0:
        score += 15
    if experience_count > 0:
        score += 15
    if credentials_count > 0:
        score += 10
    if documents_count > 0:
        score += 10
    return score


def _build_continue_items(
    *,
    profile: UserProfile | None,
    education_count: int,
    projects_count: int,
    skills_count: int,
    experience_count: int,
    credentials_count: int,
    documents_count: int,
) -> list[DashboardContinueItem]:
    suggestions: list[DashboardContinueItem] = []

    if profile is None or not profile.profile_completed:
        suggestions.append(
            DashboardContinueItem(
                key="profile_setup",
                label="Complete your profile",
                action_route="/onboarding/profile",
            )
        )
    elif not _has_profile_details(profile):
        suggestions.append(
            DashboardContinueItem(
                key="profile_details",
                label="Add bio and interests to your profile",
                action_route="/workspace/profile",
            )
        )

    if education_count == 0:
        suggestions.append(
            DashboardContinueItem(
                key="education_records",
                label="Add education records",
                action_route="/workspace/education",
            )
        )
    if projects_count == 0:
        suggestions.append(
            DashboardContinueItem(
                key="projects_update",
                label="Add your projects",
                action_route="/workspace/projects",
            )
        )
    if skills_count == 0:
        suggestions.append(
            DashboardContinueItem(
                key="skills_added",
                label="Add your skills",
                action_route="/workspace/skills",
            )
        )
    if experience_count == 0:
        suggestions.append(
            DashboardContinueItem(
                key="experience_added",
                label="Add work or internship experience",
                action_route="/workspace/experience",
            )
        )
    if credentials_count == 0:
        suggestions.append(
            DashboardContinueItem(
                key="certificates_added",
                label="Add certificates or achievements",
                action_route="/workspace/certificates",
            )
        )
    if documents_count == 0:
        suggestions.append(
            DashboardContinueItem(
                key="documents_vault",
                label="Upload supporting documents",
                action_route="/workspace/documents",
            )
        )

    return suggestions[:_MAX_CONTINUE_ITEMS]


def _make_activity_event(
    *,
    record_id: uuid.UUID,
    created_at: datetime,
    updated_at: datetime,
    entity_type: str,
    label: str,
    create_verb: ActivityVerb = "created",
) -> DashboardActivityEvent:
    created_utc = _normalize_utc(created_at)
    updated_utc = _normalize_utc(updated_at)
    is_updated = (updated_utc - created_utc) > _UPDATE_THRESHOLD
    event_time = updated_utc if updated_utc >= created_utc else created_utc
    verb: ActivityVerb = "updated" if is_updated else create_verb
    return DashboardActivityEvent(
        id=record_id,
        verb=verb,
        entity_type=entity_type,
        entity_id=record_id,
        label=label,
        created_at=event_time,
    )


def _fetch_recent_rows(db: Session, model: type, user_id: uuid.UUID) -> list:
    return list(
        db.execute(
            select(model)
            .where(model.user_id == user_id)
            .order_by(model.updated_at.desc(), model.created_at.desc())
            .limit(_MAX_RECENT_ACTIVITY)
        )
        .scalars()
        .all()
    )


def _build_recent_activity(
    db: Session,
    *,
    user_id: uuid.UUID,
    profile: UserProfile | None,
) -> list[DashboardActivityEvent]:
    events: list[DashboardActivityEvent] = []

    if profile is not None:
        events.append(
            _make_activity_event(
                record_id=profile.id,
                created_at=profile.created_at,
                updated_at=profile.updated_at,
                entity_type="profile",
                label="Profile details",
            )
        )

    for proj in _fetch_recent_rows(db, Project, user_id):
        events.append(
            _make_activity_event(
                record_id=proj.id,
                created_at=proj.created_at,
                updated_at=proj.updated_at,
                entity_type="project",
                label=proj.title,
            )
        )

    for doc in _fetch_recent_rows(db, Document, user_id):
        events.append(
            _make_activity_event(
                record_id=doc.id,
                created_at=doc.created_at,
                updated_at=doc.updated_at,
                entity_type="document",
                label=doc.title,
                create_verb="uploaded",
            )
        )

    for edu in _fetch_recent_rows(db, Education, user_id):
        events.append(
            _make_activity_event(
                record_id=edu.id,
                created_at=edu.created_at,
                updated_at=edu.updated_at,
                entity_type="education",
                label=f"{edu.degree} · {edu.institution}",
            )
        )

    for skill in _fetch_recent_rows(db, Skill, user_id):
        events.append(
            _make_activity_event(
                record_id=skill.id,
                created_at=skill.created_at,
                updated_at=skill.updated_at,
                entity_type="skill",
                label=skill.name,
            )
        )

    for cert in _fetch_recent_rows(db, Certificate, user_id):
        events.append(
            _make_activity_event(
                record_id=cert.id,
                created_at=cert.created_at,
                updated_at=cert.updated_at,
                entity_type="certificate",
                label=cert.name,
            )
        )

    for ach in _fetch_recent_rows(db, Achievement, user_id):
        events.append(
            _make_activity_event(
                record_id=ach.id,
                created_at=ach.created_at,
                updated_at=ach.updated_at,
                entity_type="achievement",
                label=ach.title,
            )
        )

    for exp in _fetch_recent_rows(db, Experience, user_id):
        events.append(
            _make_activity_event(
                record_id=exp.id,
                created_at=exp.created_at,
                updated_at=exp.updated_at,
                entity_type="experience",
                label=f"{exp.role} · {exp.organization}",
            )
        )

    events.sort(
        key=lambda ev: (ev.created_at, ev.entity_type, str(ev.entity_id or ev.id)),
        reverse=True,
    )
    return events[:_MAX_RECENT_ACTIVITY]


def get_dashboard_summary(db: Session, *, user: User) -> DashboardSummaryResponse:
    """Compute the owner-scoped Overview dashboard summary for an authenticated user."""
    profile = db.execute(
        select(UserProfile)
        .options(selectinload(UserProfile.activities))
        .where(UserProfile.user_id == user.id)
    ).scalar_one_or_none()

    projects_count = _count_for_user(db, Project, user.id)
    skills_count = _count_for_user(db, Skill, user.id)
    certificates_count = _count_for_user(db, Certificate, user.id)
    achievements_count = _count_for_user(db, Achievement, user.id)
    experience_count = _count_for_user(db, Experience, user.id)
    documents_count = _count_for_user(db, Document, user.id)
    education_count = _count_for_user(db, Education, user.id)
    pending_reviews = _count_pending_reviews(db, user_id=user.id)

    credentials_count = certificates_count + achievements_count
    percent = _compute_completeness_percent(
        profile=profile,
        education_count=education_count,
        projects_count=projects_count,
        skills_count=skills_count,
        experience_count=experience_count,
        credentials_count=credentials_count,
        documents_count=documents_count,
    )
    continue_items = _build_continue_items(
        profile=profile,
        education_count=education_count,
        projects_count=projects_count,
        skills_count=skills_count,
        experience_count=experience_count,
        credentials_count=credentials_count,
        documents_count=documents_count,
    )
    recent_activity = _build_recent_activity(
        db,
        user_id=user.id,
        profile=profile,
    )

    return DashboardSummaryResponse(
        first_name=_resolve_first_name(profile, user),
        slug=profile.slug if profile and profile.slug else None,
        avatar_url=(
            profile.profile_picture_url
            if profile and profile.profile_picture_url
            else None
        ),
        completeness=DashboardCompleteness(percent=percent),
        continue_items=continue_items,
        counts=DashboardCounts(
            projects=projects_count,
            skills=skills_count,
            certificates=certificates_count,
            experience=experience_count,
            documents=documents_count,
            pending_reviews=pending_reviews,
        ),
        recent_activity=recent_activity,
    )
