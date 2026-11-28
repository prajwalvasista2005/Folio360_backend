"""Public profile routes under /api/v1/public/* with strict private-record filtering."""

from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps.auth import get_current_settings
from app.core.config import Settings
from app.core.exceptions import ResourceNotFoundError
from app.core.username import normalize_slug
from app.db.session import get_db
from app.models.profile import UserProfile
from app.models.skill import Skill
from app.schemas.document import DocumentRef
from app.schemas.public import (
    PublicProfileAcademics,
    PublicProfileAchievement,
    PublicProfileCertificate,
    PublicProfileEducation,
    PublicProfileExperience,
    PublicProfileLinks,
    PublicProfileProject,
    PublicProfileProjectImage,
    PublicProfileResponse,
    PublicProfileSections,
    PublicProfileSkill,
)
from app.services import (
    certificate_service,
    education_service,
    experience_service,
    profile_service,
    project_service,
)

router = APIRouter(prefix="/public", tags=["Public Profiles"])


@router.get(
    "/profiles/{slug}",
    response_model=PublicProfileResponse,
    status_code=status.HTTP_200_OK,
    summary="Get a user's public Folio360 profile (excludes private projects and records)",
)
def get_public_profile(
    slug: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> PublicProfileResponse:
    """Return publicly visible profile sections for slug, strictly excluding private items."""
    cleaned_slug = normalize_slug(slug.lstrip("@"))
    profile = db.execute(
        select(UserProfile).where(UserProfile.slug == cleaned_slug)
    ).scalar_one_or_none()
    if profile is None or not profile.profile_completed or not profile.slug:
        raise ResourceNotFoundError(
            message="Public profile not found",
            public_message="Public profile not found.",
            error_code="NOT_FOUND",
        )

    visibility = profile_service.resolve_visibility_settings(profile.visibility_settings)
    if not visibility["public_enabled"]:
        raise ResourceNotFoundError(
            message="Public profile is disabled",
            public_message="Public profile not found.",
            error_code="NOT_FOUND",
        )

    sections_cfg = visibility["public_sections"]
    contact_cfg = visibility["public_contact"]
    links_data = profile_service.resolve_profile_links(profile.links)

    public_educations: list[PublicProfileEducation] = []
    public_academics: PublicProfileAcademics | None = None
    educations_raw = (
        education_service.list_educations(
            db,
            user_id=profile.user_id,
            page=1,
            page_size=200,
        )[0]
        if (sections_cfg["education"] or sections_cfg["academics_cgpa"])
        else []
    )
    if sections_cfg["education"]:
        public_educations = [
            PublicProfileEducation(
                institution=edu.institution,
                university_or_board=edu.university_or_board,
                education_level=edu.education_level,
                degree=edu.degree,
                programme=edu.programme,
                branch=edu.branch,
                specialization=edu.specialization,
                country=edu.country,
                state=edu.state,
                start_month=edu.start_month,
                start_year=edu.start_year,
                end_month=edu.end_month,
                end_year=edu.end_year,
                is_current=edu.is_current,
                description=edu.description,
                result=(
                    edu.result_value
                    if (
                        edu.show_result_publicly
                        and (edu.result_type != "cgpa" or sections_cfg["academics_cgpa"])
                    )
                    else None
                ),
                achievements=list(edu.achievements or []),
                documents=[
                    DocumentRef(
                        id=link.document.id,
                        title=link.document.title,
                        category=link.document.category,  # type: ignore[arg-type]
                        mime_type=link.document.mime_type,  # type: ignore[arg-type]
                    )
                    for link in edu.document_links
                    if link.document is not None and link.document.show_in_education
                ],
            )
            for edu in educations_raw
            if edu.visibility == "public"
        ]

    if sections_cfg["academics_cgpa"]:
        for edu in educations_raw:
            if edu.visibility != "public" or not edu.show_result_publicly:
                continue
            if edu.computed_cgpa is not None:
                public_academics = PublicProfileAcademics(
                    cgpa=round(float(edu.computed_cgpa), 2)
                )
                break
            if edu.result_type == "cgpa" and edu.result_value:
                try:
                    public_academics = PublicProfileAcademics(
                        cgpa=round(float(edu.result_value.strip()), 2)
                    )
                    break
                except ValueError:
                    continue

    public_skills: list[PublicProfileSkill] = []
    if sections_cfg["skills"]:
        skill_rows = list(
            db.execute(
                select(Skill)
                .where(Skill.user_id == profile.user_id)
                .order_by(Skill.created_at.desc())
            )
            .scalars()
            .all()
        )
        public_skills = [
            PublicProfileSkill(
                name=sk.name,
                category=sk.category,
                proficiency=sk.proficiency,
            )
            for sk in skill_rows
        ]

    public_projects = (
        [
            PublicProfileProject(
                title=proj.title,
                summary=proj.summary,
                description=proj.description,
                category=proj.category,
                technologies=list(proj.technologies or []),
                images=[
                    PublicProfileProjectImage(
                        url=project_service.build_project_image_url(
                            img,
                            is_public_project=True,
                            settings=settings,
                        ),
                        alt=img.alt,
                    )
                    for img in proj.images
                ],
                github_url=proj.github_url,
                live_url=proj.live_url,
                start_date=proj.start_date.isoformat() if proj.start_date else None,
                end_date=proj.end_date.isoformat() if proj.end_date else None,
                featured=proj.featured,
            )
            for proj in project_service.list_public_projects(db, user_id=profile.user_id)
        ]
        if sections_cfg["projects"]
        else []
    )

    public_certificates = (
        [
            PublicProfileCertificate(
                name=cert.name,
                issuer=cert.issuer,
                category=cert.category,
                issue_date=cert.issue_date.isoformat() if cert.issue_date else None,
                expiry_date=cert.expiry_date.isoformat() if cert.expiry_date else None,
                credential_id=cert.credential_id,
                verification_url=cert.verification_url,
                verification_status=cert.verification_status,
                featured=cert.featured,
            )
            for cert in certificate_service.list_public_certificates(db, user_id=profile.user_id)
        ]
        if sections_cfg["certificates"]
        else []
    )

    public_achievements = (
        [
            PublicProfileAchievement(
                title=ach.title,
                category=ach.category,
                organization=ach.organization,
                date=ach.date.isoformat() if ach.date else None,
                description=ach.description,
                featured=ach.featured,
            )
            for ach in certificate_service.list_public_achievements(db, user_id=profile.user_id)
        ]
        if sections_cfg["achievements"]
        else []
    )

    public_experiences = (
        [
            PublicProfileExperience(
                type=exp.type,
                organization=exp.organization,
                role=exp.role,
                location=exp.location,
                is_remote=exp.is_remote,
                organization_url=exp.organization_url,
                start_date=exp.start_date.isoformat(),
                end_date=exp.end_date.isoformat() if exp.end_date else None,
                is_current=exp.is_current,
                description=exp.description,
                highlights=list(exp.highlights or []),
                skills=[link.skill.name for link in exp.skill_links if link.skill is not None],
                featured=exp.featured,
            )
            for exp in experience_service.list_public_experiences(db, user_id=profile.user_id)
        ]
        if sections_cfg["experience"]
        else []
    )

    return PublicProfileResponse(
        slug=profile.slug,
        full_name=profile.full_name or profile.slug,
        headline=profile.headline,
        bio=profile.bio,
        avatar_url=profile.profile_picture_url,
        location=profile.location if contact_cfg["show_location"] else None,
        contact_email=profile.contact_email if contact_cfg["show_email"] else None,
        phone=profile.phone if contact_cfg["show_phone"] else None,
        links=PublicProfileLinks(
            linkedin=links_data["linkedin"],
            github=links_data["github"],
            website=profile.website,
            other=links_data["other"],
        ),
        interests=list(profile.interests or []),
        sections=PublicProfileSections(
            education=public_educations,
            academics=public_academics,
            projects=public_projects,
            skills=public_skills,
            certificates=public_certificates,
            experience=public_experiences,
            achievements=public_achievements,
        ),
    )
