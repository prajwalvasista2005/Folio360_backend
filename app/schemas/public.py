"""Pydantic v2 response schemas for public profile viewing under /api/v1/public/*."""

from pydantic import BaseModel, Field

from app.schemas.document import DocumentRef


class PublicProfileLinkItem(BaseModel):
    """External link item on a public profile."""

    label: str
    url: str


class PublicProfileLinks(BaseModel):
    """Public links object returned on public profiles."""

    linkedin: str | None = None
    github: str | None = None
    website: str | None = None
    other: list[PublicProfileLinkItem] = Field(default_factory=list)


class PublicProfileEducation(BaseModel):
    """Publicly visible education record summary."""

    institution: str
    university_or_board: str | None = None
    education_level: str | None = None
    degree: str
    programme: str | None = None
    branch: str | None = None
    specialization: str | None = None
    country: str | None = None
    state: str | None = None
    start_month: int | None = None
    start_year: int | None = None
    end_month: int | None = None
    end_year: int | None = None
    is_current: bool = False
    description: str | None = None
    result: str | None = None
    achievements: list[str] = Field(default_factory=list)
    documents: list[DocumentRef] = Field(default_factory=list)


class PublicProfileProjectImage(BaseModel):
    """Publicly accessible cover image for a public project."""

    url: str
    alt: str | None = None


class PublicProfileProject(BaseModel):
    """Publicly visible portfolio project."""

    title: str
    summary: str
    description: str | None = None
    category: str
    technologies: list[str] = Field(default_factory=list)
    images: list[PublicProfileProjectImage] = Field(default_factory=list)
    github_url: str | None = None
    live_url: str | None = None
    start_date: str | None = None
    end_date: str | None = None
    featured: bool = False


class PublicProfileCertificate(BaseModel):
    """Publicly visible certificate (excludes private Vault storage keys/URLs)."""

    name: str
    issuer: str
    category: str = "course"
    issue_date: str | None = None
    expiry_date: str | None = None
    credential_id: str | None = None
    verification_url: str | None = None
    verification_status: str = "self_reported"
    featured: bool = False


class PublicProfileAchievement(BaseModel):
    """Publicly visible achievement (excludes private Vault storage keys/URLs)."""

    title: str
    category: str
    organization: str | None = None
    date: str | None = None
    description: str | None = None
    featured: bool = False


class PublicProfileExperience(BaseModel):
    """Publicly visible experience record (excludes private Vault storage keys/URLs)."""

    type: str
    organization: str
    role: str
    location: str | None = None
    is_remote: bool = False
    organization_url: str | None = None
    start_date: str
    end_date: str | None = None
    is_current: bool = False
    description: str | None = None
    highlights: list[str] = Field(default_factory=list)
    skills: list[str] = Field(default_factory=list)
    featured: bool = False


class PublicProfileSkill(BaseModel):
    """Publicly visible skill summary (excludes private internal IDs)."""

    name: str
    category: str
    proficiency: str | None = None


class PublicProfileAcademics(BaseModel):
    """Publicly visible academic CGPA summary when explicitly enabled."""

    cgpa: float


class PublicProfileSections(BaseModel):
    """Public sections payload matching frontend PublicProfile.sections."""

    education: list[PublicProfileEducation] = Field(default_factory=list)
    education_documents: list[DocumentRef] = Field(default_factory=list)
    academics: PublicProfileAcademics | None = None
    projects: list[PublicProfileProject] = Field(default_factory=list)
    skills: list[PublicProfileSkill] = Field(default_factory=list)
    certificates: list[PublicProfileCertificate] = Field(default_factory=list)
    experience: list[PublicProfileExperience] = Field(default_factory=list)
    achievements: list[PublicProfileAchievement] = Field(default_factory=list)


class PublicProfileResponse(BaseModel):
    """Serialized public profile payload for GET /api/v1/public/profiles/{slug}."""

    slug: str
    full_name: str
    headline: str | None = None
    bio: str | None = None
    avatar_url: str | None = None
    location: str | None = None
    contact_email: str | None = None
    phone: str | None = None
    links: PublicProfileLinks = Field(default_factory=PublicProfileLinks)
    interests: list[str] = Field(default_factory=list)
    sections: PublicProfileSections = Field(default_factory=PublicProfileSections)
