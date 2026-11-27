"""SQLAlchemy ORM model exports for application and Alembic metadata discovery."""

from app.db.base import Base
from app.models.certificate import (
    Achievement,
    AchievementDocument,
    Certificate,
    CertificateSkill,
)
from app.models.document import Document, EducationDocument
from app.models.document_analysis import DocumentAnalysis
from app.models.education import Education
from app.models.email_verification_token import EmailVerificationToken
from app.models.experience import Experience, ExperienceDocument, ExperienceSkill
from app.models.github import GitHubConnection, GitHubOAuthState
from app.models.oauth import OAuthAccount, OAuthExchangeCode, OAuthState
from app.models.password_reset_token import PasswordResetToken
from app.models.profile import UserProfile, UserProfileActivity
from app.models.project import Project, ProjectImage
from app.models.refresh_session import RefreshSession
from app.models.skill import Skill
from app.models.user import User

__all__ = [
    "Base",
    "User",
    "EmailVerificationToken",
    "PasswordResetToken",
    "RefreshSession",
    "OAuthAccount",
    "OAuthState",
    "OAuthExchangeCode",
    "UserProfile",
    "UserProfileActivity",
    "Education",
    "Document",
    "EducationDocument",
    "DocumentAnalysis",
    "Project",
    "ProjectImage",
    "GitHubConnection",
    "GitHubOAuthState",
    "Skill",
    "Certificate",
    "CertificateSkill",
    "Achievement",
    "AchievementDocument",
    "Experience",
    "ExperienceSkill",
    "ExperienceDocument",
]
