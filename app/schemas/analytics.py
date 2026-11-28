"""Pydantic v2 schemas for the authenticated Overview dashboard summary endpoint."""

from datetime import datetime
from typing import Literal
import uuid

from pydantic import BaseModel, Field

ActivityVerb = Literal[
    "created",
    "updated",
    "deleted",
    "uploaded",
    "confirmed",
    "generated",
    "shared",
]


class DashboardCompleteness(BaseModel):
    """Profile and portfolio completeness percentage."""

    percent: int = Field(ge=0, le=100)


class DashboardContinueItem(BaseModel):
    """Actionable completion suggestion pointing to an existing frontend route."""

    key: str
    label: str
    action_route: str


class DashboardCounts(BaseModel):
    """Owner-scoped portfolio and document counts displayed on Overview."""

    projects: int = Field(ge=0)
    skills: int = Field(ge=0)
    certificates: int = Field(ge=0)
    experience: int = Field(ge=0)
    documents: int = Field(ge=0)
    pending_reviews: int = Field(ge=0)


class DashboardActivityEvent(BaseModel):
    """Normalized recent activity entry derived from persisted user records."""

    id: uuid.UUID
    verb: ActivityVerb
    entity_type: str
    entity_id: uuid.UUID | None = None
    label: str
    created_at: datetime


class DashboardSummaryResponse(BaseModel):
    """Response payload for GET /api/v1/analytics/dashboard."""

    first_name: str
    slug: str | None = None
    avatar_url: str | None = None
    completeness: DashboardCompleteness
    continue_items: list[DashboardContinueItem]
    counts: DashboardCounts
    recent_activity: list[DashboardActivityEvent]
