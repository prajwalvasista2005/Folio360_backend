"""Authenticated Overview dashboard analytics routes under /api/v1/analytics."""

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.api.deps.auth import get_current_verified_user
from app.db.session import get_db
from app.models.user import User
from app.schemas.analytics import DashboardSummaryResponse
from app.services import analytics_service

router = APIRouter(prefix="/analytics", tags=["Analytics"])


@router.get(
    "/dashboard",
    response_model=DashboardSummaryResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Overview dashboard summary for the authenticated user",
)
def get_dashboard(
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> DashboardSummaryResponse:
    """Return owner-scoped profile summary, completeness, counts, and recent activity."""
    return analytics_service.get_dashboard_summary(db, user=current_user)
