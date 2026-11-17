"""Health check route reporting service status."""

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, Field

from app.core.config import Settings, get_settings

router = APIRouter(tags=["Health"])


def get_current_settings(request: Request) -> Settings:
    """Retrieve the settings instance attached to the active application."""
    return getattr(request.app.state, "settings", None) or get_settings()


class HealthResponse(BaseModel):
    """Schema for health status response."""

    status: str = Field(
        default="healthy",
        description="Current operational status of the backend application",
        examples=["healthy"],
    )
    application: str = Field(
        description="Name of the application",
        examples=["Folio360"],
    )
    version: str = Field(
        description="Semantic version of the application",
        examples=["1.0.0"],
    )


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Health check",
    description=(
        "Returns the operational health status of the Folio360 backend service. "
        "Reports application-level availability."
    ),
)
def check_health(
    settings: Settings = Depends(get_current_settings),
) -> HealthResponse:
    """Return application health information."""
    return HealthResponse(
        status="healthy",
        application=settings.APP_NAME,
        version=settings.APP_VERSION,
    )
