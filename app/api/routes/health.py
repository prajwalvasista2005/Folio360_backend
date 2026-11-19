"""Health and readiness check routes reporting service status."""

from typing import Literal

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.core.config import Settings, get_settings
from app.db.session import check_database_readiness

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


class ReadinessResponse(BaseModel):
    """Schema for database readiness status response."""

    status: Literal["ready", "unavailable"] = Field(
        description="Database readiness status for serving database-backed requests",
        examples=["ready"],
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


@router.get(
    "/health/ready",
    response_model=ReadinessResponse,
    status_code=status.HTTP_200_OK,
    responses={
        status.HTTP_503_SERVICE_UNAVAILABLE: {
            "model": ReadinessResponse,
            "description": "Database is unconfigured, unreachable, timed out, or readiness concurrency limit reached",
        }
    },
    summary="Database readiness check",
    description=(
        "Synchronous database readiness probe executing SELECT 1 with bounded "
        "per-process concurrency via a dedicated NullPool readiness engine."
    ),
)
def readiness_check(
    request: Request,
    settings: Settings = Depends(get_current_settings),
) -> ReadinessResponse | JSONResponse:
    """Synchronous readiness check verifying PostgreSQL reachability within probe capacity."""
    is_ready = check_database_readiness(
        readiness_engine=getattr(request.app.state, "db_readiness_engine", None),
        readiness_semaphore=getattr(request.app.state, "db_readiness_semaphore", None),
        settings=settings,
    )
    if not is_ready:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "unavailable"},
        )
    return ReadinessResponse(status="ready")
