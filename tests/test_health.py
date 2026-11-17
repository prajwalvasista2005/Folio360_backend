"""Tests for application health, OpenAPI documentation, and application factory settings."""

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import app, create_app


@pytest.fixture
def client() -> TestClient:
    """Fixture providing a FastAPI TestClient instance."""
    with TestClient(app) as test_client:
        yield test_client


def test_health_check_endpoint(client: TestClient) -> None:
    """Verify that GET /api/v1/health returns HTTP 200 and valid default health payload."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "healthy"
    assert data["application"] == "Folio360"
    assert data["version"] == "1.0.0"


def test_custom_settings_affects_health_endpoint() -> None:
    """Verify that a custom Settings instance passed to create_app affects the health route."""
    custom_settings = Settings(
        APP_NAME="CustomFolioApp",
        APP_VERSION="3.0.0",
        API_V1_PREFIX="/api/v1",
    )
    custom_app = create_app(settings=custom_settings)

    with TestClient(custom_app) as custom_client:
        response = custom_client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["application"] == "CustomFolioApp"
        assert data["version"] == "3.0.0"
        assert data["status"] == "healthy"


def test_openapi_schema(client: TestClient) -> None:
    """Verify that OpenAPI schema is generated and includes the health check path."""
    response = client.get("/openapi.json")
    assert response.status_code == 200

    schema = response.json()
    assert schema["info"]["title"] == "Folio360"
    assert schema["info"]["version"] == "1.0.0"
    assert "/api/v1/health" in schema["paths"]
    assert "get" in schema["paths"]["/api/v1/health"]


def test_docs_ui(client: TestClient) -> None:
    """Verify that Swagger UI documentation endpoint is accessible."""
    response = client.get("/docs")
    assert response.status_code == 200
    assert "swagger-ui" in response.text.lower() or "html" in response.headers.get("content-type", "")


def test_cors_preflight(client: TestClient) -> None:
    """Verify that CORS preflight requests from allowed origins receive appropriate CORS headers."""
    headers = {
        "Origin": "http://localhost:3000",
        "Access-Control-Request-Method": "GET",
    }
    response = client.options("/api/v1/health", headers=headers)
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"
