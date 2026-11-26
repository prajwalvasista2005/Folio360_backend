"""Unit tests for Phase 2 Stage 6 AI Analyzer schemas, state machine, Gemini adapter, and security."""

import json
import uuid

import httpx
from pydantic import ValidationError
import pytest

from app.core.config import Settings
from app.core.logging import sanitize_log_text
from app.models.document_analysis import DocumentAnalysis
from app.schemas.document_analysis import DocumentExtractionPayload
from app.services.ai_analyzer_provider import (
    AIAnalyzerConfigError,
    AIProviderOutputError,
    AIProviderRateLimitError,
    AIProviderTimeoutError,
    AIProviderUnavailableError,
    GeminiDocumentAnalyzer,
    MockDocumentAnalyzer,
    build_ai_analyzer_provider,
)
from app.services.document_analysis_service import (
    InvalidAnalysisStateTransitionError,
    transition_analysis_status,
)


def _make_analysis(status_val: str = "pending") -> DocumentAnalysis:
    return DocumentAnalysis(
        id=uuid.uuid4(),
        document_id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        status=status_val,
        provider_name="mock",
        model_name="mock-academic-v1",
        analyzer_version="stage6-v1",
    )


def test_analysis_state_machine_and_safe_repr() -> None:
    """Verify allowed and disallowed DocumentAnalysis state transitions and redaction in repr."""
    rec = _make_analysis("pending")
    rec.summary = "Sensitive student grade summary"
    assert "Sensitive" not in repr(rec)
    assert str(rec.document_id) in repr(rec)

    transition_analysis_status(rec, "processing")
    transition_analysis_status(rec, "failed")
    transition_analysis_status(rec, "processing")
    transition_analysis_status(rec, "completed")

    for target in ("pending", "processing", "failed", "completed"):
        with pytest.raises(InvalidAnalysisStateTransitionError) as exc_info:
            transition_analysis_status(rec, target)
        assert exc_info.value.status_code == 409
        assert exc_info.value.error_code == "INVALID_STATE_TRANSITION"

    # Cannot jump directly from pending -> completed
    pending = _make_analysis("pending")
    with pytest.raises(InvalidAnalysisStateTransitionError):
        transition_analysis_status(pending, "completed")


def test_extraction_payload_validation_normalization_and_bounds() -> None:
    """Extraction Pydantic validation preserves numbers, handles nulls, and rejects bogus structures."""
    valid = DocumentExtractionPayload.model_validate(
        {
            "document_type": "marksheet",
            "is_verified": False,
            "summary": "  Semester 5 marksheet for Computer Science.  ",
            "confidence": 0.875,
            "uncertain_fields": ["  marksheet.subjects[0].grade ", "marksheet.subjects[0].grade", "  "],
            "marksheet": {
                "institution_name": "  ",
                "student_name": "Asha Rao",
                "subjects": [
                    {
                        "subject_name": " Operating Systems ",
                        "marks_obtained": 84.5,
                        "max_marks": 100.0,
                        "grade": "   ",
                        "uncertain": True,
                    }
                ],
                "total_marks_obtained": None,
                "total_max_marks": None,
            },
            "certificate": None,
        }
    )
    assert valid.is_verified is False
    assert valid.summary == "Semester 5 marksheet for Computer Science."
    assert valid.uncertain_fields == ["marksheet.subjects[0].grade"]
    assert valid.marksheet is not None
    assert valid.marksheet.institution_name is None
    assert valid.marksheet.subjects[0].marks_obtained == 84.5
    assert valid.marksheet.subjects[0].grade is None

    # Model output claiming is_verified=True is rejected
    with pytest.raises(ValidationError):
        DocumentExtractionPayload.model_validate(
            {"document_type": "certificate", "is_verified": True, "summary": "Cert"}
        )

    # Extra unknown keys are forbidden
    with pytest.raises(ValidationError):
        DocumentExtractionPayload.model_validate(
            {"document_type": "other", "summary": "Ok", "invented_key": "nope"}
        )

    # marks_obtained exceeding max_marks is rejected
    with pytest.raises(ValidationError):
        DocumentExtractionPayload.model_validate(
            {
                "document_type": "marksheet",
                "summary": "Bad marks",
                "marksheet": {
                    "subjects": [
                        {
                            "subject_name": "Math",
                            "marks_obtained": 120.0,
                            "max_marks": 100.0,
                        }
                    ]
                },
            }
        )


def test_gemini_adapter_structured_output_headers_and_failure_mapping() -> None:
    """GeminiDocumentAnalyzer sends key in header only and maps timeouts, 429, 5xx, and bad JSON."""
    captured_requests: list[httpx.Request] = []
    valid_json = json.dumps(
        {
            "document_type": "certificate",
            "is_verified": False,
            "summary": "Degree completion certificate.",
            "confidence": 0.9,
            "uncertain_fields": [],
            "certificate": {
                "certificate_title": "B.E. Degree Certificate",
                "issuing_institution": "VTU",
                "recipient_name": "Prajwal Vasista",
                "award_or_qualification": "First Class",
                "issue_date": "2025-07-01",
            },
            "marksheet": None,
        }
    )

    def _handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        return httpx.Response(
            200,
            json={"candidates": [{"content": {"parts": [{"text": valid_json}]}}]},
        )

    client = httpx.Client(transport=httpx.MockTransport(_handler))
    adapter = GeminiDocumentAnalyzer(
        api_key="AIzaSySecretTestKeyForHeaderOnly",
        model_name="gemini-2.5-flash",
        base_url="https://generativelanguage.googleapis.com",
        timeout_seconds=10.0,
        client=client,
    )
    out = adapter.analyze_document(
        data=b"%PDF-1.7\n%%EOF\n",
        mime_type="application/pdf",
        category_hint="certificate",
    )
    assert out.document_type == "certificate"
    assert out.certificate is not None
    assert out.certificate.issuing_institution == "VTU"
    assert len(captured_requests) == 1
    req = captured_requests[0]
    assert req.headers.get("x-goog-api-key") == "AIzaSySecretTestKeyForHeaderOnly"
    assert "AIzaSySecretTestKeyForHeaderOnly" not in str(req.url)

    # 429 -> AIProviderRateLimitError
    rl_client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(429)))
    with pytest.raises(AIProviderRateLimitError):
        GeminiDocumentAnalyzer(api_key="k", client=rl_client).analyze_document(
            data=b"abc", mime_type="image/png", category_hint="other"
        )

    # 503 -> AIProviderUnavailableError
    unavail_client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(503)))
    with pytest.raises(AIProviderUnavailableError):
        GeminiDocumentAnalyzer(api_key="k", client=unavail_client).analyze_document(
            data=b"abc", mime_type="image/png", category_hint="other"
        )

    # Timeout -> AIProviderTimeoutError
    def _timeout_handler(r: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=r)

    timeout_client = httpx.Client(transport=httpx.MockTransport(_timeout_handler))
    with pytest.raises(AIProviderTimeoutError):
        GeminiDocumentAnalyzer(api_key="k", client=timeout_client).analyze_document(
            data=b"abc", mime_type="image/png", category_hint="other"
        )

    # Malformed non-JSON / invalid schema -> AIProviderOutputError
    bad_json_client = httpx.Client(
        transport=httpx.MockTransport(
            lambda r: httpx.Response(
                200,
                json={"candidates": [{"content": {"parts": [{"text": "not-json"}]}}]},
            )
        )
    )
    with pytest.raises(AIProviderOutputError):
        GeminiDocumentAnalyzer(api_key="k", client=bad_json_client).analyze_document(
            data=b"abc", mime_type="image/png", category_hint="other"
        )


def test_ai_provider_config_guards_and_log_redaction() -> None:
    """Production forbids mock AI provider and missing Gemini key; logger redacts Gemini keys."""
    unconfigured = Settings(_env_file=None, AI_ANALYZER_PROVIDER="none")
    with pytest.raises(AIAnalyzerConfigError):
        build_ai_analyzer_provider(unconfigured)

    prod_mock = Settings(_env_file=None, ENVIRONMENT="production", AI_ANALYZER_PROVIDER="mock")
    with pytest.raises(RuntimeError):
        build_ai_analyzer_provider(prod_mock)

    with pytest.raises(RuntimeError):
        Settings(
            _env_file=None,
            ENVIRONMENT="production",
            DATABASE_URL="postgresql+psycopg://u:p@db:5432/d",
            JWT_SECRET_KEY="a" * 32,
            RESEND_API_KEY="re_prod_key",
            EMAIL_FROM_ADDRESS="noreply@folio360.com",
            FRONTEND_BASE_URL="https://app.folio360.com",
            CORS_ORIGINS=["https://app.folio360.com"],
            AI_ANALYZER_PROVIDER="gemini",
            AI_ANALYZER_API_KEY=None,
        ).validate_runtime_requirements()

    redacted = sanitize_log_text(
        "headers={'x-goog-api-key': 'super-secret-gemini-key'} ai_analyzer_api_key=abc12345"
    )
    assert "super-secret-gemini-key" not in redacted
    assert "abc12345" not in redacted

    partial = MockDocumentAnalyzer(mode="partial").analyze_document(
        data=b"pdf", mime_type="application/pdf", category_hint="marksheet"
    )
    assert partial.is_verified is False
    assert partial.marksheet is not None
    assert partial.marksheet.total_marks_obtained is None
    assert len(partial.uncertain_fields) == 2
