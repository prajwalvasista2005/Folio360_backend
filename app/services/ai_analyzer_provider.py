"""AI Document Analyzer provider abstraction, Gemini REST adapter, and deterministic test double."""

import base64
import json
import logging
from typing import Literal, Protocol
from urllib.parse import quote

import httpx
from pydantic import ValidationError

from app.core.config import Settings
from app.schemas.document import DocumentMimeType
from app.schemas.document_analysis import DocumentExtractionPayload

logger = logging.getLogger("folio360.ai_analyzer")

MockAnalyzerMode = Literal[
    "marksheet",
    "certificate",
    "partial",
    "timeout",
    "rate_limit",
    "unavailable",
    "malformed_json",
    "invalid_schema",
]

_EXTRACTION_SYSTEM_INSTRUCTIONS = """
You are Folio360's academic document extraction assistant.
Analyze the attached PDF or image document and return ONLY one JSON object conforming strictly to:
{
  "document_type": "marksheet" | "certificate" | "other",
  "is_verified": false,
  "summary": "1-3 sentence concise factual summary of the document",
  "confidence": <float 0.0..1.0 or null>,
  "uncertain_fields": [<dotted field names where text is blurry, truncated, or ambiguous>],
  "extracted_text_excerpt": <short literal source excerpt or null>,
  "marksheet": {
    "institution_name": <string or null>,
    "student_name": <string or null>,
    "program_or_course": <string or null>,
    "semester_or_exam": <string or null>,
    "academic_year": <string or null>,
    "subjects": [
      {
        "subject_name": <string>,
        "subject_code": <string or null>,
        "marks_obtained": <number or null>,
        "max_marks": <number or null>,
        "grade": <string or null>,
        "raw_mark_text": <string or null>,
        "uncertain": <boolean>
      }
    ],
    "total_marks_obtained": <number or null>,
    "total_max_marks": <number or null>,
    "result_status": <string or null>
  } | null,
  "certificate": {
    "certificate_title": <string or null>,
    "issuing_institution": <string or null>,
    "recipient_name": <string or null>,
    "award_or_qualification": <string or null>,
    "issue_date": <string or null>
  } | null
}
Rules:
1. Never invent missing marks, grades, totals, dates, or institution names. Set missing fields to null.
2. Do not calculate totals or normalize marks; preserve raw source values in marks_obtained/grade/raw_mark_text.
3. Always set "is_verified": false.
4. For marksheets populate "marksheet" and set "certificate": null; for certificates populate "certificate" and set "marksheet": null.
5. List any unreadable or low-confidence fields in "uncertain_fields".
""".strip()


class AIAnalyzerError(Exception):
    """Base exception for AI document analysis provider errors."""


class AIAnalyzerConfigError(AIAnalyzerError):
    """Raised when no AI analyzer provider or required credentials are configured."""


class AIProviderUnavailableError(AIAnalyzerError):
    """Raised when the configured AI provider cannot be reached or returns 5xx."""


class AIProviderTimeoutError(AIAnalyzerError):
    """Raised when the AI provider request times out."""


class AIProviderRateLimitError(AIAnalyzerError):
    """Raised when the AI provider enforces rate limits (HTTP 429)."""


class AIProviderOutputError(AIAnalyzerError):
    """Raised when the AI provider returns malformed JSON or invalid schema output."""


class AIAnalyzerProvider(Protocol):
    """Provider abstraction isolating external AI vendor SDK/REST details."""

    provider_name: str
    model_name: str

    def analyze_document(
        self,
        *,
        data: bytes,
        mime_type: DocumentMimeType,
        category_hint: str,
    ) -> DocumentExtractionPayload:
        """Analyze trusted document bytes and return schema-validated extraction data."""
        ...


def _strip_json_fences(raw_text: str) -> str:
    stripped = raw_text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        return "\n".join(lines).strip()
    return stripped


class GeminiDocumentAnalyzer:
    """Gemini REST API adapter supporting PDF, JPEG, and PNG via structured JSON mode."""

    provider_name: str = "gemini"

    def __init__(
        self,
        *,
        api_key: str,
        model_name: str = "gemini-2.5-flash",
        base_url: str = "https://generativelanguage.googleapis.com",
        timeout_seconds: float = 30.0,
        client: httpx.Client | None = None,
    ) -> None:
        if not api_key or not api_key.strip():
            raise AIAnalyzerConfigError("Gemini API key is required")
        self._api_key = api_key.strip()
        self.model_name = model_name.strip()
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds
        self._injected_client = client

    def analyze_document(
        self,
        *,
        data: bytes,
        mime_type: DocumentMimeType,
        category_hint: str,
    ) -> DocumentExtractionPayload:
        endpoint = (
            f"{self._base_url}/v1beta/models/"
            f"{quote(self.model_name, safe='.-_:')}:generateContent"
        )
        prompt = (
            f"{_EXTRACTION_SYSTEM_INSTRUCTIONS}\n"
            f"Document vault category hint (advisory only): {category_hint}."
        )
        encoded = base64.b64encode(data).decode("ascii")
        request_body = {
            "contents": [
                {
                    "parts": [
                        {"text": prompt},
                        {
                            "inline_data": {
                                "mime_type": mime_type,
                                "data": encoded,
                            }
                        },
                    ]
                }
            ],
            "generationConfig": {
                "responseMimeType": "application/json",
                "temperature": 0.0,
            },
        }
        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": self._api_key,
        }

        try:
            if self._injected_client is not None:
                response = self._injected_client.post(
                    endpoint,
                    headers=headers,
                    json=request_body,
                    timeout=self._timeout_seconds,
                )
            else:
                with httpx.Client(timeout=self._timeout_seconds) as client:
                    response = client.post(
                        endpoint,
                        headers=headers,
                        json=request_body,
                    )
        except httpx.TimeoutException as exc:
            raise AIProviderTimeoutError("AI provider request timed out") from exc
        except httpx.HTTPError as exc:
            logger.warning(
                "AI provider transport failure: exception=%s",
                type(exc).__name__,
            )
            raise AIProviderUnavailableError("AI provider connection failed") from exc

        if response.status_code == 429:
            raise AIProviderRateLimitError("AI provider rate limit exceeded")
        if response.status_code >= 500:
            raise AIProviderUnavailableError(
                f"AI provider returned HTTP {response.status_code}"
            )
        if response.status_code >= 400:
            raise AIProviderOutputError(
                f"AI provider rejected request with HTTP {response.status_code}"
            )

        try:
            payload = response.json()
            candidates = payload["candidates"]
            parts = candidates[0]["content"]["parts"]
            raw_json_text = _strip_json_fences(str(parts[0]["text"]))
            parsed = json.loads(raw_json_text)
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise AIProviderOutputError("Malformed AI provider response payload") from exc

        try:
            return DocumentExtractionPayload.model_validate(parsed)
        except ValidationError as exc:
            raise AIProviderOutputError("AI provider output failed schema validation") from exc


class MockDocumentAnalyzer:
    """Deterministic test/dev provider double; strictly forbidden in production/staging."""

    provider_name: str = "mock"
    model_name: str = "mock-academic-v1"

    def __init__(self, *, mode: MockAnalyzerMode = "marksheet") -> None:
        self._mode = mode

    def analyze_document(
        self,
        *,
        data: bytes,
        mime_type: DocumentMimeType,
        category_hint: str,
    ) -> DocumentExtractionPayload:
        del data, mime_type
        if self._mode == "timeout":
            raise AIProviderTimeoutError("Mock AI provider timed out")
        if self._mode == "rate_limit":
            raise AIProviderRateLimitError("Mock AI provider rate limited")
        if self._mode == "unavailable":
            raise AIProviderUnavailableError("Mock AI provider unavailable")
        if self._mode == "malformed_json":
            raise AIProviderOutputError("Mock malformed JSON from provider")
        if self._mode == "invalid_schema":
            # Passes an invalid structure through DocumentExtractionPayload.model_validate
            return DocumentExtractionPayload.model_validate(
                {"document_type": "marksheet", "is_verified": True, "summary": "bad"}
            )
        if self._mode == "partial":
            return DocumentExtractionPayload.model_validate(
                {
                    "document_type": "marksheet",
                    "is_verified": False,
                    "summary": "Partial Semester 5 marksheet extracted; grade table partially blurry.",
                    "confidence": 0.62,
                    "uncertain_fields": ["marksheet.total_marks_obtained", "marksheet.subjects[0].grade"],
                    "marksheet": {
                        "institution_name": "RV College of Engineering",
                        "student_name": None,
                        "program_or_course": "B.E. Computer Science",
                        "semester_or_exam": "Semester 5",
                        "academic_year": None,
                        "subjects": [
                            {
                                "subject_name": "Operating Systems",
                                "subject_code": "CS501",
                                "marks_obtained": 84.0,
                                "max_marks": 100.0,
                                "grade": None,
                                "raw_mark_text": "84/100",
                                "uncertain": True,
                            }
                        ],
                        "total_marks_obtained": None,
                        "total_max_marks": None,
                        "result_status": None,
                    },
                    "certificate": None,
                }
            )
        if self._mode == "certificate" or category_hint == "certificate":
            return DocumentExtractionPayload.model_validate(
                {
                    "document_type": "certificate",
                    "is_verified": False,
                    "summary": "Academic achievement certificate issued by RV College of Engineering.",
                    "confidence": 0.91,
                    "uncertain_fields": [],
                    "certificate": {
                        "certificate_title": "Dean's Merit Certificate",
                        "issuing_institution": "RV College of Engineering",
                        "recipient_name": "Prajwal Vasista",
                        "award_or_qualification": "First Class with Distinction",
                        "issue_date": "2025-06-15",
                    },
                    "marksheet": None,
                }
            )
        return DocumentExtractionPayload.model_validate(
            {
                "document_type": "marksheet",
                "is_verified": False,
                "summary": "Semester 5 B.E. marksheet containing two subjects.",
                "confidence": 0.94,
                "uncertain_fields": [],
                "marksheet": {
                    "institution_name": "RV College of Engineering",
                    "student_name": "Prajwal Vasista",
                    "program_or_course": "B.E. Computer Science & Engineering",
                    "semester_or_exam": "Semester 5",
                    "academic_year": "2024-2025",
                    "subjects": [
                        {
                            "subject_name": "Database Management Systems",
                            "subject_code": "21CS52",
                            "marks_obtained": 91.0,
                            "max_marks": 100.0,
                            "grade": "S",
                            "raw_mark_text": "91",
                            "uncertain": False,
                        },
                        {
                            "subject_name": "Computer Networks",
                            "subject_code": "21CS53",
                            "marks_obtained": 86.0,
                            "max_marks": 100.0,
                            "grade": "A",
                            "raw_mark_text": "86",
                            "uncertain": False,
                        },
                    ],
                    "total_marks_obtained": 177.0,
                    "total_max_marks": 200.0,
                    "result_status": "PASS",
                },
                "certificate": None,
            }
        )


def build_ai_analyzer_provider(settings: Settings) -> AIAnalyzerProvider:
    """Instantiate the configured AI Document Analyzer provider securely."""
    if settings.AI_ANALYZER_PROVIDER == "none":
        raise AIAnalyzerConfigError("AI document analyzer provider is not configured")

    if settings.AI_ANALYZER_PROVIDER == "mock":
        if settings.ENVIRONMENT in {"production", "staging"}:
            raise RuntimeError(
                "Mock AI analyzer is forbidden when ENVIRONMENT is production or staging"
            )
        return MockDocumentAnalyzer(mode="marksheet")

    if settings.AI_ANALYZER_API_KEY is None:
        raise AIAnalyzerConfigError(
            "AI_ANALYZER_API_KEY is required when AI_ANALYZER_PROVIDER is 'gemini'"
        )

    return GeminiDocumentAnalyzer(
        api_key=settings.AI_ANALYZER_API_KEY.get_secret_value(),
        model_name=settings.AI_ANALYZER_MODEL,
        base_url=settings.AI_ANALYZER_BASE_URL,
        timeout_seconds=settings.AI_ANALYZER_TIMEOUT_SECONDS,
    )
