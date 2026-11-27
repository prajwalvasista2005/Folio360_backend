"""AI-powered career skill gap analysis service using Gemini structured JSON output."""

from collections.abc import Mapping, Sequence
import json
import logging
from typing import Any
from urllib.parse import quote

import httpx
from pydantic import ValidationError

from app.core.config import Settings, get_settings
from app.models.skill import Skill
from app.schemas.skill import GapAnalysisResponse
from app.services.ai_analyzer_provider import (
    AIAnalyzerConfigError,
    AIProviderOutputError,
    AIProviderRateLimitError,
    AIProviderTimeoutError,
    AIProviderUnavailableError,
    _strip_json_fences,
)

logger = logging.getLogger("folio360.skill_analysis")

DEFAULT_GAP_ANALYSIS_MODEL = "gemini-3.5-flash-lite"

_GAP_ANALYSIS_SYSTEM_PROMPT = """
You are an expert career advisor and workforce skills strategist for Folio360.
Compare the user's current skill inventory against their target role and return ONLY a single JSON object matching this exact schema:
{
  "match_percentage": <integer between 0 and 100>,
  "missing_skills": [<list of concise high-priority skill gaps required for the target role>],
  "recommendations": [<list of concise nice-to-have skill additions or growth recommendations>]
}
Rules:
1. "match_percentage" must be a realistic integer from 0 to 100 reflecting how well the user's current skills cover the target role.
2. "missing_skills" must list specific, high-priority skills the user lacks for the target role (avoid repeating skills they already have).
3. "recommendations" must list helpful nice-to-have skills, tools, or next-step additions that strengthen competitiveness for the target role.
4. Keep each item in "missing_skills" and "recommendations" concise (2-8 words).
5. Return strictly valid JSON with no markdown fences or extra commentary.
""".strip()


def _format_skill_entry(skill: Skill | Mapping[str, Any]) -> str:
    if isinstance(skill, Mapping):
        name = str(skill.get("name", "")).strip()
        category = str(skill.get("category", "technical")).strip() or "technical"
        proficiency = skill.get("proficiency")
    else:
        name = skill.name.strip()
        category = skill.category.strip() or "technical"
        proficiency = skill.proficiency

    if proficiency and str(proficiency).strip():
        return f"- {name} (category: {category}, proficiency: {str(proficiency).strip()})"
    return f"- {name} (category: {category})"


def _build_gap_analysis_prompt(
    *,
    current_skills: Sequence[Skill | Mapping[str, Any]],
    target_role: str,
) -> str:
    formatted_skills = [
        _format_skill_entry(skill)
        for skill in current_skills
        if (skill.get("name") if isinstance(skill, Mapping) else skill.name)
    ]
    skills_block = "\n".join(formatted_skills) if formatted_skills else "None listed yet."
    return (
        f"{_GAP_ANALYSIS_SYSTEM_PROMPT}\n\n"
        f"Target Role: {target_role.strip()}\n\n"
        f"Current User Skills:\n{skills_block}"
    )


def analyze_skill_gaps(
    *,
    current_skills: Sequence[Skill | Mapping[str, Any]],
    target_role: str,
    settings: Settings | None = None,
    client: httpx.Client | None = None,
) -> GapAnalysisResponse:
    """Analyze gaps between a user's current skills and a target role using Gemini."""
    active_settings = settings or get_settings()

    if active_settings.AI_ANALYZER_PROVIDER == "mock":
        if active_settings.ENVIRONMENT in {"production", "staging"}:
            raise RuntimeError(
                "Mock AI analyzer is forbidden when ENVIRONMENT is production or staging"
            )
        return GapAnalysisResponse(
            match_percentage=65 if current_skills else 20,
            missing_skills=[
                f"Core {target_role.strip()} domain knowledge",
                "System architecture & design",
            ],
            recommendations=[
                "Cross-functional stakeholder communication",
                "Automated testing & observability",
            ],
        )

    if active_settings.AI_ANALYZER_PROVIDER == "none" and active_settings.AI_ANALYZER_API_KEY is None:
        raise AIAnalyzerConfigError("AI skill analyzer provider is not configured")

    if active_settings.AI_ANALYZER_API_KEY is None:
        raise AIAnalyzerConfigError(
            "AI_ANALYZER_API_KEY is required for skill gap analysis"
        )

    api_key = active_settings.AI_ANALYZER_API_KEY.get_secret_value().strip()
    if not api_key:
        raise AIAnalyzerConfigError("AI_ANALYZER_API_KEY must not be blank")

    model_name = (active_settings.AI_ANALYZER_MODEL or DEFAULT_GAP_ANALYSIS_MODEL).strip()
    base_url = active_settings.AI_ANALYZER_BASE_URL.rstrip("/")
    endpoint = (
        f"{base_url}/v1beta/models/"
        f"{quote(model_name, safe='.-_:')}:generateContent"
    )
    prompt = _build_gap_analysis_prompt(
        current_skills=current_skills,
        target_role=target_role,
    )
    request_body = {
        "contents": [
            {
                "parts": [
                    {"text": prompt},
                ]
            }
        ],
        "generationConfig": {
            "responseMimeType": "application/json",
            "temperature": 0.2,
        },
    }
    headers = {
        "Content-Type": "application/json",
        "x-goog-api-key": api_key,
    }

    try:
        if client is not None:
            response = client.post(
                endpoint,
                headers=headers,
                json=request_body,
                timeout=active_settings.AI_ANALYZER_TIMEOUT_SECONDS,
            )
        else:
            with httpx.Client(timeout=active_settings.AI_ANALYZER_TIMEOUT_SECONDS) as http_client:
                response = http_client.post(
                    endpoint,
                    headers=headers,
                    json=request_body,
                )
    except httpx.TimeoutException as exc:
        raise AIProviderTimeoutError("AI provider request timed out") from exc
    except httpx.HTTPError as exc:
        logger.warning(
            "Skill gap analysis transport failure: exception=%s",
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
        return GapAnalysisResponse.model_validate(parsed)
    except ValidationError as exc:
        raise AIProviderOutputError(
            "AI provider output failed GapAnalysisResponse validation"
        ) from exc
