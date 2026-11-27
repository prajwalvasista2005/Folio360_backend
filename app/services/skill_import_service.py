"""Service for extracting skill import candidates from Projects and uploaded Resumes."""

import base64
from collections.abc import Sequence
import json
import logging
from typing import Any
from urllib.parse import quote
import uuid

import httpx
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.models.document import Document
from app.models.project import Project
from app.models.skill import Skill
from app.schemas.skill import (
    SkillBulkCreateRequest,
    SkillBulkCreateResponse,
    SkillImportCandidate,
    SkillImportCategory,
    SkillImportPreviewRequest,
    SkillImportPreviewResponse,
    SkillImportSource,
    SkillResponse,
)
from app.services.ai_analyzer_provider import (
    AIAnalyzerConfigError,
    AIProviderOutputError,
    AIProviderRateLimitError,
    AIProviderTimeoutError,
    AIProviderUnavailableError,
    _strip_json_fences,
)
from app.services.storage_service import StorageBackend, build_storage_backend, is_trusted_storage_key

logger = logging.getLogger("folio360.skill_import")

DEFAULT_SKILL_IMPORT_MODEL = "gemini-3.5-flash-lite"
_SUPPORTED_RESUME_MIME_TYPES = {"application/pdf", "image/jpeg", "image/png"}
_VALID_PROFICIENCIES = {"Beginner", "Intermediate", "Advanced", "Expert"}

_PROJECT_EXTRACTION_PROMPT = """
You are a universal career skills analyst for Folio360, serving users across all fields and disciplines (engineering, culinary arts, healthcare, design, finance, trades, education, research, business, etc.).
Given the user's projects below, extract universal, concise skill names demonstrated across those projects.
Return ONLY a single JSON object matching this exact schema:
{
  "skills": [
    {
      "name": "<concise skill name, 1-5 words>",
      "category": "technical" | "tool" | "soft",
      "proficiency": "Beginner" | "Intermediate" | "Advanced" | "Expert" | null,
      "source_label": "<title of the project where this skill is demonstrated>"
    }
  ]
}
Category definitions:
- "technical": Domain & Technical Expertise (core subject-matter knowledge, specialized methods, domain practices, frameworks, languages).
- "tool": Tools, Software & Equipment (software applications, instruments, platforms, lab/kitchen/field equipment, tools).
- "soft": Workplace & Soft Skills (leadership, collaboration, communication, project management, client coordination, problem solving).
Rules:
1. Extract concrete, reusable skills (not generic sentences or project titles).
2. Avoid duplicates; keep names clean and standardized (max 100 chars).
3. Return strictly valid JSON with no markdown fences or commentary.
""".strip()

_RESUME_EXTRACTION_PROMPT = """
You are a universal career skills analyst for Folio360, serving users across all fields and disciplines (engineering, culinary arts, healthcare, design, finance, trades, education, research, business, etc.).
Analyze the attached resume (PDF or image) and extract the candidate's demonstrated skills across all sections (skills, experience, projects, certifications, education).
Return ONLY a single JSON object matching this exact schema:
{
  "skills": [
    {
      "name": "<concise skill name, 1-5 words>",
      "category": "technical" | "tool" | "soft",
      "proficiency": "Beginner" | "Intermediate" | "Advanced" | "Expert" | null
    }
  ]
}
Category definitions:
- "technical": Domain & Technical Expertise (core subject-matter knowledge, specialized capabilities, methodologies, domain disciplines).
- "tool": Tools, Software & Equipment (software, platforms, machinery, instruments, equipment).
- "soft": Workplace & Soft Skills (leadership, teamwork, communication, stakeholder management, organization).
Rules:
1. Only extract skills explicitly supported by the resume. Do not invent skills.
2. Keep each skill name concise and standardized (1-5 words, max 100 chars).
3. Return strictly valid JSON with no markdown fences or commentary.
""".strip()

_TOOL_KEYWORDS = {
    "docker",
    "kubernetes",
    "git",
    "github",
    "gitlab",
    "figma",
    "excel",
    "tableau",
    "power bi",
    "autocad",
    "photoshop",
    "illustrator",
    "vscode",
    "vs code",
    "postman",
    "jira",
    "notion",
    "slack",
    "aws",
    "gcp",
    "azure",
    "postgres",
    "postgresql",
    "mysql",
    "redis",
    "mongodb",
    "vite",
    "webpack",
    "terraform",
    "linux",
    "blender",
    "solidworks",
    "matlab",
}


def _classify_technology_fallback(name: str) -> SkillImportCategory:
    lowered = name.strip().lower()
    if lowered in _TOOL_KEYWORDS:
        return "tool"
    return "technical"


def _normalize_proficiency_value(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    title_cased = cleaned.title()
    if title_cased in _VALID_PROFICIENCIES:
        return title_cased
    return None


def _call_gemini_json(
    *,
    parts: list[dict[str, Any]],
    settings: Settings,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    if settings.AI_ANALYZER_API_KEY is None:
        raise AIAnalyzerConfigError("AI_ANALYZER_API_KEY is not configured")

    api_key = settings.AI_ANALYZER_API_KEY.get_secret_value().strip()
    if not api_key:
        raise AIAnalyzerConfigError("AI_ANALYZER_API_KEY must not be blank")

    model_name = (settings.AI_ANALYZER_MODEL or DEFAULT_SKILL_IMPORT_MODEL).strip()
    base_url = settings.AI_ANALYZER_BASE_URL.rstrip("/")
    endpoint = (
        f"{base_url}/v1beta/models/"
        f"{quote(model_name, safe='.-_:')}:generateContent"
    )
    request_body = {
        "contents": [{"parts": parts}],
        "generationConfig": {
            "responseMimeType": "application/json",
            "temperature": 0.1,
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
                timeout=settings.AI_ANALYZER_TIMEOUT_SECONDS,
            )
        else:
            with httpx.Client(timeout=settings.AI_ANALYZER_TIMEOUT_SECONDS) as http_client:
                response = http_client.post(
                    endpoint,
                    headers=headers,
                    json=request_body,
                )
    except httpx.TimeoutException as exc:
        raise AIProviderTimeoutError("AI provider request timed out") from exc
    except httpx.HTTPError as exc:
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
        resp_parts = candidates[0]["content"]["parts"]
        raw_json_text = _strip_json_fences(str(resp_parts[0]["text"]))
        parsed = json.loads(raw_json_text)
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise AIProviderOutputError("Malformed AI provider response payload") from exc

    if not isinstance(parsed, dict):
        raise AIProviderOutputError("Expected JSON object from AI provider")
    return parsed


def _extract_project_skills_with_ai(
    *,
    projects: Sequence[Project],
    settings: Settings,
    client: httpx.Client | None = None,
) -> list[dict[str, Any]]:
    if settings.AI_ANALYZER_PROVIDER == "mock":
        if settings.ENVIRONMENT in {"production", "staging"}:
            raise RuntimeError("Mock AI analyzer is forbidden in production or staging")
        mock_items: list[dict[str, Any]] = []
        for project in projects:
            for tech in project.technologies or []:
                mock_items.append(
                    {
                        "name": tech,
                        "category": _classify_technology_fallback(tech),
                        "proficiency": None,
                        "source_label": project.title,
                    }
                )
        return mock_items

    if settings.AI_ANALYZER_API_KEY is None:
        return []

    project_lines: list[str] = []
    for idx, project in enumerate(projects[:25], start=1):
        techs = ", ".join(project.technologies or []) or "None listed"
        desc = (project.description or "").strip()
        if len(desc) > 800:
            desc = f"{desc[:800]}..."
        project_lines.append(
            f"Project {idx}: {project.title}\n"
            f"Category: {project.category}\n"
            f"Summary: {project.summary}\n"
            f"Technologies/Tools Listed: {techs}\n"
            f"Description: {desc or 'N/A'}"
        )

    prompt = f"{_PROJECT_EXTRACTION_PROMPT}\n\nUser Projects:\n\n" + "\n\n---\n\n".join(project_lines)
    parsed = _call_gemini_json(
        parts=[{"text": prompt}],
        settings=settings,
        client=client,
    )
    raw_skills = parsed.get("skills")
    return raw_skills if isinstance(raw_skills, list) else []


def _extract_resume_skills_with_ai(
    *,
    data: bytes,
    mime_type: str,
    settings: Settings,
    client: httpx.Client | None = None,
) -> list[dict[str, Any]]:
    if settings.AI_ANALYZER_PROVIDER == "mock":
        if settings.ENVIRONMENT in {"production", "staging"}:
            raise RuntimeError("Mock AI analyzer is forbidden in production or staging")
        return [
            {"name": "Project Management", "category": "soft", "proficiency": "Intermediate"},
            {"name": "Data Analysis", "category": "technical", "proficiency": "Advanced"},
        ]

    encoded = base64.b64encode(data).decode("ascii")
    parsed = _call_gemini_json(
        parts=[
            {"text": _RESUME_EXTRACTION_PROMPT},
            {"inline_data": {"mime_type": mime_type, "data": encoded}},
        ],
        settings=settings,
        client=client,
    )
    raw_skills = parsed.get("skills")
    return raw_skills if isinstance(raw_skills, list) else []


def preview_skill_imports(
    db: Session,
    *,
    user_id: uuid.UUID,
    payload: SkillImportPreviewRequest,
    settings: Settings | None = None,
    storage: StorageBackend | None = None,
    client: httpx.Client | None = None,
) -> SkillImportPreviewResponse:
    """Extract deduplicated skill import candidates from user Projects and uploaded Resumes."""
    active_settings = settings or get_settings()

    existing_skills = list(
        db.execute(select(Skill).where(Skill.user_id == user_id)).scalars().all()
    )
    existing_lower = {
        skill.name.strip().lower()
        for skill in existing_skills
        if skill.name and skill.name.strip()
    }

    candidates: list[SkillImportCandidate] = []
    seen_candidate_lower: set[str] = set()
    skipped_existing: list[str] = []
    seen_skipped_lower: set[str] = set()
    notes: list[str] = []

    def _register_candidate(
        *,
        name: Any,
        category: Any,
        proficiency: Any,
        source: SkillImportSource,
        source_label: str | None,
    ) -> None:
        if not isinstance(name, str):
            return
        cleaned_name = name.strip()
        if not cleaned_name or len(cleaned_name) > 100:
            return
        lowered = cleaned_name.lower()
        if lowered in existing_lower:
            if lowered not in seen_skipped_lower:
                seen_skipped_lower.add(lowered)
                skipped_existing.append(cleaned_name)
            return
        if lowered in seen_candidate_lower:
            return
        try:
            candidate = SkillImportCandidate.model_validate(
                {
                    "name": cleaned_name,
                    "category": category if isinstance(category, str) else "technical",
                    "proficiency": _normalize_proficiency_value(proficiency),
                    "source": source,
                    "source_label": source_label,
                }
            )
        except ValidationError:
            return
        seen_candidate_lower.add(lowered)
        candidates.append(candidate)

    requested_sources = list(dict.fromkeys(payload.sources))

    if "project" in requested_sources:
        projects = list(
            db.execute(
                select(Project)
                .where(Project.user_id == user_id)
                .order_by(Project.display_order.asc(), Project.created_at.desc())
            )
            .scalars()
            .all()
        )
        if not projects:
            notes.append("No projects found to extract skills from.")
        else:
            ai_items: list[dict[str, Any]] = []
            try:
                ai_items = _extract_project_skills_with_ai(
                    projects=projects,
                    settings=active_settings,
                    client=client,
                )
            except (
                AIAnalyzerConfigError,
                AIProviderTimeoutError,
                AIProviderRateLimitError,
                AIProviderUnavailableError,
                AIProviderOutputError,
            ) as exc:
                logger.warning("AI project skill extraction skipped: %s", exc)
                notes.append(
                    "AI project text extraction was unavailable; imported structured project technologies instead."
                )

            for item in ai_items:
                if not isinstance(item, dict):
                    continue
                _register_candidate(
                    name=item.get("name"),
                    category=item.get("category"),
                    proficiency=item.get("proficiency"),
                    source="project",
                    source_label=(
                        str(item.get("source_label")).strip()
                        if item.get("source_label")
                        else "Projects"
                    ),
                )

            for project in projects:
                for tech in project.technologies or []:
                    _register_candidate(
                        name=tech,
                        category=_classify_technology_fallback(tech),
                        proficiency=None,
                        source="project",
                        source_label=project.title,
                    )

    if "resume" in requested_sources:
        doc_filters = [
            Document.user_id == user_id,
            Document.category == "resume",
        ]
        if payload.document_id is not None:
            doc_filters.append(Document.id == payload.document_id)

        resume_docs = list(
            db.execute(
                select(Document)
                .where(*doc_filters)
                .order_by(Document.created_at.desc())
            )
            .scalars()
            .all()
        )

        if not resume_docs:
            notes.append(
                "Selected resume document was not found."
                if payload.document_id is not None
                else "No uploaded resume found in Document Vault."
            )
        else:
            selected_doc: Document | None = None
            for doc in resume_docs:
                if (
                    doc.processing_status == "ready"
                    and doc.storage_state == "trusted"
                    and is_trusted_storage_key(
                        doc.storage_key,
                        trusted_namespace=active_settings.DOCUMENT_TRUSTED_NAMESPACE,
                    )
                    and doc.mime_type in _SUPPORTED_RESUME_MIME_TYPES
                    and doc.size_bytes <= active_settings.AI_ANALYZER_MAX_INPUT_BYTES
                ):
                    selected_doc = doc
                    break

            if selected_doc is None:
                latest = resume_docs[0]
                if latest.processing_status in {"pending_scan", "scanning"}:
                    notes.append(
                        f'Resume "{latest.title}" is still being scanned. Try again once it is ready.'
                    )
                elif latest.mime_type not in _SUPPORTED_RESUME_MIME_TYPES:
                    notes.append(
                        f'Resume "{latest.title}" format ({latest.mime_type}) is not supported for AI extraction.'
                    )
                elif latest.size_bytes > active_settings.AI_ANALYZER_MAX_INPUT_BYTES:
                    notes.append(
                        f'Resume "{latest.title}" exceeds the maximum file size for AI extraction.'
                    )
                else:
                    notes.append(
                        f'Resume "{latest.title}" is not in a trusted ready state for AI extraction.'
                    )
            else:
                backend = storage or build_storage_backend(active_settings)
                try:
                    resume_bytes = backend.read_bytes(storage_key=selected_doc.storage_key)
                except Exception as exc:
                    logger.warning(
                        "Failed reading resume bytes for skill import: document_id=%s err=%s",
                        selected_doc.id,
                        type(exc).__name__,
                    )
                    notes.append(
                        f'Resume file "{selected_doc.title}" could not be read from storage.'
                    )
                else:
                    try:
                        resume_items = _extract_resume_skills_with_ai(
                            data=resume_bytes,
                            mime_type=selected_doc.mime_type,
                            settings=active_settings,
                            client=client,
                        )
                    except (
                        AIAnalyzerConfigError,
                        AIProviderTimeoutError,
                        AIProviderRateLimitError,
                        AIProviderUnavailableError,
                        AIProviderOutputError,
                    ) as exc:
                        logger.warning("Resume AI skill extraction failed: %s", exc)
                        notes.append(f"Unable to extract skills from resume right now: {exc}")
                    else:
                        if not resume_items:
                            notes.append(f'No additional skills detected in resume "{selected_doc.title}".')
                        for item in resume_items:
                            if not isinstance(item, dict):
                                continue
                            _register_candidate(
                                name=item.get("name"),
                                category=item.get("category"),
                                proficiency=item.get("proficiency"),
                                source="resume",
                                source_label=selected_doc.title,
                            )

    return SkillImportPreviewResponse(
        candidates=candidates,
        skipped_existing=skipped_existing,
        notes=notes,
    )


def bulk_create_skills(
    db: Session,
    *,
    user_id: uuid.UUID,
    payload: SkillBulkCreateRequest,
) -> SkillBulkCreateResponse:
    """Persist multiple skills for a user, skipping duplicates case-insensitively."""
    existing_skills = list(
        db.execute(select(Skill).where(Skill.user_id == user_id)).scalars().all()
    )
    seen_lower = {
        skill.name.strip().lower()
        for skill in existing_skills
        if skill.name and skill.name.strip()
    }

    new_records: list[Skill] = []
    skipped: list[str] = []

    for item in payload.skills:
        lowered = item.name.strip().lower()
        if lowered in seen_lower:
            skipped.append(item.name)
            continue
        seen_lower.add(lowered)
        record = Skill(
            user_id=user_id,
            name=item.name,
            category=item.category,
            proficiency=item.proficiency,
        )
        db.add(record)
        new_records.append(record)

    if new_records:
        db.commit()
        for record in new_records:
            db.refresh(record)

    return SkillBulkCreateResponse(
        created=[SkillResponse.model_validate(record) for record in new_records],
        skipped=skipped,
    )
