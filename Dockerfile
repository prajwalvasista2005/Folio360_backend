FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt ./
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --timeout=30 --retries=5 -r requirements.txt

RUN adduser --disabled-password --gecos "" --uid 1000 appuser

COPY --chown=appuser:appuser alembic.ini pytest.ini ./
COPY --chown=appuser:appuser alembic ./alembic
COPY --chown=appuser:appuser app ./app
COPY --chown=appuser:appuser tests ./tests

USER appuser

EXPOSE 8000

CMD ["python", "-m", "app.server", "--host", "0.0.0.0", "--port", "8000"]
