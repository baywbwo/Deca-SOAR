# DECA SOAR image for gateway, Temporal worker, broker and jobs (phase 0). Build from the repo root:
#   docker build -f deploy/deca/Dockerfile -t deca-soar:<git-sha> .
FROM python:3.12-slim-bookworm@sha256:REPLACE_WITH_PINNED_DIGEST AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY pyproject.toml ./
COPY src ./src
RUN python -m venv /opt/venv && /opt/venv/bin/pip install .

FROM python:3.12-slim-bookworm@sha256:REPLACE_WITH_PINNED_DIGEST
RUN useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin deca
COPY --from=build /opt/venv /opt/venv
COPY migrations /app/migrations
COPY policy /app/policy
ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    DECA_MIGRATIONS_DIR=/app/migrations DECA_POLICY_DIR=/app/policy
WORKDIR /app
USER 10001:10001
# Overridden per service in docker-compose.yml.
CMD ["uvicorn", "deca_soar.broker.app:app", "--host", "0.0.0.0", "--port", "8100", "--no-server-header"]
