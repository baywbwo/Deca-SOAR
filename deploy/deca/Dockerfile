# DECA SOAR image for gateway, Temporal worker, broker and jobs (phase 0). Build from the repo root:
#   docker build -f deploy/deca/Dockerfile \
#     --build-arg BASE_IMAGE=python:3.12-slim-bookworm@sha256:<digest> -t deca-soar:<git-sha> .
# The base image must be pinned by digest (review N3): the build stops if BASE_IMAGE still carries
# the placeholder, and scripts/preflight.py --production fails on it too. Record the digest used as
# DECA_BASE_IMAGE in /etc/deca-soar/deca.env (RUNBOOK section 5).
ARG BASE_IMAGE=python:3.12-slim-bookworm@sha256:REPLACE_WITH_PINNED_DIGEST

FROM ${BASE_IMAGE} AS build
ARG BASE_IMAGE
RUN echo "$BASE_IMAGE" | grep -Eq '@sha256:[0-9a-f]{64}$' \
    || { echo "BASE_IMAGE must be pinned as <image>@sha256:<64 hex>" >&2; exit 1; }
WORKDIR /src
COPY pyproject.toml ./
COPY src ./src
COPY deploy/deca/requirements ./deploy/deca/requirements
RUN sh deploy/deca/requirements/install-locked.sh python3 /opt/venv /src

FROM ${BASE_IMAGE}
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
