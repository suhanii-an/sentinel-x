# SENTINEL-X backend.
#
# Multi-stage so the runtime image carries no compiler, no build cache and no
# pip metadata for packages it does not need. The final image runs as a
# non-root user with no shell history and a read-only-friendly layout, because
# a container that runs as root is one container escape away from being a real
# problem — and this is a security tool.

# ---------------------------------------------------------------- build stage
FROM python:3.11-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Build dependencies for psycopg and bcrypt. They stay in this stage.
RUN apt-get update \
 && apt-get install --no-install-recommends -y build-essential libpq-dev \
 && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip \
 && /opt/venv/bin/pip install -r requirements.txt

# -------------------------------------------------------------- runtime stage
FROM python:3.11-slim-bookworm AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH"

# libpq5 only — the client library, not the build headers.
RUN apt-get update \
 && apt-get install --no-install-recommends -y libpq5 curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --shell /usr/sbin/nologin --uid 10001 sentinel

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app

# Application code. Detection rules, the ATT&CK catalogue and the indicator
# dataset are copied in rather than mounted: they are part of the artefact, and
# a deployment whose rule pack can be swapped from outside the image is a
# deployment whose detections are not reproducible.
COPY --chown=sentinel:sentinel backend/app ./app
COPY --chown=sentinel:sentinel backend/alembic.ini ./alembic.ini
COPY --chown=sentinel:sentinel backend/migrations ./migrations
COPY --chown=sentinel:sentinel detection-rules /detection-rules
COPY --chown=sentinel:sentinel data /data
COPY --chown=sentinel:sentinel scripts /scripts

ENV DETECTION_RULES_DIR=/detection-rules \
    DATA_DIR=/data \
    PYTHONPATH=/app

USER sentinel

EXPOSE 8000

# The health endpoint is unauthenticated by design: an orchestrator has to be
# able to probe it before any token exists. It reports only whether
# dependencies respond — no versions, no configuration.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8000/api/v1/system/health || exit 1

# One worker by default. The rate limiter keeps its counters in process, so N
# workers means N times the configured budget; docs/deployment.md explains when
# to scale out and what has to move to Redis first.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
