"""SENTINEL-X application entry point."""

from __future__ import annotations

import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.deps import client_ip, general_limiter
from app.api.v1.router import api_router
from app.core.config import settings
from app.core.errors import register_exception_handlers
from app.core.logging import configure_logging, get_logger

configure_logging()
logger = get_logger("sentinelx.app")

#: Longest request path written to a log line.
MAX_LOGGED_PATH = 256

#: Starlette renamed 413 per RFC 9110 and deprecated the old spelling. Resolved
#: once, through ``hasattr`` rather than ``getattr(..., default)``, because the
#: deprecated attribute warns on access even when it is only the fallback.
CONTENT_TOO_LARGE: int = (
    status.HTTP_413_CONTENT_TOO_LARGE
    if hasattr(status, "HTTP_413_CONTENT_TOO_LARGE")
    else 413
)

DESCRIPTION = """
SENTINEL-X is a security operations platform that simulates enterprise telemetry,
detects suspicious behaviour with a deterministic detection engine, correlates
multi-source evidence into incidents, maps those incidents to MITRE ATT&CK,
reconstructs attack chains, and provides evidence-grounded AI assistance to
analysts.

**Architectural commitment.** Detection is deterministic and happens before any
language model is consulted. Rules, thresholds, sequences, indicator matching and
statistical baselining decide what is suspicious. The AI layer explains and
summarises evidence that already exists; it cannot create, close or reclassify
anything, and the platform is fully functional with no AI provider configured.

**Simulation boundary.** All telemetry is synthetic. All containment actions are
simulated — no EDR, directory service, firewall or cloud provider is contacted.
Evidence collection is the one response action genuinely performed.

Authenticate at `POST /api/v1/auth/login` and send the returned token as
`Authorization: Bearer <token>`.
"""

TAGS_METADATA = [
    {"name": "auth", "description": "Sign-in, accounts and the role model."},
    {"name": "events", "description": "Telemetry ingestion and the normalized event store."},
    {"name": "alerts", "description": "The alert queue and triage workflow."},
    {"name": "incidents", "description": "Correlated incidents: timeline, graph, evidence, ATT&CK."},
    {"name": "hosts", "description": "Asset inventory."},
    {"name": "users", "description": "Identity inventory and behavioural baselines."},
    {"name": "indicators", "description": "IOC store and match history."},
    {"name": "detections", "description": "Detection rule registry and rule self-tests."},
    {"name": "mitre", "description": "ATT&CK catalogue and detection coverage."},
    {"name": "hunting", "description": "Structured and natural-language threat hunting."},
    {"name": "simulations", "description": "Safe attack scenario generation."},
    {"name": "response", "description": "Simulated containment actions and playbooks."},
    {"name": "reports", "description": "Incident report generation and export."},
    {"name": "ai", "description": "Evidence-grounded investigation assistant."},
    {"name": "evaluation", "description": "Measured detection performance."},
    {"name": "cloud", "description": "Cloud control-plane security analytics."},
    {"name": "system", "description": "Dashboard, search, audit log, health."},
]

#: Applied to every response. A security platform that does not set its own
#: security headers is not a good look.
SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "cross-origin-opener-policy": "same-origin",
    "permissions-policy": "geolocation=(), microphone=(), camera=(), payment=()",
    # This API serves JSON, never HTML, so the strictest possible CSP applies.
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    "cache-control": "no-store",
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "startup",
        extra={
            "environment": settings.ENVIRONMENT,
            "ai_configured": settings.ai_enabled,
            "demo_mode": settings.DEMO_MODE,
        },
    )
    if settings.ENVIRONMENT != "production":
        # Convenience for local runs; production uses `alembic upgrade head`.
        from app.core.database import create_all

        create_all()
    yield
    logger.info("shutdown")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=DESCRIPTION,
    openapi_tags=TAGS_METADATA,
    lifespan=lifespan,
    # The interactive docs publish the whole API surface, the version and every
    # schema to an anonymous caller. That is exactly what you want while
    # building and free reconnaissance in production, so they are switched off
    # there. The OpenAPI document is still generated in-process, which is what
    # the auth test walks.
    docs_url=None if settings.ENVIRONMENT == "production" else "/docs",
    redoc_url=None if settings.ENVIRONMENT == "production" else "/redoc",
    openapi_url=None if settings.ENVIRONMENT == "production" else "/openapi.json",
    swagger_ui_parameters={"persistAuthorization": True, "docExpansion": "none"},
)

register_exception_handlers(app)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["authorization", "content-type"],
    max_age=600,
)


@app.middleware("http")
async def request_pipeline(request: Request, call_next):
    """Correlation ID, request logging, body-size cap and security headers."""
    request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
    request.state.request_id = request_id
    started = time.perf_counter()

    # Reject NUL bytes in the URL before anything looks the value up.
    #
    # PostgreSQL cannot store a NUL in a text column and raises rather than
    # truncating, so `GET /api/v1/events/%00` reaches the database as a bound
    # parameter and comes back as a 500. SQLite accepts it happily, which is
    # exactly why this needs to be caught at the edge rather than per-handler:
    # the bug is invisible in local development and appears in production.
    # A NUL in a URL is never legitimate, so it is a 400, not a 404.
    #
    # The path arrives percent-decoded and the query string does not, so both
    # forms are checked. Missing the encoded form would leave the query-string
    # half of the hole open.
    raw_query = request.url.query or ""
    if (
        "\x00" in request.url.path
        or "\x00" in raw_query
        or "%00" in raw_query.lower()
    ):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": {
                "code": "INVALID_REQUEST",
                "message": "The request URL contains a NUL byte.",
            }},
            headers={**SECURITY_HEADERS, "x-request-id": request_id},
        )

    # Reject oversized bodies before they are read into memory. Ingestion is the
    # one endpoint that accepts attacker-influenced content by design.
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > settings.MAX_REQUEST_BYTES:
        return JSONResponse(
            status_code=CONTENT_TOO_LARGE,
            content={"error": {
                "code": "PAYLOAD_TOO_LARGE",
                "message": f"Request body exceeds {settings.MAX_REQUEST_BYTES} bytes.",
            }},
            headers={**SECURITY_HEADERS, "x-request-id": request_id},
        )

    response = await call_next(request)

    duration_ms = int((time.perf_counter() - started) * 1000)
    response.headers["x-request-id"] = request_id
    response.headers["x-response-time-ms"] = str(duration_ms)
    for header, value in SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)

    logger.info(
        "request",
        extra={
            "request_id": request_id,
            "method": request.method,
            # Truncated: the path is caller-controlled, and an unbounded
            # path would let one request write an arbitrarily large log line.
            "path": request.url.path[:MAX_LOGGED_PATH],
            "status": response.status_code,
            "duration_ms": duration_ms,
            "client": client_ip(request),
        },
    )
    return response


@app.middleware("http")
async def global_rate_limit(request: Request, call_next):
    """Per-client budget across the whole API.

    Coarse and per-process by design — see app/core/ratelimit.py for why that is
    a stated limitation rather than a hidden one. Health checks and docs are
    exempt so an orchestrator cannot lock itself out.
    """
    exempt = request.url.path in {
        "/api/v1/system/health", "/docs", "/redoc", "/openapi.json", "/",
    }
    if request.method == "OPTIONS" or exempt:
        return await call_next(request)

    key = f"http:{client_ip(request) or 'unknown'}"
    allowed, remaining, retry_after = general_limiter.check(key)
    if not allowed:
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"error": {
                "code": "RATE_LIMITED",
                "message": f"Too many requests. Retry in {retry_after}s.",
                "details": {"retry_after_seconds": retry_after},
            }},
            headers={**SECURITY_HEADERS, "retry-after": str(retry_after)},
        )

    response = await call_next(request)
    response.headers["x-ratelimit-remaining"] = str(remaining)
    return response


app.include_router(api_router, prefix=settings.API_V1_PREFIX)


@app.get("/", include_in_schema=False)
def root() -> dict[str, str]:
    """A signpost, not an information source.

    This is reachable without a token, so it says only where the API lives.
    ``/system/health`` deliberately withholds version numbers from anonymous
    callers, and publishing the version here would have handed back exactly
    what that endpoint refuses. The version is available on
    ``/system/info``, which requires authentication.
    """
    body = {"name": settings.APP_NAME, "api": settings.API_V1_PREFIX}
    if settings.ENVIRONMENT != "production":
        body["docs"] = "/docs"
    return body
