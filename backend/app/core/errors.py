"""Structured API errors.

Rule: the client gets a stable machine-readable code and a safe human message.
Stack traces, SQL fragments and internal paths stay server-side.  Leaking an
ORM error string to an unauthenticated caller is a genuine information-disclosure
bug, not a cosmetic one.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import get_logger

logger = get_logger("sentinelx.errors")

# Starlette renamed 422 from "Unprocessable Entity" to "Unprocessable Content"
# (RFC 9110) and deprecated the old name. Resolving it once here keeps the
# codebase warning-free on new Starlette without breaking on the older version
# that the minimum pinned FastAPI may pull in.
# Referenced through ``hasattr`` rather than ``getattr(..., default)`` because
# the deprecated attribute emits its warning on access, default or not.
UNPROCESSABLE: int = (
    status.HTTP_422_UNPROCESSABLE_CONTENT
    if hasattr(status, "HTTP_422_UNPROCESSABLE_CONTENT")
    else 422
)


class SentinelError(Exception):
    """Base class for errors that are safe to surface to API clients."""

    code = "INTERNAL_ERROR"
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    message = "An unexpected error occurred."

    def __init__(self, message: str | None = None, *, details: Any = None):
        self.message = message or self.message
        self.details = details
        super().__init__(self.message)


class NotFoundError(SentinelError):
    code = "NOT_FOUND"
    status_code = status.HTTP_404_NOT_FOUND
    message = "Resource not found."


class ValidationFailed(SentinelError):
    code = "VALIDATION_FAILED"
    status_code = UNPROCESSABLE
    message = "Request validation failed."


class InvalidEventError(SentinelError):
    code = "INVALID_EVENT"
    status_code = UNPROCESSABLE
    message = "Event validation failed."


class UnsafeQueryError(SentinelError):
    code = "UNSAFE_QUERY"
    status_code = status.HTTP_400_BAD_REQUEST
    message = "The requested query was rejected by the query validator."


class AuthenticationError(SentinelError):
    code = "AUTHENTICATION_FAILED"
    status_code = status.HTTP_401_UNAUTHORIZED
    message = "Authentication failed."


class AuthorizationError(SentinelError):
    code = "NOT_AUTHORIZED"
    status_code = status.HTTP_403_FORBIDDEN
    message = "You do not have permission to perform this action."


class RateLimitError(SentinelError):
    code = "RATE_LIMITED"
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    message = "Too many requests."


class AIUnavailableError(SentinelError):
    code = "AI_UNAVAILABLE"
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    message = "The AI investigation assistant is not configured."


class AIValidationError(SentinelError):
    code = "AI_OUTPUT_REJECTED"
    status_code = status.HTTP_502_BAD_GATEWAY
    message = "The AI response failed grounding validation and was discarded."


class ConflictError(SentinelError):
    code = "CONFLICT"
    status_code = status.HTTP_409_CONFLICT
    message = "The request conflicts with the current state of the resource."


#: Longest error message the API will return.
#
# Error messages routinely name the identifier the caller asked for ("Incident
# 'SX-2026-0042' does not exist"), which means a caller controls part of the
# message. Without a cap, a request for a 10 MB identifier is answered with a
# 10 MB error body: free amplification, and a way to flood the log with one
# request. The cap is well above any legitimate message.
MAX_ERROR_MESSAGE = 512


def _safe_message(message: str) -> str:
    text = str(message)
    if len(text) <= MAX_ERROR_MESSAGE:
        return text
    return text[: MAX_ERROR_MESSAGE - 3] + "..."


def _envelope(code: str, message: str, details: Any = None) -> dict[str, Any]:
    body: dict[str, Any] = {"error": {"code": code, "message": _safe_message(message)}}
    if details is not None:
        body["error"]["details"] = details
    return body


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(SentinelError)
    async def _sentinel(request: Request, exc: SentinelError) -> JSONResponse:
        if exc.status_code >= 500:
            logger.error("handled_error", extra={"code": exc.code, "path": request.url.path}, exc_info=exc)
        return JSONResponse(
            status_code=exc.status_code,
            content=_envelope(exc.code, exc.message, exc.details),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Pydantic's error list is safe (it describes the caller's own payload
        # shape) but we strip the `input` echo to avoid reflecting large or
        # sensitive request bodies back to the client.
        details = [
            {"loc": list(e.get("loc", [])), "msg": e.get("msg", ""), "type": e.get("type", "")}
            for e in exc.errors()
        ]
        return JSONResponse(
            status_code=UNPROCESSABLE,
            content=_envelope("VALIDATION_FAILED", "Request validation failed.", details),
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code_map = {
            401: "AUTHENTICATION_FAILED",
            403: "NOT_AUTHORIZED",
            404: "NOT_FOUND",
            405: "METHOD_NOT_ALLOWED",
            413: "PAYLOAD_TOO_LARGE",
            429: "RATE_LIMITED",
        }
        code = code_map.get(exc.status_code, "HTTP_ERROR")
        message = exc.detail if isinstance(exc.detail, str) else "Request failed."
        headers = getattr(exc, "headers", None)
        return JSONResponse(
            status_code=exc.status_code,
            content=_envelope(code, message),
            headers=headers,
        )

    @app.exception_handler(SQLAlchemyError)
    async def _db(request: Request, exc: SQLAlchemyError) -> JSONResponse:
        # Never surface the SQL or the driver message.
        logger.error("database_error", extra={"path": request.url.path}, exc_info=exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=_envelope("DATABASE_ERROR", "A database error occurred."),
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        logger.error("unhandled_error", extra={"path": request.url.path}, exc_info=exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=_envelope("INTERNAL_ERROR", "An unexpected error occurred."),
        )
