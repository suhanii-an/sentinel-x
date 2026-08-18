"""Structured application logging with secret redaction.

Security telemetry platforms handle credentials by definition (authentication
events carry usernames; cloud audit events carry access-key identifiers), and the
application itself holds an LLM API key and a JWT signing key.  Every log record
passes through :class:`RedactionFilter` before it is emitted.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from typing import Any

from app.core.config import settings

# Patterns are deliberately broad: it is far better to over-redact a log line
# than to leak a bearer token into a log aggregator.
_REDACTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)\S+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b(sk-[A-Za-z0-9_\-]{8,})"), "[REDACTED_API_KEY]"),
    (re.compile(r"(?i)\b(AKIA[0-9A-Z]{16})\b"), "[REDACTED_ACCESS_KEY]"),
    (re.compile(r"(?i)((?:api[_-]?key|secret|password|passwd|token)\"?\s*[:=]\s*\"?)([^\s\",}]+)"), r"\1[REDACTED]"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "[REDACTED_JWT]"),
]


def redact(text: str) -> str:
    for pattern, replacement in _REDACTION_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class RedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = redact(str(record.msg))
            if record.args:
                if isinstance(record.args, dict):
                    record.args = {k: redact(str(v)) for k, v in record.args.items()}
                else:
                    record.args = tuple(redact(str(a)) for a in record.args)
        except Exception:  # noqa: S110 - deliberate
            # Logging must never be able to break the request path it is
            # observing. A redaction failure loses a log line; a raised
            # exception here would lose the request.
            pass
        return True


#: Attribute names ``LogRecord`` owns. A key in ``extra`` that collides with one
#: of these makes ``Logger.makeRecord`` raise ``KeyError``, which turns a
#: logging call into a 500 on whatever request it was observing. Listed once and
#: used both to rename incoming keys and to skip them on the way out.
RESERVED_RECORD_KEYS = frozenset({
    "args", "asctime", "created", "exc_info", "exc_text", "filename",
    "funcName", "levelname", "levelno", "lineno", "module", "msecs",
    "message", "msg", "name", "pathname", "process", "processName",
    "relativeCreated", "stack_info", "thread", "threadName", "taskName",
})


class SafeLogger(logging.Logger):
    """A logger whose ``extra`` can never break the caller.

    ``logging`` refuses an ``extra`` key that shadows a ``LogRecord``
    attribute, and it refuses it by raising — so a field named ``created`` or
    ``module`` anywhere in the codebase crashes the request it was meant to
    record. Observability must not be able to take down the thing it observes,
    so colliding keys are renamed rather than rejected.
    """

    def makeRecord(self, name, level, fn, lno, msg, args, exc_info,
                   func=None, extra=None, sinfo=None):
        if extra:
            collisions = RESERVED_RECORD_KEYS.intersection(extra)
            if collisions:
                extra = {
                    (f"field_{k}" if k in collisions else k): v for k, v in extra.items()
                }
        return super().makeRecord(
            name, level, fn, lno, msg, args, exc_info, func, extra, sinfo
        )


logging.setLoggerClass(SafeLogger)


class JSONFormatter(logging.Formatter):
    """One JSON object per line — friendly to any log shipper."""

    _RESERVED = RESERVED_RECORD_KEYS

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in self._RESERVED and not key.startswith("_"):
                try:
                    json.dumps(value)
                    payload[key] = value
                except (TypeError, ValueError):
                    payload[key] = str(value)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return redact(json.dumps(payload, default=str))


def configure_logging() -> None:
    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    handler.addFilter(RedactionFilter())
    root.addHandler(handler)
    root.setLevel(settings.LOG_LEVEL.upper())
    # uvicorn's access log duplicates our own request middleware log line.
    logging.getLogger("uvicorn.access").disabled = True
    for noisy in ("httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
