"""Shared API schema primitives."""

from __future__ import annotations

import datetime as dt
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Page(BaseModel, Generic[T]):
    """Offset pagination envelope.

    Offset rather than cursor: the analyst workflows here are "show me page 3 of
    the alert queue sorted by risk", which cursors serve badly. The trade-off
    (drift under concurrent inserts) is acceptable for a queue an analyst is
    actively working, and is noted in docs/testing.md.
    """

    items: list[T]
    total: int
    limit: int
    offset: int

    @property
    def has_more(self) -> bool:
        return self.offset + len(self.items) < self.total


class PageParams(BaseModel):
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0, le=100_000)


class TimeWindow(BaseModel):
    start: dt.datetime | None = None
    end: dt.datetime | None = None


class MessageResponse(BaseModel):
    message: str
    details: dict[str, Any] | None = None


class ErrorBody(BaseModel):
    code: str
    message: str
    details: Any | None = None


class ErrorResponse(BaseModel):
    """The shape every failing endpoint returns."""

    error: ErrorBody
