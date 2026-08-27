"""Structured AI response contracts.

The model is never allowed to return prose that the UI renders directly.  Every
task has a schema, every response is parsed into it, and a response that fails
validation is discarded rather than shown with a caveat.

The most important field is ``evidence_ids``.  It is validated against the exact
set of identifiers the model was given, which is what converts "the AI said so"
into "here are the records, check them yourself".
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_TEXT = 4000
MAX_LIST = 25


class InvestigationAnswer(BaseModel):
    """Response contract for incident explanation, summary and Q&A."""

    model_config = ConfigDict(extra="ignore")

    summary: str = Field(min_length=1, max_length=MAX_TEXT)
    reasoning: str = Field(default="", max_length=MAX_TEXT)
    #: Public identifiers (EVT-..., ALT-..., SX-...) supporting the answer.
    evidence_ids: list[str] = Field(default_factory=list, max_length=MAX_LIST)
    mitre_techniques: list[str] = Field(default_factory=list, max_length=MAX_LIST)
    recommended_actions: list[str] = Field(default_factory=list, max_length=MAX_LIST)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    confidence_rationale: str = Field(default="", max_length=1000)
    #: What the model could not determine from the evidence it was given.
    #: Required by the prompt: an empty list on a thin evidence set is itself a
    #: signal that the response is overreaching.
    limitations: list[str] = Field(default_factory=list, max_length=MAX_LIST)

    @field_validator("evidence_ids", "mitre_techniques", mode="before")
    @classmethod
    def _coerce_list(cls, v: Any) -> Any:
        if isinstance(v, str):
            return [part.strip() for part in v.split(",") if part.strip()]
        return v

    @field_validator("recommended_actions", "limitations")
    @classmethod
    def _bound_items(cls, v: list[str]) -> list[str]:
        return [str(item)[:500] for item in v]


class HuntTranslation(BaseModel):
    """Response contract for natural-language hunt translation.

    ``query`` is a raw dict here and is re-validated against :class:`HuntQuery`
    by the service.  Two-stage validation on purpose: this schema checks the
    envelope, the DSL checks that the query is expressible and safe.
    """

    model_config = ConfigDict(extra="ignore")

    query: dict[str, Any]
    interpretation: str = Field(default="", max_length=1000)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    assumptions: list[str] = Field(default_factory=list, max_length=10)


class ExecutiveSummary(BaseModel):
    """Response contract for the non-technical report section."""

    model_config = ConfigDict(extra="ignore")

    summary: str = Field(min_length=1, max_length=MAX_TEXT)
    business_impact: str = Field(default="", max_length=2000)
    key_points: list[str] = Field(default_factory=list, max_length=10)
    evidence_ids: list[str] = Field(default_factory=list, max_length=MAX_LIST)


TASK_SCHEMAS: dict[str, type[BaseModel]] = {
    "explain": InvestigationAnswer,
    "summarize": InvestigationAnswer,
    "question": InvestigationAnswer,
    "next_steps": InvestigationAnswer,
    "hunt_translation": HuntTranslation,
    "executive_summary": ExecutiveSummary,
}
