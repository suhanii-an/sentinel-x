"""AI investigation orchestration.

The pipeline for every AI call is the same, and each stage exists for a reason:

    build evidence bundle   -> the model sees only stored facts
    scan for injection      -> attacker-authored content is flagged, not obeyed
    fence + delimit         -> telemetry cannot escape into instruction position
    call provider           -> bounded timeout, no tools, no database access
    validate schema         -> non-conforming output is discarded, not displayed
    validate grounding      -> fabricated identifiers are removed and disclosed
    persist                 -> every interaction is auditable after the fact

A rejected response is recorded with its rejection reason.  An ungrounded answer
is a security-relevant event, and the platform keeps a trail of them rather than
retrying until something parses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.ai import context as context_builder
from app.ai import prompts
from app.ai.guard import (
    InjectionScan,
    ValidationOutcome,
    scan_for_injection,
    validate_response,
    wrap_untrusted,
)
from app.ai.provider import LLMProvider, ProviderError, get_provider
from app.ai.schemas import TASK_SCHEMAS, HuntTranslation, InvestigationAnswer
from app.core.config import settings
from app.core.errors import AIUnavailableError, AIValidationError
from app.core.logging import get_logger
from app.core.timeutils import utcnow
from app.models.incidents import Incident
from app.models.operations import AIInvestigation
from app.threat_hunting.dsl import HuntQuery

logger = get_logger("sentinelx.ai")

MAX_QUESTION_LENGTH = 1000


@dataclass(slots=True)
class AIResult:
    task: str
    answer: dict[str, Any] | None
    validation_status: str
    validation_errors: list[str] = field(default_factory=list)
    provider: str = "none"
    model: str = ""
    latency_ms: int = 0
    offered_evidence_ids: list[str] = field(default_factory=list)
    cited_evidence_ids: list[str] = field(default_factory=list)
    dropped_evidence_ids: list[str] = field(default_factory=list)
    dropped_techniques: list[str] = field(default_factory=list)
    injection_flagged: bool = False
    injection_signals: list[dict[str, Any]] = field(default_factory=list)
    evidence_event_count: int = 0

    @property
    def accepted(self) -> bool:
        return self.validation_status == "accepted"

    def to_dict(self) -> dict[str, Any]:
        return {
            "task": self.task,
            "accepted": self.accepted,
            "validation_status": self.validation_status,
            "validation_errors": self.validation_errors,
            "answer": self.answer,
            "provider": self.provider,
            "model": self.model,
            "latency_ms": self.latency_ms,
            "grounding": {
                "evidence_offered": len(self.offered_evidence_ids),
                "evidence_cited": self.cited_evidence_ids,
                "citations_removed": self.dropped_evidence_ids,
                "techniques_removed": self.dropped_techniques,
            },
            "prompt_injection": {
                "flagged": self.injection_flagged,
                "signals": self.injection_signals,
            },
        }


def ai_status() -> dict[str, Any]:
    """What the UI needs to render the assistant's availability honestly."""
    provider = get_provider()
    return {
        "available": provider.available,
        "provider": provider.name,
        "model": settings.AI_MODEL if provider.available else None,
        "suggested_questions": prompts.SUGGESTED_QUESTIONS if provider.available else [],
        "message": (
            "AI investigation assistant is available."
            if provider.available
            else "AI ASSISTANT UNAVAILABLE - no provider configured. Detection, correlation, "
                 "incidents, timeline, ATT&CK mapping, threat hunting, response simulation, "
                 "reporting and evaluation are all unaffected."
        ),
    }


def _run_task(
    *,
    task: str,
    system_prompt: str,
    user_content: str,
    allowed_evidence_ids: set[str],
    allowed_techniques: set[str],
    injection: InjectionScan,
    provider: LLMProvider | None = None,
    strict: bool = False,
) -> AIResult:
    provider = provider or get_provider()
    schema = TASK_SCHEMAS[task]

    result = AIResult(
        task=task,
        answer=None,
        validation_status="pending",
        provider=provider.name,
        offered_evidence_ids=sorted(allowed_evidence_ids),
        injection_flagged=injection.flagged,
        injection_signals=injection.signals,
    )

    if not provider.available:
        raise AIUnavailableError()

    try:
        response = provider.complete(
            system=system_prompt,
            user=user_content,
            max_tokens=settings.AI_MAX_TOKENS,
            temperature=0.0,
        )
    except ProviderError as exc:
        result.validation_status = "provider_error"
        result.validation_errors = [str(exc)]
        logger.warning("ai_provider_failed", extra={"task": task, "provider": provider.name})
        return result

    result.model = response.model
    result.latency_ms = response.latency_ms

    outcome: ValidationOutcome = validate_response(
        response.text,
        schema,
        allowed_evidence_ids=allowed_evidence_ids if task != "hunt_translation" else None,
        allowed_techniques=allowed_techniques if task != "hunt_translation" else None,
    )
    result.validation_errors = outcome.errors
    result.dropped_evidence_ids = outcome.dropped_evidence_ids
    result.dropped_techniques = outcome.dropped_techniques

    if not outcome.ok or outcome.model is None:
        result.validation_status = "rejected_schema"
        logger.warning("ai_response_rejected", extra={"task": task, "errors": outcome.errors[:3]})
        return result

    if strict and (outcome.dropped_evidence_ids or outcome.dropped_techniques):
        result.validation_status = "rejected_grounding"
        logger.warning("ai_response_ungrounded", extra={"task": task,
                                                        "dropped": outcome.dropped_evidence_ids[:5]})
        return result

    result.answer = outcome.model.model_dump(mode="json")
    result.cited_evidence_ids = list(result.answer.get("evidence_ids", []) or [])
    result.validation_status = "accepted"
    return result


def _persist(
    db: Session,
    result: AIResult,
    *,
    incident_pk: int | None,
    question: str,
    created_by: str,
) -> AIInvestigation:
    row = AIInvestigation(
        incident_pk=incident_pk,
        created_at=utcnow(),
        created_by=created_by,
        question=question[:4000],
        task=result.task,
        provider=result.provider,
        model=result.model or "",
        latency_ms=result.latency_ms,
        answer=result.answer,
        validation_status=result.validation_status,
        validation_errors=result.validation_errors,
        confidence=(result.answer or {}).get("confidence"),
        offered_evidence_ids=result.offered_evidence_ids[:200],
        cited_evidence_ids=result.cited_evidence_ids,
        injection_flagged=result.injection_flagged,
        injection_signals=result.injection_signals[:20],
    )
    db.add(row)
    db.flush()
    return row


def investigate_incident(
    db: Session,
    incident: Incident,
    *,
    task: str = "explain",
    question: str | None = None,
    created_by: str = "analyst",
    provider: LLMProvider | None = None,
    strict: bool = False,
) -> tuple[AIResult, AIInvestigation]:
    """Run an AI investigation task against one incident's evidence."""
    if task not in {"explain", "summarize", "question", "next_steps"}:
        raise ValueError(f"unsupported investigation task '{task}'")
    if task == "question" and not question:
        raise ValueError("a question is required for the 'question' task")

    bundle = context_builder.build_incident_bundle(db, incident)
    allowed_ids, allowed_techniques = context_builder.allowed_identifiers(bundle)
    injection = scan_for_injection(bundle, location="evidence")

    if injection.flagged:
        logger.warning(
            "prompt_injection_detected",
            extra={"incident": incident.incident_id, "signals": len(injection.signals)},
        )

    sections = [wrap_untrusted(bundle)]
    if task == "question":
        # The analyst's question is trusted input relative to telemetry, but it is
        # still placed outside the data block and never merged into the system
        # prompt, so it cannot redefine the task either.
        sections.append(
            "ANALYST QUESTION (from an authenticated SENTINEL-X user, answer this "
            f"and only this):\n{str(question)[:MAX_QUESTION_LENGTH]}"
        )
    sections.append(
        "Produce the JSON object described in your instructions. "
        "Cite only identifiers that appear in the evidence block above."
    )

    result = _run_task(
        task=task,
        system_prompt=prompts.TASK_PROMPTS[task],
        user_content="\n\n".join(sections),
        allowed_evidence_ids=allowed_ids,
        allowed_techniques=allowed_techniques,
        injection=injection,
        provider=provider,
        strict=strict,
    )
    result.evidence_event_count = len(bundle.get("events", []))

    row = _persist(
        db, result,
        incident_pk=incident.id,
        question=question or task,
        created_by=created_by,
    )
    return result, row


def executive_summary(
    db: Session,
    incident: Incident,
    *,
    created_by: str = "analyst",
    provider: LLMProvider | None = None,
) -> tuple[AIResult, AIInvestigation]:
    """Draft the non-technical report section.

    The report generator always produces a deterministic executive summary; this
    only replaces it when it validates, and the report records which one was used.
    """
    bundle = context_builder.build_incident_bundle(db, incident, max_events=25)
    allowed_ids, allowed_techniques = context_builder.allowed_identifiers(bundle)
    injection = scan_for_injection(bundle, location="evidence")

    result = _run_task(
        task="executive_summary",
        system_prompt=prompts.EXECUTIVE_SUMMARY_SYSTEM,
        user_content=wrap_untrusted(bundle)
        + "\n\nWrite the executive summary as the JSON object described in your instructions.",
        allowed_evidence_ids=allowed_ids,
        allowed_techniques=allowed_techniques,
        injection=injection,
        provider=provider,
    )
    row = _persist(db, result, incident_pk=incident.id,
                   question="executive_summary", created_by=created_by)
    return result, row


def translate_hunt(
    db: Session,
    natural_language: str,
    *,
    created_by: str = "analyst",
    provider: LLMProvider | None = None,
) -> tuple[AIResult, HuntQuery | None, AIInvestigation]:
    """Translate a plain-English hunting question into a validated HuntQuery.

    Note what does *not* happen here: the model never produces SQL, and its output
    is not executed. It emits a query document, which is validated by the same
    :class:`HuntQuery` schema an analyst's hand-written query goes through. If the
    model emits something the schema rejects, nothing runs.
    """
    question = str(natural_language)[:MAX_QUESTION_LENGTH]
    # The analyst's phrasing is untrusted for prompt purposes too: it may have
    # been copied out of a log line.
    injection = scan_for_injection(question, location="analyst_input")

    result = _run_task(
        task="hunt_translation",
        system_prompt=prompts.HUNT_TRANSLATION_SYSTEM,
        user_content=(
            "Translate this hunting question into the JSON query document:\n\n"
            f"{question}"
        ),
        allowed_evidence_ids=set(),
        allowed_techniques=set(),
        injection=injection,
        provider=provider,
    )

    hunt_query: HuntQuery | None = None
    if result.accepted and result.answer:
        try:
            translation = HuntTranslation(**result.answer)
            hunt_query = HuntQuery(**translation.query)
            hunt_query.description = translation.interpretation[:500]
        except (ValidationError, TypeError) as exc:
            # The envelope parsed but the query itself is not expressible. The
            # answer is downgraded rather than executed.
            result.validation_status = "rejected_query_schema"
            result.validation_errors.append(f"Translated query failed DSL validation: {exc}")
            hunt_query = None

    row = _persist(db, result, incident_pk=None, question=question, created_by=created_by)
    return result, hunt_query, row


def require_accepted(result: AIResult) -> InvestigationAnswer:
    """Raise unless the response passed every check."""
    if not result.accepted or result.answer is None:
        raise AIValidationError(
            "The AI response failed validation and was discarded.",
            details={"status": result.validation_status, "errors": result.validation_errors[:5]},
        )
    return InvestigationAnswer(**result.answer)
