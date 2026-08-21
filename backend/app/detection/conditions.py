"""Declarative condition evaluation.

A *selection* is a mapping of field -> constraint.  All entries must hold (AND).
A constraint is either a literal (equality) or a dict of operators.

    selection:
      event_type: authentication
      status: failure
      metadata.service: ssh
      command_line:
        contains: "-perm -4000"
      destination_port:
        in: [22, 3389, 5985]

Boolean composition uses the reserved keys ``any_of``, ``all_of`` and ``not``.

String comparisons are case-insensitive by default.  Security telemetry is not
case-consistent — ``ADMINISTRATOR``, ``Administrator`` and ``administrator`` are
the same principal — and a rule that misses because of casing is a detection
gap, not a nuance.  Rules can opt into exact matching with ``case_sensitive: true``.

Regex patterns come from version-controlled rule files, never from API input.
Even so, the subject string is length-capped before matching so a pathological
pattern cannot be handed an unbounded input.
"""

from __future__ import annotations

import re
from typing import Any

from app.detection.fields import resolve
from app.models.events import Event

RESERVED_KEYS = {"any_of", "all_of", "not", "case_sensitive"}
MAX_REGEX_SUBJECT = 4096

OPERATORS = {
    "eq", "not_eq", "in", "not_in", "contains", "not_contains",
    "startswith", "endswith", "regex", "not_regex",
    "gt", "gte", "lt", "lte", "exists", "is_null",
}

_REGEX_CACHE: dict[tuple[str, bool], re.Pattern[str]] = {}


class ConditionError(ValueError):
    """The selection document is malformed."""


def _compile(pattern: str, case_sensitive: bool) -> re.Pattern[str]:
    key = (pattern, case_sensitive)
    if key not in _REGEX_CACHE:
        flags = 0 if case_sensitive else re.IGNORECASE
        _REGEX_CACHE[key] = re.compile(pattern, flags)
    return _REGEX_CACHE[key]


def _norm(value: Any, case_sensitive: bool) -> Any:
    if isinstance(value, str) and not case_sensitive:
        return value.lower()
    return value


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _compare(actual: Any, operator: str, expected: Any, case_sensitive: bool) -> bool:
    if operator == "exists":
        return (actual is not None) == bool(expected)
    if operator == "is_null":
        return (actual is None) == bool(expected)

    if operator in {"gt", "gte", "lt", "lte"}:
        if actual is None:
            return False
        try:
            a, b = float(actual), float(expected)
        except (TypeError, ValueError):
            return False
        return {"gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b}[operator]

    a = _norm(actual, case_sensitive)

    if operator in {"eq", "not_eq"}:
        # Booleans must compare identically: `True == 1` is a real source of
        # rule bugs when metadata carries mixed types.
        if isinstance(expected, bool) or isinstance(actual, bool):
            result = bool(actual) is bool(expected) and (actual is not None)
        else:
            result = a == _norm(expected, case_sensitive)
        return result if operator == "eq" else not result

    if operator in {"in", "not_in"}:
        candidates = [_norm(v, case_sensitive) for v in _as_list(expected)]
        result = a in candidates
        return result if operator == "in" else not result

    if operator in {"contains", "not_contains", "startswith", "endswith"}:
        if actual is None:
            return operator.startswith("not_")
        needles = [str(_norm(v, case_sensitive)) for v in _as_list(expected)]
        if operator in {"contains", "not_contains"}:
            # Membership for list-valued fields (metadata.privileges,
            # metadata.argument_indicators), substring for scalars.  Stringifying
            # a list and substring-matching it would make ["ab"] match "b".
            if isinstance(actual, (list, tuple, set)):
                haystack = {str(_norm(item, case_sensitive)) for item in actual}
                result = any(n in haystack for n in needles)
            else:
                result = any(n in str(a) for n in needles)
            return result if operator == "contains" else not result
        text = str(a)
        if operator == "startswith":
            return any(text.startswith(n) for n in needles)
        return any(text.endswith(n) for n in needles)

    if operator in {"regex", "not_regex"}:
        if actual is None:
            return operator == "not_regex"
        subject = str(actual)[:MAX_REGEX_SUBJECT]
        result = any(_compile(str(p), case_sensitive).search(subject) is not None for p in _as_list(expected))
        return result if operator == "regex" else not result

    raise ConditionError(f"Unsupported operator '{operator}'")


def matches(event: Event, selection: dict[str, Any] | None) -> bool:
    """Evaluate a selection document against one event."""
    if not selection:
        return True
    case_sensitive = bool(selection.get("case_sensitive", False))

    if "any_of" in selection:
        branches = selection["any_of"]
        if not isinstance(branches, list):
            raise ConditionError("'any_of' must be a list of selections")
        if not any(matches(event, b) for b in branches):
            return False

    if "all_of" in selection:
        branches = selection["all_of"]
        if not isinstance(branches, list):
            raise ConditionError("'all_of' must be a list of selections")
        if not all(matches(event, b) for b in branches):
            return False

    if "not" in selection and matches(event, selection["not"]):
        return False

    for field, constraint in selection.items():
        if field in RESERVED_KEYS:
            continue
        actual = resolve(event, field)

        if isinstance(constraint, dict):
            for operator, expected in constraint.items():
                if operator not in OPERATORS:
                    raise ConditionError(
                        f"Unsupported operator '{operator}' on field '{field}'. "
                        f"Supported: {', '.join(sorted(OPERATORS))}"
                    )
                if not _compare(actual, operator, expected, case_sensitive):
                    return False
        elif isinstance(constraint, list):
            if not _compare(actual, "in", constraint, case_sensitive):
                return False
        else:
            if not _compare(actual, "eq", constraint, case_sensitive):
                return False

    return True


def validate_selection(selection: dict[str, Any] | None, *, path: str = "selection") -> list[str]:
    """Static-check a selection at rule load time.

    Catching a typo'd field name when the rule file loads is the difference
    between a loud startup error and a rule that quietly never fires.
    """
    from app.detection.fields import FIELD_MAP

    errors: list[str] = []
    if selection is None:
        return errors
    if not isinstance(selection, dict):
        return [f"{path}: must be a mapping"]

    for field, constraint in selection.items():
        if field in {"any_of", "all_of"}:
            if not isinstance(constraint, list):
                errors.append(f"{path}.{field}: must be a list")
                continue
            for i, branch in enumerate(constraint):
                errors.extend(validate_selection(branch, path=f"{path}.{field}[{i}]"))
            continue
        if field == "not":
            errors.extend(validate_selection(constraint, path=f"{path}.not"))
            continue
        if field == "case_sensitive":
            if not isinstance(constraint, bool):
                errors.append(f"{path}.case_sensitive: must be a boolean")
            continue

        if not (field.startswith("metadata.") or field.startswith("raw.") or field in FIELD_MAP):
            errors.append(f"{path}: unknown field '{field}'")
            continue

        if isinstance(constraint, dict):
            for operator, expected in constraint.items():
                if operator not in OPERATORS:
                    errors.append(f"{path}.{field}: unsupported operator '{operator}'")
                elif operator in {"regex", "not_regex"}:
                    for pattern in _as_list(expected):
                        try:
                            re.compile(str(pattern))
                        except re.error as exc:
                            errors.append(f"{path}.{field}: invalid regex {pattern!r} ({exc})")
    return errors
