"""Detection rule documents: schema, loading and static validation.

Rules live as YAML under ``detection-rules/``.  They are *content*, not code —
version-controlled, reviewable in a pull request, and testable in isolation,
which is how detection engineering actually works.

The loader validates aggressively at startup.  A rule with a misspelled field
name is worse than a missing rule: it looks like coverage and provides none.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.detection.conditions import validate_selection
from app.detection.fields import GROUPABLE_FIELDS
from app.models.enums import RuleType, Severity

RULE_SUFFIXES = {".yml", ".yaml"}


class RuleLoadError(Exception):
    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("; ".join(errors))


class MitreMapping(BaseModel):
    model_config = ConfigDict(extra="forbid")
    techniques: list[str] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)

    @field_validator("techniques")
    @classmethod
    def _check_technique_format(cls, v: list[str]) -> list[str]:
        import re

        pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
        for technique in v:
            if not pattern.match(technique):
                raise ValueError(
                    f"'{technique}' is not a valid ATT&CK technique ID (expected T#### or T####.###)"
                )
        return v

    @field_validator("tactics")
    @classmethod
    def _check_tactic_format(cls, v: list[str]) -> list[str]:
        import re

        pattern = re.compile(r"^TA\d{4}$")
        for tactic in v:
            if not pattern.match(tactic):
                raise ValueError(f"'{tactic}' is not a valid ATT&CK tactic ID (expected TA####)")
        return v


class ThresholdSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    count: int = Field(ge=2, le=10_000)
    window_seconds: int = Field(ge=1, le=86_400)
    #: Optional: require the matched events to span at least N distinct values of
    #: a field (e.g. 5 failures against 5 *different* accounts = spraying).
    distinct_field: str | None = None
    distinct_count: int | None = Field(default=None, ge=2)


class SequenceStep(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=64)
    selection: dict[str, Any]
    min_count: int = Field(default=1, ge=1, le=1000)
    #: Maximum gap from the previous step.  Defaults to the rule's window.
    max_gap_seconds: int | None = Field(default=None, ge=1, le=86_400)
    optional: bool = False


class SequenceConstraint(BaseModel):
    """A cross-step requirement checked after a sequence matches.

    Needed because the condition language is per-event and cannot express
    relationships *between* steps.  "The same user authenticated to at least two
    different hosts" is exactly the shape of lateral movement, and without this
    the rule would happily match a user logging in to one machine three times.
    """

    model_config = ConfigDict(extra="forbid")
    distinct_field: str
    min_distinct: int = Field(ge=2, le=100)


class IOCSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    types: list[str] = Field(default_factory=list)
    fields: list[str] = Field(default_factory=lambda: ["source_ip", "destination_ip", "file_hash"])


class AnomalySpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    #: Name of a detector registered in app/detection/detectors/anomaly.py.
    #: Never an import path or callable — no code is loaded from rule content.
    detector: str
    params: dict[str, Any] = Field(default_factory=dict)


class RuleTestBaseline(BaseModel):
    """A behavioural baseline fixture for an anomaly rule's self-test."""

    model_config = ConfigDict(extra="forbid")
    entity_type: str = "user"
    entity_ref: str
    feature: str
    value: dict[str, Any] = Field(default_factory=dict)
    observations: int = 0


class RuleTestIOC(BaseModel):
    """An indicator fixture for an IOC rule's self-test."""

    model_config = ConfigDict(extra="forbid")
    ioc_id: str = "IOC-TEST"
    indicator: str
    ioc_type: str
    confidence: float = 0.8
    severity: str = "medium"
    source: str = "test-fixture"
    description: str = ""
    tags: list[str] = Field(default_factory=list)


class RuleTest(BaseModel):
    """A declarative self-test shipped alongside the rule."""

    model_config = ConfigDict(extra="forbid")
    name: str
    events: list[dict[str, Any]]
    expect: Literal["match", "no_match"]
    description: str = ""
    #: Fixtures for rule types that read state the events alone cannot supply.
    baselines: list[RuleTestBaseline] = Field(default_factory=list)
    iocs: list[RuleTestIOC] = Field(default_factory=list)


class RuleDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=3, max_length=64, pattern=r"^[A-Z0-9_]+$")
    name: str = Field(min_length=3, max_length=255)
    description: str = ""
    type: RuleType
    severity: Severity
    confidence: float = Field(default=0.6, ge=0.0, le=1.0)
    enabled: bool = True
    category: str = "general"
    author: str = "sentinel-x"
    version: str = "1.0"

    mitre: MitreMapping = Field(default_factory=MitreMapping)

    selection: dict[str, Any] | None = None
    group_by: list[str] = Field(default_factory=list)
    threshold: ThresholdSpec | None = None
    steps: list[SequenceStep] = Field(default_factory=list)
    window_seconds: int | None = Field(default=None, ge=1, le=86_400)
    ordered: bool = True
    constraints: list[SequenceConstraint] = Field(default_factory=list)
    ioc: IOCSpec | None = None
    anomaly: AnomalySpec | None = None

    #: ``{field}`` placeholders are filled from the triggering event.
    title_template: str | None = None
    #: Suppress repeat alerts for the same group for this many seconds.
    dedup_window_seconds: int = Field(default=900, ge=0, le=86_400)

    false_positives: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    tests: list[RuleTest] = Field(default_factory=list)

    #: Populated by the loader, not by the file.
    source_path: str | None = None

    @field_validator("group_by")
    @classmethod
    def _groupable(cls, v: list[str]) -> list[str]:
        for field in v:
            if field.startswith("metadata."):
                continue
            if field not in GROUPABLE_FIELDS:
                raise ValueError(
                    f"'{field}' is not a groupable field. Groupable: {', '.join(sorted(GROUPABLE_FIELDS))}"
                )
        return v

    # ------------------------------------------------------------- validation
    def structural_errors(self) -> list[str]:
        """Checks that depend on the combination of fields, run after parsing."""
        errors: list[str] = []
        where = f"rule {self.id}"

        if self.type == RuleType.MATCH:
            if not self.selection:
                errors.append(f"{where}: type 'match' requires a 'selection'")
        elif self.type == RuleType.THRESHOLD:
            if not self.selection:
                errors.append(f"{where}: type 'threshold' requires a 'selection'")
            if not self.threshold:
                errors.append(f"{where}: type 'threshold' requires a 'threshold' block")
            if not self.group_by:
                errors.append(
                    f"{where}: type 'threshold' requires 'group_by' — an ungrouped threshold "
                    "counts unrelated activity together and will fire on background noise"
                )
            if self.threshold and self.threshold.distinct_field and not self.threshold.distinct_count:
                errors.append(f"{where}: 'distinct_field' requires 'distinct_count'")
        elif self.type == RuleType.SEQUENCE:
            if len(self.steps) < 2:
                errors.append(f"{where}: type 'sequence' requires at least two steps")
            if not self.window_seconds:
                errors.append(f"{where}: type 'sequence' requires 'window_seconds'")
            if not self.group_by:
                errors.append(f"{where}: type 'sequence' requires 'group_by' to bind steps to an entity")
            names = [s.name for s in self.steps]
            if len(names) != len(set(names)):
                errors.append(f"{where}: sequence step names must be unique")
            if self.steps and all(s.optional for s in self.steps):
                errors.append(f"{where}: at least one sequence step must be required")
        elif self.type == RuleType.IOC:
            if not self.ioc:
                errors.append(f"{where}: type 'ioc' requires an 'ioc' block")
        # Kept parallel with the branches above rather than collapsed into
        # `elif ... and not ...`, so the dispatch chain reads as one table of
        # "rule type -> the block it requires".
        elif self.type == RuleType.ANOMALY:  # noqa: SIM102
            if not self.anomaly:
                errors.append(f"{where}: type 'anomaly' requires an 'anomaly' block")

        if self.constraints:
            from app.detection.fields import FIELD_MAP

            if self.type != RuleType.SEQUENCE:
                errors.append(f"{where}: 'constraints' is only meaningful for sequence rules")
            for constraint in self.constraints:
                if (
                    constraint.distinct_field not in FIELD_MAP
                    and not constraint.distinct_field.startswith("metadata.")
                ):
                    errors.append(
                        f"{where}: constraint references unknown field '{constraint.distinct_field}'"
                    )

        errors.extend(f"{where}: {e}" for e in validate_selection(self.selection))
        for step in self.steps:
            errors.extend(
                f"{where}: step '{step.name}' {e}" for e in validate_selection(step.selection)
            )

        if self.ioc:
            from app.detection.fields import FIELD_MAP

            for field in self.ioc.fields:
                if field not in FIELD_MAP and not field.startswith("metadata."):
                    errors.append(f"{where}: ioc.fields references unknown field '{field}'")

        if self.anomaly:
            from app.detection.detectors.anomaly import ANOMALY_DETECTORS

            if self.anomaly.detector not in ANOMALY_DETECTORS:
                errors.append(
                    f"{where}: unknown anomaly detector '{self.anomaly.detector}'. "
                    f"Available: {', '.join(sorted(ANOMALY_DETECTORS))}"
                )
        return errors

    @property
    def effective_window(self) -> int:
        if self.threshold:
            return self.threshold.window_seconds
        if self.window_seconds:
            return self.window_seconds
        return 300


def load_rule_file(path: Path) -> list[RuleDefinition]:
    """Load one YAML file, which may contain multiple documents."""
    errors: list[str] = []
    rules: list[RuleDefinition] = []
    try:
        # safe_load_all: never construct arbitrary Python objects from rule files.
        documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except yaml.YAMLError as exc:
        raise RuleLoadError([f"{path.name}: YAML parse error: {exc}"]) from exc

    for index, document in enumerate(documents):
        if document is None:
            continue
        if not isinstance(document, dict):
            errors.append(f"{path.name}[{index}]: rule document must be a mapping")
            continue
        try:
            rule = RuleDefinition(**document)
        except Exception as exc:  # pydantic ValidationError
            errors.append(f"{path.name}[{index}]: {exc}")
            continue
        rule.source_path = str(path)
        structural = rule.structural_errors()
        if structural:
            errors.extend(f"{path.name}: {e}" for e in structural)
            continue
        rules.append(rule)

    if errors:
        raise RuleLoadError(errors)
    return rules


def load_rules(rules_dir: Path) -> tuple[list[RuleDefinition], list[str]]:
    """Load every rule under ``rules_dir``.

    Returns ``(rules, errors)``.  A broken rule file never prevents the platform
    from starting with the rules that *are* valid — but the errors are surfaced
    in the API and the UI rather than being logged and forgotten.
    """
    rules: list[RuleDefinition] = []
    errors: list[str] = []
    seen: dict[str, str] = {}

    if not rules_dir.exists():
        return [], [f"Detection rules directory not found: {rules_dir}"]

    for path in sorted(rules_dir.rglob("*")):
        if path.suffix.lower() not in RULE_SUFFIXES or not path.is_file():
            continue
        try:
            for rule in load_rule_file(path):
                if rule.id in seen:
                    errors.append(
                        f"duplicate rule id '{rule.id}' in {path.name} (already defined in {seen[rule.id]})"
                    )
                    continue
                seen[rule.id] = path.name
                rules.append(rule)
        except RuleLoadError as exc:
            errors.extend(exc.errors)

    return rules, errors
