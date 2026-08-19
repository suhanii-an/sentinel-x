"""Detection rule registry.

Rules are authored as YAML under ``detection-rules/`` — version-controlled,
reviewable, diffable, exactly like real detection content.  This table is the
*runtime registry*: it mirrors the files on disk and owns the mutable operational
state (enabled/disabled, trigger counts, last fired).

Rule logic is never executed as code from the database.  ``definition`` is a
declarative document interpreted by the detection engine; there is no eval(), no
dynamic import, and no path through the UI that can introduce new executable
logic.  That is a deliberate constraint, documented in docs/threat-model.md.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import Boolean, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, JSONVariant
from app.core.timeutils import UTCDateTime, utcnow


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")

    rule_type: Mapped[str] = mapped_column(String(24), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)

    category: Mapped[str] = mapped_column(String(64), default="general", index=True)
    mitre_techniques: Mapped[list] = mapped_column(JSONVariant, default=list)
    tactics: Mapped[list] = mapped_column(JSONVariant, default=list)

    #: The parsed YAML document, stored verbatim for inspection in the UI.
    definition: Mapped[dict] = mapped_column(JSONVariant, default=dict)
    source_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    author: Mapped[str] = mapped_column(String(128), default="sentinel-x")
    version: Mapped[str] = mapped_column(String(24), default="1.0")
    references: Mapped[list] = mapped_column(JSONVariant, default=list)
    false_positives: Mapped[list] = mapped_column(JSONVariant, default=list)
    #: Declarative self-tests shipped with the rule (see /detections rule testing).
    tests: Mapped[list] = mapped_column(JSONVariant, default=list)

    created_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)
    last_triggered_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    trigger_count: Mapped[int] = mapped_column(Integer, default=0)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<DetectionRule {self.rule_id} enabled={self.enabled}>"


Index("ix_rules_enabled_type", DetectionRule.enabled, DetectionRule.rule_type)
