"""Local MITRE ATT&CK catalogue.

ATT&CK lives in one place — this table, loaded from ``data/mitre/`` — and every
other component references techniques by ID only.  Nothing in the UI or the
detection rules embeds a technique *name*, because names change between ATT&CK
versions and IDs do not.

The bundled catalogue is a curated subset of ATT&CK Enterprise covering the
techniques this platform actually detects.  ``scripts/refresh_mitre.py``
regenerates it from the official MITRE CTI repository.
"""

from __future__ import annotations

from sqlalchemy import Boolean, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, JSONVariant


class MitreTactic(Base):
    __tablename__ = "mitre_tactics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tactic_id: Mapped[str] = mapped_column(String(16), unique=True, index=True)  # TA0006
    name: Mapped[str] = mapped_column(String(128))
    shortname: Mapped[str] = mapped_column(String(64))  # credential-access
    description: Mapped[str] = mapped_column(Text, default="")
    #: Kill-chain ordering used to lay out the attack timeline left to right.
    order: Mapped[int] = mapped_column(Integer, default=0)
    url: Mapped[str | None] = mapped_column(String(255), nullable=True)


class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    technique_id: Mapped[str] = mapped_column(String(24), unique=True, index=True)  # T1110.001
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    #: A technique can belong to several tactics (T1078 spans four).
    tactic_ids: Mapped[list] = mapped_column(JSONVariant, default=list)
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, default=False)
    parent_technique_id: Mapped[str | None] = mapped_column(String(24), nullable=True, index=True)
    platforms: Mapped[list] = mapped_column(JSONVariant, default=list)
    data_sources: Mapped[list] = mapped_column(JSONVariant, default=list)
    detection_guidance: Mapped[str] = mapped_column(Text, default="")
    url: Mapped[str | None] = mapped_column(String(255), nullable=True)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<MitreTechnique {self.technique_id} {self.name}>"


Index("ix_mitre_parent", MitreTechnique.parent_technique_id)
