"""Model package.

Importing this module registers every mapper with the declarative ``Base``.
``Base.metadata.create_all`` and Alembic autogenerate both depend on that, so the
re-exports below are load-bearing, not cosmetic.
"""

from app.models.alerts import Alert, AlertEvent
from app.models.detections import DetectionRule
from app.models.entities import Host, User
from app.models.events import Event
from app.models.incidents import AnalystNote, Incident, IncidentEvent, IncidentTechnique
from app.models.iocs import IOC, IOCMatch
from app.models.mitre import MitreTactic, MitreTechnique
from app.models.operations import AIInvestigation, AuditLog, Report, ResponseAction
from app.models.platform import (
    AppUser,
    BehaviorBaseline,
    EvaluationRun,
    SavedHunt,
    SimulationRun,
)

__all__ = [
    "AIInvestigation",
    "Alert",
    "AlertEvent",
    "AnalystNote",
    "AppUser",
    "AuditLog",
    "BehaviorBaseline",
    "DetectionRule",
    "EvaluationRun",
    "Event",
    "Host",
    "IOC",
    "IOCMatch",
    "Incident",
    "IncidentEvent",
    "IncidentTechnique",
    "MitreTactic",
    "MitreTechnique",
    "Report",
    "ResponseAction",
    "SavedHunt",
    "SimulationRun",
    "User",
]
