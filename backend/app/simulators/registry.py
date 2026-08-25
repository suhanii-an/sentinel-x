"""Scenario registry."""

from __future__ import annotations

from app.simulators.base import ScenarioSpec, Simulator
from app.simulators.brute_force import BruteForceSimulator, PasswordSprayingSimulator
from app.simulators.cloud_iam import CloudIAMSimulator
from app.simulators.credential_abuse import CredentialAbuseSimulator
from app.simulators.discovery import DiscoverySimulator
from app.simulators.full_chain import FullChainSimulator
from app.simulators.lateral_movement import LateralMovementSimulator
from app.simulators.persistence import PersistenceSimulator
from app.simulators.privilege_escalation import PrivilegeEscalationSimulator

_SIMULATORS: list[Simulator] = [
    FullChainSimulator(),
    BruteForceSimulator(),
    PasswordSprayingSimulator(),
    CredentialAbuseSimulator(),
    DiscoverySimulator(),
    PrivilegeEscalationSimulator(),
    PersistenceSimulator(),
    LateralMovementSimulator(),
    CloudIAMSimulator(),
]

SIMULATORS: dict[str, Simulator] = {s.spec.key: s for s in _SIMULATORS}


def get_simulator(key: str) -> Simulator | None:
    return SIMULATORS.get(key)


def list_specs() -> list[ScenarioSpec]:
    """Scenario catalogue, full chain first so the demo path is obvious."""
    return [s.spec for s in _SIMULATORS]


def scenario_keys() -> list[str]:
    return list(SIMULATORS.keys())
