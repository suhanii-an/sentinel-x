"""API v1 route aggregation."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import (
    ai,
    alerts,
    auth,
    cloud,
    detections,
    entities,
    evaluation,
    events,
    hunt,
    incidents,
    iocs,
    mitre,
    reports,
    response,
    simulations,
    system,
)

api_router = APIRouter()

api_router.include_router(auth.router)
api_router.include_router(events.router)
api_router.include_router(alerts.router)
api_router.include_router(incidents.router)
api_router.include_router(entities.hosts_router)
api_router.include_router(entities.users_router)
api_router.include_router(iocs.router)
api_router.include_router(detections.router)
api_router.include_router(mitre.router)
api_router.include_router(hunt.router)
api_router.include_router(simulations.router)
api_router.include_router(response.router)
api_router.include_router(reports.router)
api_router.include_router(ai.router)
api_router.include_router(evaluation.router)
api_router.include_router(cloud.router)
api_router.include_router(system.router)
