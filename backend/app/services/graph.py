"""Attack graph construction.

The graph is derived entirely from stored relationships between real events — it
is a *projection* of the evidence, never a hand-drawn illustration.  If an edge
appears, at least one event produced it, and the edge carries the event IDs that
did so, which is what lets the UI make every edge clickable through to evidence.

Node and edge vocabulary is deliberately small.  A graph with thirty edge types
is a diagram nobody reads; six verbs cover what actually matters in an
intrusion: who authenticated from where, what ran where, what connected to what,
what was modified, what was escalated, and what a detection mapped to.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.mitre import catalog
from app.models.alerts import Alert
from app.models.enums import EventStatus, EventType
from app.models.events import Event
from app.models.incidents import Incident
from app.models.iocs import IOCMatch

#: Upper bound on rendered nodes.  Past this the picture stops communicating,
#: and the evidence table is the better tool.
MAX_NODES = 220
MAX_EDGES = 500


@dataclass(slots=True)
class GraphNode:
    id: str
    kind: str          # host | user | ip | process | file | technique | ioc | alert
    label: str
    severity: str = "info"
    event_count: int = 0
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "label": self.label,
            "severity": self.severity,
            "event_count": self.event_count,
            "attributes": self.attributes,
        }


@dataclass(slots=True)
class GraphEdge:
    source: str
    target: str
    relation: str
    event_ids: list[str] = field(default_factory=list)
    count: int = 0

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.source, self.target, self.relation)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": f"{self.source}->{self.target}:{self.relation}",
            "source": self.source,
            "target": self.target,
            "relation": self.relation,
            "count": self.count,
            # Capped: an edge representing 400 events does not need to ship 400
            # identifiers to the browser.
            "event_ids": self.event_ids[:12],
        }


class GraphBuilder:
    def __init__(self) -> None:
        self.nodes: dict[str, GraphNode] = {}
        self.edges: dict[tuple[str, str, str], GraphEdge] = {}

    def node(
        self,
        kind: str,
        value: str,
        *,
        label: str | None = None,
        severity: str | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> str:
        node_id = f"{kind}:{value}"
        existing = self.nodes.get(node_id)
        if existing is None:
            existing = GraphNode(id=node_id, kind=kind, label=label or value)
            self.nodes[node_id] = existing
        existing.event_count += 1
        if attributes:
            existing.attributes.update({k: v for k, v in attributes.items() if v is not None})
        if severity:
            from app.models.enums import Severity

            existing.severity = str(Severity.max_of([existing.severity, severity]))
        return node_id

    def edge(self, source: str, target: str, relation: str, event_id: str | None = None) -> None:
        if source == target:
            return
        key = (source, target, relation)
        existing = self.edges.get(key)
        if existing is None:
            existing = GraphEdge(source=source, target=target, relation=relation)
            self.edges[key] = existing
        existing.count += 1
        if event_id and event_id not in existing.event_ids:
            existing.event_ids.append(event_id)

    def result(self) -> dict[str, Any]:
        nodes = sorted(self.nodes.values(), key=lambda n: n.event_count, reverse=True)[:MAX_NODES]
        keep = {n.id for n in nodes}
        edges = [
            e for e in sorted(self.edges.values(), key=lambda e: e.count, reverse=True)
            if e.source in keep and e.target in keep
        ][:MAX_EDGES]
        return {
            "nodes": [n.to_dict() for n in nodes],
            "edges": [e.to_dict() for e in edges],
            "truncated": len(self.nodes) > len(nodes) or len(self.edges) > len(edges),
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
        }


def build_incident_graph(db: Session, incident: Incident) -> dict[str, Any]:
    """Build the attack graph for one incident from its evidence."""
    alerts: Sequence[Alert] = incident.alerts
    event_pks = {link.event_pk for a in alerts for link in a.evidence_links}
    events: list[Event] = []
    if event_pks:
        events = list(
            db.execute(
                select(Event).where(Event.id.in_(sorted(event_pks))).order_by(Event.timestamp.asc())
            ).scalars().all()
        )

    severity_by_event: dict[int, str] = {}
    for alert in alerts:
        for link in alert.evidence_links:
            from app.models.enums import Severity

            current = severity_by_event.get(link.event_pk, "info")
            severity_by_event[link.event_pk] = str(Severity.max_of([current, alert.severity]))

    builder = GraphBuilder()

    for event in events:
        severity = severity_by_event.get(event.id, "info")
        host_node = user_node = ip_node = None

        if event.host_ref:
            host_node = builder.node("host", event.host_ref, severity=severity)
        if event.user_ref:
            user_node = builder.node(
                "user", event.user_ref, severity=severity,
                attributes={"user_type": (event.meta or {}).get("identity_type")},
            )
        if event.source_ip:
            ip_node = builder.node(
                "ip", event.source_ip, severity=severity,
                attributes={"private": (event.meta or {}).get("source_is_private")},
            )
        if event.cloud_account:
            cloud_node = builder.node("cloud_account", event.cloud_account, severity=severity)
            if user_node:
                builder.edge(user_node, cloud_node, "operated in", event.event_id)

        # --- relationships, by event type -------------------------------
        if event.event_type == EventType.AUTHENTICATION:
            if user_node and ip_node:
                relation = "authenticated from" if event.status == EventStatus.SUCCESS else "attempted from"
                builder.edge(user_node, ip_node, relation, event.event_id)
            if user_node and host_node:
                relation = "logged in to" if event.status == EventStatus.SUCCESS else "failed login to"
                builder.edge(user_node, host_node, relation, event.event_id)

        elif event.event_type in (EventType.PROCESS, EventType.DISCOVERY):
            if event.process_name:
                process_node = builder.node(
                    "process", f"{event.host_ref or 'unknown'}::{event.process_name}",
                    label=str(event.process_name).rsplit("/", 1)[-1], severity=severity,
                    attributes={
                        "command_line": event.command_line,
                        "parent": event.parent_process,
                        "discovery_category": (event.meta or {}).get("discovery_category"),
                    },
                )
                if user_node:
                    builder.edge(user_node, process_node, "executed", event.event_id)
                if host_node:
                    builder.edge(process_node, host_node, "ran on", event.event_id)

        elif event.event_type == EventType.NETWORK:
            if event.destination_ip:
                destination = builder.node("ip", event.destination_ip, severity=severity)
                if host_node:
                    builder.edge(host_node, destination, "connected to", event.event_id)
                elif ip_node:
                    builder.edge(ip_node, destination, "connected to", event.event_id)

        elif event.event_type == EventType.FILE:
            if event.file_path:
                file_node = builder.node(
                    "file", f"{event.host_ref or 'unknown'}::{event.file_path}",
                    label=str(event.file_path), severity=severity,
                    attributes={"mechanism": (event.meta or {}).get("persistence_mechanism")},
                )
                actor = user_node or host_node
                if actor:
                    builder.edge(actor, file_node, "modified", event.event_id)
                if host_node:
                    builder.edge(file_node, host_node, "persists on", event.event_id)

        elif event.event_type == EventType.PRIVILEGE:
            if user_node and host_node:
                builder.edge(user_node, host_node, "escalated on", event.event_id)
            target = (event.meta or {}).get("target_user") or (event.meta or {}).get("target_principal")
            if user_node and target:
                builder.edge(user_node, builder.node("user", str(target), severity=severity),
                             "elevated to", event.event_id)

        elif event.event_type == EventType.ACCOUNT:
            if host_node and user_node:
                builder.edge(user_node, host_node, "account changed on", event.event_id)

    # --- detections and techniques --------------------------------------
    for alert in alerts:
        alert_node = builder.node(
            "alert", alert.alert_id, label=alert.rule_id, severity=alert.severity,
            attributes={"title": alert.title, "confidence": alert.confidence,
                        "risk_score": alert.risk_score, "status": alert.status},
        )
        for entity in alert.entity_keys or []:
            kind, _, value = entity.partition(":")
            mapped = {"ip": "ip", "host": "host", "user": "user", "cloud": "cloud_account"}.get(kind)
            if mapped and f"{mapped}:{value}" in builder.nodes:
                builder.edge(alert_node, f"{mapped}:{value}", "detected on")
        for technique_id in alert.technique_ids or []:
            technique_node = builder.node(
                "technique", technique_id,
                label=f"{technique_id} {catalog.technique_name(technique_id)}",
                severity=alert.severity,
                attributes={"url": (catalog.technique(technique_id).url
                                    if catalog.technique(technique_id) else None)},
            )
            builder.edge(alert_node, technique_node, "maps to")

    # --- indicator corroboration ----------------------------------------
    if event_pks:
        matches = db.execute(
            select(IOCMatch).where(IOCMatch.event_pk.in_(sorted(event_pks)))
        ).scalars().all()
        event_by_pk = {e.id: e for e in events}
        for match in matches:
            ioc_node = builder.node(
                "ioc", match.ioc.ioc_id, label=match.ioc.indicator, severity=match.ioc.severity,
                attributes={"ioc_type": match.ioc.ioc_type, "source": match.ioc.source,
                            "confidence": match.ioc.confidence},
            )
            event = event_by_pk.get(match.event_pk)
            if event is None:
                continue
            for candidate in (f"ip:{event.source_ip}", f"ip:{event.destination_ip}",
                              f"host:{event.host_ref}"):
                if candidate in builder.nodes:
                    builder.edge(ioc_node, candidate, "matches", event.event_id)

    result = builder.result()
    result["incident_id"] = incident.incident_id
    return result
