"""Attack-path reconstruction.

Sorts a correlated group by timestamp, classifies each event into its stage,
builds an observed attack graph, and returns the ordered AttackPath contract.
"""

from __future__ import annotations

from typing import Any, Dict, List

import networkx as nx

# Canonical stage order (PRD).
STAGE_ORDER = [
    "initial_compromise",
    "token_abuse",
    "application_access",
    "token_created",
    "api_access",
    "privilege_escalation",
    "data_access",
]


def _classify(event: Dict[str, Any]) -> str:
    """Classify a single event into an attack stage.

    Falls back to an explicit ``stage_hint`` when present, otherwise derives
    the stage from the event ``type``/``action`` and attributes.
    """
    hint = event.get("stage_hint")
    if hint in STAGE_ORDER:
        return hint

    etype = event.get("type") or ""
    action = event.get("action") or ""
    rows = event.get("rows") or 0

    if event.get("session_reuse") or action == "session_reuse":
        return "initial_compromise"
    if etype == "token_use" or action == "token_use":
        return "token_abuse"
    if etype == "app_access" or action == "access":
        return "application_access"
    if etype == "token_create" or action == "create_token":
        return "token_created"
    if event.get("privileged") or action == "privileged_call":
        return "privilege_escalation"
    if etype == "db_query" or action == "db_query" or rows > 1000:
        return "data_access"
    if etype == "api_call" or action == "api_call":
        return "api_access"
    return "application_access"


def _entity_for(event: Dict[str, Any]) -> str:
    """Pick the most relevant entity for a step."""
    return (event.get("resource")
            or event.get("token_id")
            or event.get("session_id")
            or event.get("identity"))


class AttackStep:
    def __init__(self, index: int, event: Dict[str, Any], stage: str):
        self.index = index
        self.event_id = event["id"]
        self.stage = stage
        self.entity = _entity_for(event)
        self.timestamp = event.get("timestamp")
        self.event = event

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.index,
            "event_id": self.event_id,
            "stage": self.stage,
            "entity": self.entity,
            "timestamp": self.timestamp,
        }


class AttackPath:
    def __init__(self, steps: List["AttackStep"], graph: "nx.DiGraph"):
        self.steps = steps
        self.graph = graph

    @property
    def stages(self) -> List[str]:
        return [s.stage for s in self.steps]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "steps": [s.to_dict() for s in self.steps],
            "stages": self.stages,
            "length": len(self.steps),
        }


def reconstruct(group) -> AttackPath:
    """Build an :class:`AttackPath` from a correlation group.

    ``group`` may be a :class:`attackpath.correlate.CorrelationGroup` or a list
    of event dicts.
    """
    if hasattr(group, "events"):
        events = list(group.events)
    else:
        events = list(group)

    events.sort(key=lambda e: e.get("timestamp", ""))

    steps: List[AttackStep] = []
    graph = nx.DiGraph()
    prev_id = None
    for i, ev in enumerate(events, start=1):
        stage = _classify(ev)
        step = AttackStep(i, ev, stage)
        steps.append(step)
        graph.add_node(ev["id"], stage=stage, entity=step.entity)
        if prev_id is not None:
            graph.add_edge(prev_id, ev["id"])
        prev_id = ev["id"]

    return AttackPath(steps, graph)
