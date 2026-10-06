"""Scenario loading (events + environment JSON) and lookup indexing.

Implements FR-01: events are indexed across the four correlation dimensions
(token_id, session_id, device_id, identity).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional


class LoadedEvents:
    """Container for loaded events plus the four lookup dictionaries.

    The lookups map a dimension value to the list of events carrying that
    value, so the correlation stage can quickly find events that share a
    token, session, device or identity.
    """

    def __init__(self, events: List[Dict[str, Any]]):
        self.events: List[Dict[str, Any]] = events
        self.by_token: Dict[str, List[Dict[str, Any]]] = {}
        self.by_session: Dict[str, List[Dict[str, Any]]] = {}
        self.by_device: Dict[str, List[Dict[str, Any]]] = {}
        self.by_identity: Dict[str, List[Dict[str, Any]]] = {}
        self._index()

    def _index(self) -> None:
        for ev in self.events:
            self._add(self.by_token, ev.get("token_id"), ev)
            self._add(self.by_session, ev.get("session_id"), ev)
            self._add(self.by_device, ev.get("device_id"), ev)
            self._add(self.by_identity, ev.get("identity"), ev)

    @staticmethod
    def _add(index: Dict[str, List[Dict[str, Any]]], key: Optional[str],
             ev: Dict[str, Any]) -> None:
        if key is None:
            return
        index.setdefault(key, []).append(ev)

    def __len__(self) -> int:
        return len(self.events)

    def __iter__(self):
        return iter(self.events)


def _read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_events(path: str) -> LoadedEvents:
    """Load events from a JSON file and build the four lookup dicts.

    The file may be a bare list of events or an object with an ``events`` key.
    Returns a :class:`LoadedEvents` which is iterable (yields the raw events)
    and exposes ``by_token``/``by_session``/``by_device``/``by_identity``.
    """
    data = _read_json(path)
    if isinstance(data, dict):
        events = data.get("events", [])
    else:
        events = data
    return LoadedEvents(list(events))


def load_environment(path: str) -> Dict[str, Any]:
    """Load the environment graph document (nodes + edges) as a dict."""
    data = _read_json(path)
    if not isinstance(data, dict):
        raise ValueError("environment document must be a JSON object")
    return data
