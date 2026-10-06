"""Event correlation (FR-01).

Events are treated as graph nodes and linked when they share a token, a
session, a device within a 30-minute window, or an OAuth-creation link via
``issued_by_session`` / ``issued_by_token``. Connected components with at
least one suspicion flag are returned as suspicious groups.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import networkx as nx

# Suspicion flags
NEW_DEVICE = "NEW_DEVICE"
SESSION_REUSE_NEW_GEO = "SESSION_REUSE_NEW_GEO"
TOKEN_SCOPE_EXCESSIVE = "TOKEN_SCOPE_EXCESSIVE"
BULK_READ = "BULK_READ"

DEVICE_WINDOW_SECONDS = 30 * 60
ADMIN_SCOPE_MARKER = ":admin"
BULK_READ_THRESHOLD = 1000


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    text = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class CorrelationGroup:
    """A connected set of events plus its suspicion flags."""

    def __init__(self, events: List[Dict[str, Any]], flags: List[str]):
        self.events = sorted(events, key=lambda e: e.get("timestamp", ""))
        self.event_ids = [e["id"] for e in self.events]
        self.flags = sorted(set(flags))

    @property
    def suspicious(self) -> bool:
        return len(self.flags) > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_ids": list(self.event_ids),
            "flags": list(self.flags),
            "suspicious": self.suspicious,
        }


def _share_link(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    """Return True if events ``a`` and ``b`` should be linked."""
    a_tok, b_tok = a.get("token_id"), b.get("token_id")
    if a_tok and b_tok and a_tok == b_tok:
        return True

    a_sess, b_sess = a.get("session_id"), b.get("session_id")
    if a_sess and b_sess and a_sess == b_sess:
        return True

    # OAuth-creation link: a created token references the issuing session/token.
    for first, second in ((a, b), (b, a)):
        issued_sess = first.get("issued_by_session")
        issued_tok = first.get("issued_by_token")
        if issued_sess and issued_sess == second.get("session_id"):
            return True
        if issued_tok and issued_tok == second.get("token_id"):
            return True

    # Same device within a 30-minute window.
    a_dev, b_dev = a.get("device_id"), b.get("device_id")
    if a_dev and b_dev and a_dev == b_dev:
        ta, tb = _parse_ts(a.get("timestamp")), _parse_ts(b.get("timestamp"))
        if ta is not None and tb is not None:
            if abs((ta - tb).total_seconds()) <= DEVICE_WINDOW_SECONDS:
                return True

    return False


def _flags_for_events(events: List[Dict[str, Any]]) -> List[str]:
    flags: List[str] = []
    for ev in events:
        if ev.get("new_device"):
            flags.append(NEW_DEVICE)
        if ev.get("session_reuse"):
            flags.append(SESSION_REUSE_NEW_GEO)
        scopes = ev.get("scopes") or []
        if any(ADMIN_SCOPE_MARKER in s for s in scopes):
            flags.append(TOKEN_SCOPE_EXCESSIVE)
        action = ev.get("action") or ev.get("type") or ""
        rows = ev.get("rows") or 0
        if ("read" in action or "query" in action) and rows > BULK_READ_THRESHOLD:
            flags.append(BULK_READ)
    return flags


def correlate(loaded) -> List[CorrelationGroup]:
    """Return the suspicious correlation groups for the loaded events.

    ``loaded`` may be a :class:`attackpath.loader.LoadedEvents` or any iterable
    of event dicts.
    """
    events = list(loaded)

    graph = nx.Graph()
    for ev in events:
        graph.add_node(ev["id"], event=ev)

    for i in range(len(events)):
        for j in range(i + 1, len(events)):
            if _share_link(events[i], events[j]):
                graph.add_edge(events[i]["id"], events[j]["id"])

    groups: List[CorrelationGroup] = []
    for component in nx.connected_components(graph):
        comp_events = [graph.nodes[node_id]["event"] for node_id in component]
        flags = _flags_for_events(comp_events)
        group = CorrelationGroup(comp_events, flags)
        if group.suspicious:
            groups.append(group)

    groups.sort(key=lambda g: g.event_ids[0] if g.event_ids else "")
    return groups
