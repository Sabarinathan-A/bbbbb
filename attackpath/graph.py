"""Build a directed networkx graph from the environment document."""

from __future__ import annotations

from typing import Any, Dict

import networkx as nx


def build_graph(environment: Dict[str, Any]) -> "nx.DiGraph":
    """Return a ``networkx.DiGraph`` built from the environment dict.

    Node attributes (type, sensitivity, revoked, scopes, ...) are preserved.
    Each edge retains its ``permission`` and ``actions`` list.
    """
    graph = nx.DiGraph()

    for node in environment.get("nodes", []):
        node_id = node["id"]
        attrs = {k: v for k, v in node.items() if k != "id"}
        graph.add_node(node_id, **attrs)

    for edge in environment.get("edges", []):
        source = edge["source"]
        target = edge["target"]
        attrs = {k: v for k, v in edge.items()
                 if k not in ("source", "target")}
        attrs.setdefault("actions", [])
        graph.add_edge(source, target, **attrs)

    return graph
