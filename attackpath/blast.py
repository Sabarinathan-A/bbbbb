"""Blast-radius computation.

Performs a BFS over the environment graph starting from the compromised token
and its owner, recording every reachable node with its hop count, sensitivity
and the edge used to reach it, then derives summary metrics.
"""

from __future__ import annotations

from collections import deque
from typing import Any, Dict, List, Optional

from .graph import build_graph


class BlastRadius:
    def __init__(self, seeds: List[str], reachable: List[Dict[str, Any]],
                 metrics: Dict[str, Any]):
        self.seeds = seeds
        self.reachable = reachable
        self.metrics = metrics
        self.synthetic = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "synthetic": True,
            "seeds": list(self.seeds),
            "reachable": list(self.reachable),
            "metrics": self.metrics,
            # Convenience top-level mirrors of the headline metrics.
            "reachable_resources": self.metrics["reachable_resources"],
            "sensitive_assets": self.metrics["sensitive_assets"],
        }


def compute_blast(environment: Dict[str, Any], token: str,
                  owner: Optional[str] = None) -> BlastRadius:
    """BFS from ``token`` (and its ``owner``) over the environment graph.

    Returns a :class:`BlastRadius` whose metrics include
    ``reachable_resources`` (nodes other than the seeds reachable from the
    seeds) and ``sensitive_assets`` (reachable nodes with high sensitivity).
    """
    graph = build_graph(environment)

    nodes = {n["id"]: n for n in environment.get("nodes", [])}

    # Determine owner if not given.
    if owner is None:
        for edge in environment.get("edges", []):
            if edge.get("permission") == "owns" and edge.get("target") == token:
                owner = edge.get("source")
                break

    seeds = [s for s in (token, owner) if s is not None and s in graph]

    reachable: List[Dict[str, Any]] = []
    visited = set(seeds)
    queue = deque()
    for seed in seeds:
        queue.append((seed, 0, None))

    while queue:
        current, hops, edge_used = queue.popleft()
        if current not in seeds:
            node_attrs = nodes.get(current, {})
            reachable.append({
                "node": current,
                "hops": hops,
                "sensitivity": node_attrs.get("sensitivity", "normal"),
                "type": node_attrs.get("type"),
                "category": node_attrs.get("category"),
                "edge_used": edge_used,
            })
        for _, target, data in graph.out_edges(current, data=True):
            if target in visited:
                continue
            # A token that is revoked blocks traversal through it.
            tgt_attrs = nodes.get(current, {})
            if tgt_attrs.get("type") == "token" and tgt_attrs.get("revoked"):
                continue
            visited.add(target)
            queue.append((target, hops + 1, {
                "source": current,
                "target": target,
                "permission": data.get("permission"),
            }))

    sensitive = [r for r in reachable if r["sensitivity"] == "high"]
    critical = [r for r in reachable
                if r["sensitivity"] == "high"
                and r.get("type") in ("datastore", "service")]
    financial = [r for r in reachable if r.get("category") == "financial_api"]
    customer_data = [r for r in reachable
                     if r.get("category") == "customer_data"]
    other_identities = [r for r in reachable if r.get("type") == "identity"]

    metrics = {
        "reachable_resources": len(reachable),
        "sensitive_assets": len(sensitive),
        "critical_systems": len(critical),
        "financial_apis": len(financial),
        "customer_data_systems": len(customer_data),
        "other_identities": len(other_identities),
    }

    return BlastRadius(seeds, reachable, metrics)
