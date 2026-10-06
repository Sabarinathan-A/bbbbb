"""Policy evaluation: can a source reach a target with a given permission.

Allowed only if the acting token (if any) is not revoked, the source->target
edge exists, and the required permission is satisfied (wildcard scopes such as
``orders:*`` are honoured).
"""

from __future__ import annotations

from typing import Any, Dict, Optional

TOKEN_REVOKED = "TOKEN_REVOKED"
NO_EDGE = "NO_EDGE"
SCOPE_INSUFFICIENT = "SCOPE_INSUFFICIENT"
ALLOWED = "ALLOWED"


class PolicyResult:
    """Outcome of a reachability check."""

    def __init__(self, allowed: bool, reason: str,
                 source: Optional[str] = None, target: Optional[str] = None,
                 permission: Optional[str] = None):
        self.allowed = allowed
        self.reason = reason
        self.source = source
        self.target = target
        self.permission = permission

    def __bool__(self) -> bool:
        return self.allowed

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "source": self.source,
            "target": self.target,
            "permission": self.permission,
        }

    def __repr__(self) -> str:
        return "PolicyResult(allowed={!r}, reason={!r})".format(
            self.allowed, self.reason)


def _index_nodes(environment: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {n["id"]: n for n in environment.get("nodes", [])}


def _find_edge(environment: Dict[str, Any], source: str,
               target: str) -> Optional[Dict[str, Any]]:
    for edge in environment.get("edges", []):
        if edge.get("source") == source and edge.get("target") == target:
            return edge
    return None


def _scope_matches(required: str, granted: str) -> bool:
    """Return True if a granted scope satisfies the required permission.

    Supports wildcard scopes like ``orders:*`` which satisfy any ``orders:...``
    requirement, and exact matches like ``payments:admin``.
    """
    if granted == required:
        return True
    if ":" in granted:
        g_resource, g_action = granted.split(":", 1)
        if g_action == "*":
            if ":" in required:
                r_resource = required.split(":", 1)[0]
            else:
                r_resource = required
            return g_resource == r_resource
    return False


def can_reach(environment: Dict[str, Any], source: str, target: str,
              permission: Optional[str] = None) -> PolicyResult:
    """Evaluate whether ``source`` can reach ``target`` with ``permission``.

    * If ``source`` is a token node and it is revoked -> ``TOKEN_REVOKED``.
    * If no ``source``->``target`` edge exists -> ``NO_EDGE``.
    * If a permission is requested and the edge/scope does not satisfy it
      -> ``SCOPE_INSUFFICIENT``.
    * Otherwise -> allowed.
    """
    nodes = _index_nodes(environment)

    source_node = nodes.get(source)
    if source_node is not None and source_node.get("type") == "token":
        if source_node.get("revoked", False):
            return PolicyResult(False, TOKEN_REVOKED, source, target, permission)

    edge = _find_edge(environment, source, target)
    if edge is None:
        return PolicyResult(False, NO_EDGE, source, target, permission)

    if permission is not None:
        edge_permission = edge.get("permission")
        if not _scope_matches(permission, edge_permission):
            # Also allow the source token's own scopes to satisfy the request.
            scopes = []
            if source_node is not None:
                scopes = source_node.get("scopes", []) or []
            if not any(_scope_matches(permission, s) for s in scopes):
                return PolicyResult(False, SCOPE_INSUFFICIENT, source, target,
                                    permission)

    return PolicyResult(True, ALLOWED, source, target, permission)
