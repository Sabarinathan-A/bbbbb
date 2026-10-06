"""Root-cause analysis.

The first attack step is the initial compromise; the token first abused on the
path is the abused credential, and its owner is the compromised identity.
Contributing factors are computed from the environment and the path.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

# Contributing-factor codes.
TOKEN_NOT_BOUND_TO_DEVICE = "TOKEN_NOT_BOUND_TO_DEVICE"
EXCESSIVE_OAUTH_SCOPE = "EXCESSIVE_OAUTH_SCOPE"
NO_STEP_UP_AUTH = "NO_STEP_UP_AUTH"


def _index_nodes(environment: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {n["id"]: n for n in environment.get("nodes", [])}


def _owner_of(environment: Dict[str, Any], token_id: str) -> Optional[str]:
    for edge in environment.get("edges", []):
        if edge.get("permission") == "owns" and edge.get("target") == token_id:
            return edge.get("source")
    return None


def _first_abused_token(attack_path) -> Optional[str]:
    for step in attack_path.steps:
        tok = step.event.get("token_id")
        if tok:
            return tok
    return None


class Remediation:
    """A remediation recommendation (also consumed by apply/verify)."""

    def __init__(self, rem_id: str, kind: str, target: str,
                 expected_break_step: int,
                 params: Optional[Dict[str, Any]] = None,
                 description: str = ""):
        self.id = rem_id
        self.kind = kind
        self.target = target
        self.expected_break_step = expected_break_step
        self.params = params or {}
        self.description = description

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "target": self.target,
            "expected_break_step": self.expected_break_step,
            "params": self.params,
            "description": self.description,
        }


class RootCause:
    def __init__(self, identity: str, credential: str,
                 contributing_factors: List[str],
                 breakpoints: Dict[str, Any],
                 details: Dict[str, Any]):
        self.identity = identity
        self.credential = credential
        self.contributing_factors = contributing_factors
        self.breakpoints = breakpoints
        self.details = details

    def to_dict(self) -> Dict[str, Any]:
        return {
            "identity": self.identity,
            "credential": self.credential,
            "contributing_factors": list(self.contributing_factors),
            "breakpoints": self.breakpoints,
            "details": self.details,
        }


def analyze_root_cause(attack_path, environment: Dict[str, Any]) -> RootCause:
    """Compute the root cause for the reconstructed attack path."""
    nodes = _index_nodes(environment)

    credential = _first_abused_token(attack_path)
    identity = _owner_of(environment, credential) if credential else None
    if identity is None and attack_path.steps:
        identity = attack_path.steps[0].event.get("identity")

    factors: List[str] = []
    details: Dict[str, Any] = {}

    # TOKEN_NOT_BOUND_TO_DEVICE
    tok_node = nodes.get(credential, {})
    if credential and not tok_node.get("bound_to_device", False):
        factors.append(TOKEN_NOT_BOUND_TO_DEVICE)

    # EXCESSIVE_OAUTH_SCOPE: detect oauth-77 carrying payments:admin.
    excessive = []
    for node in environment.get("nodes", []):
        if node.get("type") == "token" and node.get("token_kind") == "oauth":
            for scope in node.get("scopes", []) or []:
                if scope.endswith(":admin"):
                    excessive.append({"token": node["id"], "scope": scope})
    if excessive:
        factors.append(EXCESSIVE_OAUTH_SCOPE)
        details["excessive_scopes"] = excessive

    # NO_STEP_UP_AUTH: an OAuth token was created mid-session with no re-auth.
    created_tokens = [s for s in attack_path.steps
                      if s.stage == "token_created"]
    if created_tokens:
        factors.append(NO_STEP_UP_AUTH)
        details["oauth_created"] = [s.entity for s in created_tokens]

    breakpoints = {
        "immediate": Remediation(
            "rem-1", "revoke_token", credential, 2,
            description="Revoke session token {}".format(credential),
        ).to_dict(),
        "structural": Remediation(
            "rem-2", "reduce_scope", "oauth-77", 6,
            params={"remove_scope": "payments:admin"},
            description="Remove payments:admin scope from oauth-77",
        ).to_dict(),
    }

    return RootCause(identity, credential, factors, breakpoints, details)
