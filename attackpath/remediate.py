"""Remediation generation and application.

Generates the three canonical recommendations and provides
``apply_remediation`` which deep-copies the environment before mutating the
copy, so the original environment is never modified.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List

from .rootcause import Remediation


def generate_remediations(root_cause, attack_path=None) -> List[Dict[str, Any]]:
    """Return the three remediation recommendations as dicts.

    * rem-1: revoke the abused session token (expected break at step 2).
    * rem-2: remove payments:admin scope from oauth-77 (break at step 6).
    * rem-3: require step-up auth on OAuth grants (hardening).
    """
    credential = getattr(root_cause, "credential", None) or "tok-9f2"

    rem1 = Remediation(
        "rem-1", "revoke_token", credential, 2,
        description="Revoke session token {}".format(credential),
    )
    rem1_d = rem1.to_dict()
    rem1_d["expected_paths_broken"] = ["main_attack_path"]
    rem1_d["collateral"] = (
        "Priya must re-authenticate; her legitimate session is terminated."
    )

    rem2 = Remediation(
        "rem-2", "reduce_scope", "oauth-77", 6,
        params={"remove_scope": "payments:admin"},
        description="Remove payments:admin scope from oauth-77",
    )
    rem2_d = rem2.to_dict()
    rem2_d["expected_paths_broken"] = ["privilege_escalation_to_data_access"]
    rem2_d["collateral"] = (
        "OAuth integrations that legitimately need payments admin lose access."
    )

    rem3 = Remediation(
        "rem-3", "require_step_up_auth", "oauth-grants", 0,
        params={"applies_to": "oauth:issue"},
        description="Require step-up authentication before issuing OAuth grants",
    )
    rem3_d = rem3.to_dict()
    rem3_d["expected_paths_broken"] = ["token_created"]
    rem3_d["collateral"] = (
        "Adds an MFA prompt when applications request new OAuth grants."
    )

    return [rem1_d, rem2_d, rem3_d]


def _as_dict(remediation) -> Dict[str, Any]:
    if isinstance(remediation, dict):
        return remediation
    if hasattr(remediation, "to_dict"):
        return remediation.to_dict()
    raise TypeError("unsupported remediation type: {!r}".format(type(remediation)))


def apply_remediation(environment: Dict[str, Any], remediation) -> Dict[str, Any]:
    """Return a deep copy of ``environment`` with ``remediation`` applied.

    The original ``environment`` object is never mutated.
    """
    rem = _as_dict(remediation)
    new_env = copy.deepcopy(environment)

    kind = rem.get("kind")
    target = rem.get("target")
    params = rem.get("params", {}) or {}

    if kind == "revoke_token":
        for node in new_env.get("nodes", []):
            if node.get("id") == target:
                node["revoked"] = True

    elif kind == "reduce_scope":
        remove_scope = params.get("remove_scope")
        # Remove the scope from the token node.
        for node in new_env.get("nodes", []):
            if node.get("id") == target and "scopes" in node:
                node["scopes"] = [s for s in node["scopes"] if s != remove_scope]
        # Remove the corresponding edge whose permission is that scope.
        new_env["edges"] = [
            e for e in new_env.get("edges", [])
            if not (e.get("source") == target
                    and e.get("permission") == remove_scope)
        ]

    elif kind == "require_step_up_auth":
        new_env.setdefault("controls", {})["step_up_auth"] = True

    return new_env
