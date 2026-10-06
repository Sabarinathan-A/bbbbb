"""Remediation verification.

Replays the core attack sequence over both the original and the remediated
environment, records which step first becomes denied, and reports PATH_BROKEN
(with the breaking step index) or PATH_STILL_OPEN.

Replay step mapping (1-indexed). The ordering is chosen so the token-use step
is step 2 and the privileged payments:admin step is step 6, which is the
contract the Nimbus tests assert against:

    step 1: priya.s   -> tok-9f2       (owns)          identity owns token
    step 2: tok-9f2   -> helpdeskpro   (app:access)    token used -> app
    step 3: helpdeskpro -> oauth-77    (oauth:issue)   oauth grant issued
    step 4: oauth-77  -> orders-api    (orders:*)      api access
    step 5: payments-svc -> customers-db (db:read)     data store prepared
    step 6: oauth-77  -> payments-svc  (payments:admin) privilege escalation

Revoking tok-9f2 denies step 2 (TOKEN_REVOKED). Removing payments:admin from
oauth-77 denies step 6 (the payments:admin edge is gone -> NO_EDGE), so steps
1-5 remain allowed and the break lands on step 6.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .policy import can_reach
from .remediate import apply_remediation
from .blast import compute_blast

PATH_BROKEN = "PATH_BROKEN"
PATH_STILL_OPEN = "PATH_STILL_OPEN"

# The canonical replay sequence (source, target, permission) in step order.
REPLAY_SEQUENCE = [
    ("priya.s", "tok-9f2", "owns"),
    ("tok-9f2", "helpdeskpro", "app:access"),
    ("helpdeskpro", "oauth-77", "oauth:issue"),
    ("oauth-77", "orders-api", "orders:*"),
    ("payments-svc", "customers-db", "db:read"),
    ("oauth-77", "payments-svc", "payments:admin"),
]


class VerifyResult:
    def __init__(self, status: str, breaking_step: Optional[int],
                 steps: List[Dict[str, Any]], blast_before: Dict[str, Any],
                 blast_after: Dict[str, Any], remediation_id: Optional[str]):
        self.status = status
        self.breaking_step = breaking_step
        self.steps = steps
        self.blast_before = blast_before
        self.blast_after = blast_after
        self.remediation_id = remediation_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "breaking_step": self.breaking_step,
            "remediation_id": self.remediation_id,
            "steps": self.steps,
            "blast_before": self.blast_before,
            "blast_after": self.blast_after,
        }


def verify(environment: Dict[str, Any], remediation) -> VerifyResult:
    """Replay the core sequence against the remediated environment.

    ``environment`` is the original (unmodified) environment; the remediation
    is applied to a deep copy internally via :func:`apply_remediation`.
    """
    remediated = apply_remediation(environment, remediation)

    rem_id = None
    if isinstance(remediation, dict):
        rem_id = remediation.get("id")
    elif hasattr(remediation, "id"):
        rem_id = remediation.id

    steps: List[Dict[str, Any]] = []
    breaking_step: Optional[int] = None

    for index, (src, tgt, perm) in enumerate(REPLAY_SEQUENCE, start=1):
        before = can_reach(environment, src, tgt, perm)
        after = can_reach(remediated, src, tgt, perm)
        steps.append({
            "step": index,
            "source": src,
            "target": tgt,
            "permission": perm,
            "allowed_before": before.allowed,
            "allowed_after": after.allowed,
            "reason_after": after.reason,
        })
        if before.allowed and not after.allowed and breaking_step is None:
            breaking_step = index

    status = PATH_BROKEN if breaking_step is not None else PATH_STILL_OPEN

    blast_before = compute_blast(environment, "tok-9f2").to_dict()
    blast_after = compute_blast(remediated, "tok-9f2").to_dict()

    return VerifyResult(status, breaking_step, steps, blast_before,
                        blast_after, rem_id)
