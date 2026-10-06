"""AttackPath Engine.

A pure-Python security analysis engine that reconstructs attack paths from
JSON scenario data (events + environment), identifies root cause, computes
blast radius, and evaluates remediations.

The public API (``analyze``, ``apply_remediation``, ``verify``, ``explain``)
is fleshed out in a later feature. This module currently exposes the names so
that ``import attackpath`` works and the baseline is green.
"""

__version__ = "0.1.0"

__all__ = ["analyze", "apply_remediation", "verify", "explain"]


def analyze(*args, **kwargs):
    """Analyze a scenario and return the attack-path result. Stub for FEAT-002."""
    raise NotImplementedError("analyze is implemented in FEAT-002")


def apply_remediation(*args, **kwargs):
    """Apply a remediation to a (copied) environment. Stub for FEAT-002."""
    raise NotImplementedError("apply_remediation is implemented in FEAT-002")


def verify(*args, **kwargs):
    """Verify whether a remediation breaks the attack path. Stub for FEAT-002."""
    raise NotImplementedError("verify is implemented in FEAT-002")


def explain(*args, **kwargs):
    """Produce a human-readable explanation of the analysis. Stub for FEAT-002."""
    raise NotImplementedError("explain is implemented in FEAT-002")
