"""AttackPath Engine.

A pure-Python security analysis engine that reconstructs attack paths from
JSON scenario data (events + environment), identifies root cause, computes
blast radius, and evaluates remediations.

Public API:

    from attackpath import analyze, apply_remediation, verify, explain
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .blast import compute_blast
from .correlate import correlate
from .explain import explain as _explain
from .loader import LoadedEvents
from .reconstruct import reconstruct
from .remediate import apply_remediation as _apply_remediation
from .remediate import generate_remediations
from .rootcause import analyze_root_cause
from .verify import verify as _verify

__version__ = "0.1.0"

__all__ = ["analyze", "apply_remediation", "verify", "explain", "AnalysisResult"]


class AnalysisResult:
    """Complete result of :func:`analyze`."""

    def __init__(self, correlation, attack_path, root_cause, blast_radius,
                 remediations):
        self.correlation = correlation
        self.attack_path = attack_path
        self.root_cause = root_cause
        self.blast_radius = blast_radius
        self.remediations = remediations

    def to_dict(self) -> Dict[str, Any]:
        return {
            "correlation": self.correlation.to_dict(),
            "attack_path": self.attack_path.to_dict(),
            "root_cause": self.root_cause.to_dict(),
            "blast_radius": self.blast_radius.to_dict(),
            "remediations": list(self.remediations),
        }


def analyze(events, environment: Dict[str, Any]) -> AnalysisResult:
    """Run the full pipeline: correlate -> reconstruct -> rootcause -> blast.

    ``events`` may be a :class:`attackpath.loader.LoadedEvents`, a list of
    event dicts, or an events document dict with an ``events`` key.
    ``environment`` is the environment document dict.
    """
    if isinstance(events, dict):
        events = events.get("events", [])
    if not isinstance(events, LoadedEvents):
        events = LoadedEvents(list(events))

    groups = correlate(events)
    if not groups:
        raise ValueError("no suspicious correlation group found")
    group = groups[0]

    attack_path = reconstruct(group)
    root_cause = analyze_root_cause(attack_path, environment)
    blast_radius = compute_blast(environment, root_cause.credential,
                                 root_cause.identity)
    remediations = generate_remediations(root_cause, attack_path)

    return AnalysisResult(group, attack_path, root_cause, blast_radius,
                          remediations)


def apply_remediation(environment: Dict[str, Any], remediation) -> Dict[str, Any]:
    """Return a deep copy of ``environment`` with ``remediation`` applied.

    The original environment is never mutated.
    """
    return _apply_remediation(environment, remediation)


def verify(environment: Dict[str, Any], remediation):
    """Verify whether a remediation breaks the attack path."""
    return _verify(environment, remediation)


def explain(result, llm: Optional[Any] = None) -> str:
    """Produce a deterministic human-readable explanation of ``result``."""
    return _explain(result, llm=llm)
