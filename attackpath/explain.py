"""Deterministic, human-readable explanation of an analysis result.

The template renderer requires no network or LLM. An optional LLM rewrite may
be supplied via ``llm`` but any error or unavailability falls back silently to
the deterministic template.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional


def _get(result: Any, *names: str, default: Any = None) -> Any:
    """Fetch an attribute or dict key from ``result`` by trying each name."""
    for name in names:
        if isinstance(result, dict) and name in result:
            return result[name]
        if hasattr(result, name):
            return getattr(result, name)
    return default


def _render_template(result: Any) -> str:
    attack_path = _get(result, "attack_path")
    root_cause = _get(result, "root_cause")
    blast = _get(result, "blast_radius", "blast")

    # Identity / credential.
    identity = _get(root_cause, "identity", default="an identity")
    credential = _get(root_cause, "credential", default="a token")

    # First (initial compromise) step details.
    first_time = None
    steps = _get(attack_path, "steps", default=[])
    if steps:
        first = steps[0]
        first_time = _get(first, "timestamp")
    time_str = first_time or "the observed time"

    # Metrics.
    metrics = _get(blast, "metrics", default={}) or {}
    reachable = metrics.get("reachable_resources",
                            _get(blast, "reachable_resources", default=0))
    sensitive = metrics.get("sensitive_assets",
                            _get(blast, "sensitive_assets", default=0))

    factors = _get(root_cause, "contributing_factors", default=[]) or []
    factors_str = ", ".join(factors) if factors else "none recorded"

    stages = _get(attack_path, "stages", default=[]) or []
    stage_str = " -> ".join(stages) if stages else "the observed stages"

    lines = [
        "On {time}, the session token {cred} belonging to {ident} was used "
        "from a new device to begin an attack.".format(
            time=time_str, cred=credential, ident=identity),
        "The attack proceeded through {n} stages: {stages}.".format(
            n=len(stages), stages=stage_str),
        "Root cause: {ident}'s credential {cred} was abused; contributing "
        "factors were {factors}.".format(
            ident=identity, cred=credential, factors=factors_str),
        "Blast radius: {reach} reachable resources, of which {sens} are "
        "sensitive.".format(reach=reachable, sens=sensitive),
    ]
    return "\n".join(lines)


def explain(result: Any,
            llm: Optional[Callable[[str], str]] = None) -> str:
    """Return a deterministic explanation string for ``result``.

    If ``llm`` is provided it may rewrite the template, but any exception or a
    falsy return value falls back to the deterministic template.
    """
    template = _render_template(result)
    if llm is None:
        return template
    try:
        rewritten = llm(template)
        if rewritten:
            return rewritten
    except Exception:
        pass
    return template
