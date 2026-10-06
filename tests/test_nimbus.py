"""Nimbus acceptance suite (PRD section 23, Tests 1-9).

These tests assert the EXACT, non-negotiable Nimbus numbers against the
AttackPath engine and the committed scenario data. They run fully offline:
scenario paths are resolved relative to this file so pytest passes regardless
of the current working directory.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from attackpath import analyze, apply_remediation, verify
from attackpath.blast import compute_blast
from attackpath.correlate import correlate
from attackpath.loader import LoadedEvents, load_environment, load_events
from attackpath.policy import TOKEN_REVOKED, can_reach
from attackpath.reconstruct import reconstruct
from attackpath.rootcause import EXCESSIVE_OAUTH_SCOPE, analyze_root_cause
from attackpath.verify import PATH_BROKEN

# ---------------------------------------------------------------------------
# Paths and fixtures
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = REPO_ROOT / "scenarios"
EVENTS_PATH = SCENARIOS / "events.json"
ENVIRONMENT_PATH = SCENARIOS / "environment.json"

# The seven ordered attack-step event ids and canonical stage order.
EXPECTED_GROUP_IDS = [
    "evt-0004",
    "evt-0005",
    "evt-0006",
    "evt-0007",
    "evt-0008",
    "evt-0009",
    "evt-0010",
]
EXPECTED_STAGE_ORDER = [
    "initial_compromise",
    "token_abuse",
    "application_access",
    "token_created",
    "api_access",
    "privilege_escalation",
    "data_access",
]
NOISE_IDENTITIES = {"ravi.k", "anita.m"}


@pytest.fixture(scope="module")
def events():
    """The loaded Nimbus events (LoadedEvents container)."""
    return load_events(str(EVENTS_PATH))


@pytest.fixture(scope="module")
def environment():
    """The loaded Nimbus environment graph document."""
    return load_environment(str(ENVIRONMENT_PATH))


@pytest.fixture
def rem_by_id(events, environment):
    """Map of remediation id -> remediation dict from the full pipeline."""
    result = analyze(events, environment)
    return {rem["id"]: rem for rem in result.remediations}


# ---------------------------------------------------------------------------
# Test 1 - Loader
# ---------------------------------------------------------------------------

def test_1_loader(events):
    assert isinstance(events, LoadedEvents)
    assert len(events) > 30

    # The four lookup dicts are built and non-empty.
    assert events.by_token
    assert events.by_session
    assert events.by_device
    assert events.by_identity


# ---------------------------------------------------------------------------
# Test 2 - Correlation
# ---------------------------------------------------------------------------

def test_2_correlation(events):
    groups = correlate(events)

    # Exactly one suspicious group.
    assert len(groups) == 1
    group = groups[0]

    # Its sorted event ids are exactly evt-0004..evt-0010.
    assert sorted(group.event_ids) == EXPECTED_GROUP_IDS

    # No noise events are present in the suspicious group.
    identities = {ev.get("identity") for ev in group.events}
    assert NOISE_IDENTITIES.isdisjoint(identities)


# ---------------------------------------------------------------------------
# Test 3 - Attack Path
# ---------------------------------------------------------------------------

def test_3_attack_path(events):
    group = correlate(events)[0]
    attack_path = reconstruct(group)

    # Exactly seven ordered steps.
    assert len(attack_path.steps) == 7

    # The stage sequence equals the canonical PRD order.
    assert attack_path.stages == EXPECTED_STAGE_ORDER


# ---------------------------------------------------------------------------
# Test 4 - Policy
# ---------------------------------------------------------------------------

def test_4_policy(environment, rem_by_id):
    # tok-9f2 -> helpdeskpro is allowed on the normal environment.
    allowed = can_reach(environment, "tok-9f2", "helpdeskpro", "app:access")
    assert allowed.allowed is True

    # Applying rem-1 (revoke tok-9f2) yields a TOKEN_REVOKED denial.
    revoked_env = apply_remediation(environment, rem_by_id["rem-1"])
    denied = can_reach(revoked_env, "tok-9f2", "helpdeskpro", "app:access")
    assert denied.allowed is False
    assert denied.reason == TOKEN_REVOKED


# ---------------------------------------------------------------------------
# Test 5 - Root Cause
# ---------------------------------------------------------------------------

def test_5_root_cause(events, environment):
    attack_path = reconstruct(correlate(events)[0])
    root_cause = analyze_root_cause(attack_path, environment)

    assert root_cause.identity == "priya.s"
    assert root_cause.credential == "tok-9f2"
    assert EXCESSIVE_OAUTH_SCOPE in root_cause.contributing_factors


# ---------------------------------------------------------------------------
# Test 6 - Blast Radius
# ---------------------------------------------------------------------------

def test_6_blast_radius(environment):
    blast = compute_blast(environment, "tok-9f2", "priya.s")

    assert blast.metrics["reachable_resources"] == 7
    assert blast.metrics["sensitive_assets"] == 3
    assert blast.synthetic is True


# ---------------------------------------------------------------------------
# Test 7 - Remediation Immutability
# ---------------------------------------------------------------------------

def test_7_remediation_immutability(environment, rem_by_id):
    # Snapshot the original environment BEFORE applying any remediation.
    before = copy.deepcopy(environment)
    before_json = json.dumps(environment, sort_keys=True)

    new_env = apply_remediation(environment, rem_by_id["rem-1"])

    # The returned copy differs: tok-9f2 is now revoked.
    revoked_flags = {
        node["id"]: node.get("revoked")
        for node in new_env["nodes"]
        if node["id"] == "tok-9f2"
    }
    assert revoked_flags["tok-9f2"] is True

    # The original environment is byte-for-byte unchanged.
    assert environment == before
    assert json.dumps(environment, sort_keys=True) == before_json


# ---------------------------------------------------------------------------
# Test 8 - Verification
# ---------------------------------------------------------------------------

def test_8_verification(environment, rem_by_id):
    before_json = json.dumps(environment, sort_keys=True)

    v1 = verify(environment, rem_by_id["rem-1"])
    assert v1.status == PATH_BROKEN
    assert v1.breaking_step == 2

    v2 = verify(environment, rem_by_id["rem-2"])
    assert v2.status == PATH_BROKEN
    assert v2.breaking_step == 6

    # The original environment is unchanged after verification.
    assert json.dumps(environment, sort_keys=True) == before_json


# ---------------------------------------------------------------------------
# Test 9 - Full Pipeline
# ---------------------------------------------------------------------------

def test_9_full_pipeline(events, environment):
    result = analyze(events, environment)

    # Correlation / suspicious group.
    assert sorted(result.correlation.event_ids) == EXPECTED_GROUP_IDS
    assert result.correlation.suspicious is True

    # Attack path: exactly 7 steps in canonical stage order.
    assert len(result.attack_path.steps) == 7
    assert result.attack_path.stages == EXPECTED_STAGE_ORDER

    # Root cause priya.s / tok-9f2.
    assert result.root_cause.identity == "priya.s"
    assert result.root_cause.credential == "tok-9f2"

    # Blast radius 7 reachable / 3 sensitive.
    assert result.blast_radius.metrics["reachable_resources"] == 7
    assert result.blast_radius.metrics["sensitive_assets"] == 3

    # Remediation list contains rem-1 / rem-2 / rem-3.
    rem_ids = [rem["id"] for rem in result.remediations]
    assert rem_ids == ["rem-1", "rem-2", "rem-3"]
