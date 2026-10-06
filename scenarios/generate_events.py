"""Deterministic generator for scenarios/events.json (Nimbus scenario).

Run from the repository root:

    python scenarios/generate_events.py

Produces a committed artifact: ~40 events comprising
  * evt-0001  normal baseline login for priya.s
  * evt-0002, evt-0003  additional baseline activity for priya.s (non-attack)
  * evt-0004..evt-0010  the seven correlated attack events (one suspicious group)
  * background noise for ravi.k and anita.m that must NOT correlate into the
    suspicious group.

The generator is seeded (random.seed(42)) so the output is byte-stable.
"""

import json
import os
import random

SEED = 42

# Baseline for priya.s (the compromised identity).
BASE_DEVICE = "dev-priya-laptop"
BASE_GEO = "IN"
ATTACK_DEVICE = "dev-unknown-01"
ATTACK_GEO = "RU"
ATTACK_SESSION = "sess-attack-001"
ATTACK_TOKEN = "tok-9f2"
OAUTH_TOKEN = "oauth-77"


def _ts(minute):
    """Return an ISO-8601 timestamp inside a single 30-minute attack window."""
    base_hour = 2  # 02:00 UTC
    mm = minute % 60
    hh = base_hour + (minute // 60)
    return "2024-05-01T{:02d}:{:02d}:00Z".format(hh, mm)


def build_events():
    events = []

    # --- Baseline / normal activity for priya.s (not part of the attack) ---
    events.append({
        "id": "evt-0001",
        "type": "login",
        "action": "login",
        "identity": "priya.s",
        "token_id": None,
        "session_id": "sess-normal-001",
        "device_id": BASE_DEVICE,
        "country": BASE_GEO,
        "geo": BASE_GEO,
        "timestamp": "2024-04-30T09:00:00Z",
        "rows": 0,
        "scopes": [],
    })
    events.append({
        "id": "evt-0002",
        "type": "app_access",
        "action": "access",
        "identity": "priya.s",
        "token_id": None,
        "session_id": "sess-normal-001",
        "device_id": BASE_DEVICE,
        "country": BASE_GEO,
        "geo": BASE_GEO,
        "timestamp": "2024-04-30T09:05:00Z",
        "resource": "crm",
        "rows": 12,
        "scopes": [],
    })
    events.append({
        "id": "evt-0003",
        "type": "app_access",
        "action": "read",
        "identity": "priya.s",
        "token_id": None,
        "session_id": "sess-normal-001",
        "device_id": BASE_DEVICE,
        "country": BASE_GEO,
        "geo": BASE_GEO,
        "timestamp": "2024-04-30T09:10:00Z",
        "resource": "email",
        "rows": 3,
        "scopes": [],
    })

    # --- The seven attack events (one correlated suspicious group) ---
    # All share the attack session / token / device and fall inside a 30-minute
    # window so correlation links them into exactly one group.
    attack = [
        {
            "id": "evt-0004",
            "type": "login",
            "action": "session_reuse",
            "stage_hint": "initial_compromise",
            "token_id": None,
            "session_id": ATTACK_SESSION,
            "device_id": ATTACK_DEVICE,
            "minute": 0,
            "rows": 0,
            "scopes": [],
            "new_device": True,
            "session_reuse": True,
        },
        {
            "id": "evt-0005",
            "type": "token_use",
            "action": "token_use",
            "stage_hint": "token_abuse",
            "token_id": ATTACK_TOKEN,
            "session_id": ATTACK_SESSION,
            "device_id": ATTACK_DEVICE,
            "minute": 3,
            "rows": 0,
            "scopes": [],
        },
        {
            "id": "evt-0006",
            "type": "app_access",
            "action": "access",
            "stage_hint": "application_access",
            "token_id": ATTACK_TOKEN,
            "session_id": ATTACK_SESSION,
            "device_id": ATTACK_DEVICE,
            "minute": 6,
            "resource": "helpdeskpro",
            "rows": 0,
            "scopes": [],
        },
        {
            "id": "evt-0007",
            "type": "token_create",
            "action": "create_token",
            "stage_hint": "token_created",
            "token_id": OAUTH_TOKEN,
            "session_id": ATTACK_SESSION,
            "device_id": ATTACK_DEVICE,
            "minute": 9,
            "resource": "oauth-77",
            "rows": 0,
            "scopes": ["orders:*", "payments:admin"],
            "issued_by_session": ATTACK_SESSION,
            "issued_by_token": ATTACK_TOKEN,
        },
        {
            "id": "evt-0008",
            "type": "api_call",
            "action": "api_call",
            "stage_hint": "api_access",
            "token_id": OAUTH_TOKEN,
            "session_id": ATTACK_SESSION,
            "device_id": ATTACK_DEVICE,
            "minute": 12,
            "resource": "orders-api",
            "rows": 20,
            "scopes": ["orders:*", "payments:admin"],
        },
        {
            "id": "evt-0009",
            "type": "api_call",
            "action": "privileged_call",
            "stage_hint": "privilege_escalation",
            "token_id": OAUTH_TOKEN,
            "session_id": ATTACK_SESSION,
            "device_id": ATTACK_DEVICE,
            "minute": 16,
            "resource": "payments-svc",
            "rows": 0,
            "scopes": ["orders:*", "payments:admin"],
            "privileged": True,
        },
        {
            "id": "evt-0010",
            "type": "db_query",
            "action": "db_query",
            "stage_hint": "data_access",
            "token_id": OAUTH_TOKEN,
            "session_id": ATTACK_SESSION,
            "device_id": ATTACK_DEVICE,
            "minute": 20,
            "resource": "customers-db",
            "rows": 5000,
            "scopes": ["orders:*", "payments:admin"],
        },
    ]

    for a in attack:
        events.append({
            "id": a["id"],
            "type": a["type"],
            "action": a["action"],
            "stage_hint": a["stage_hint"],
            "identity": "priya.s",
            "token_id": a["token_id"],
            "session_id": a["session_id"],
            "device_id": a["device_id"],
            "country": ATTACK_GEO,
            "geo": ATTACK_GEO,
            "timestamp": _ts(a["minute"]),
            "resource": a.get("resource"),
            "rows": a.get("rows", 0),
            "scopes": a.get("scopes", []),
            "new_device": a.get("new_device", False),
            "session_reuse": a.get("session_reuse", False),
            "privileged": a.get("privileged", False),
            "issued_by_session": a.get("issued_by_session"),
            "issued_by_token": a.get("issued_by_token"),
        })

    # --- Background noise for other users (must NOT correlate) ---
    rng = random.Random(SEED)
    noise_users = ["ravi.k", "anita.m"]
    noise_devices = {
        "ravi.k": "dev-ravi-laptop",
        "anita.m": "dev-anita-phone",
    }
    noise_geo = {"ravi.k": "IN", "anita.m": "US"}
    noise_actions = ["login", "read", "access", "logout", "search"]
    noise_types = ["login", "app_access", "app_access", "logout", "app_access"]
    idx = 11
    for user in noise_users:
        # Each noise user has its own distinct sessions/devices and timestamps
        # well outside the attack window, so none of these events share a token,
        # session, or device-within-30-minutes with the attack group.
        for n in range(13):
            minute = rng.randint(0, 59)
            hour = rng.randint(10, 20)
            session = "sess-{}-{}".format(user.split(".")[0], (n // 4) + 1)
            k = rng.randrange(len(noise_actions))
            events.append({
                "id": "evt-{:04d}".format(idx),
                "type": noise_types[k],
                "action": noise_actions[k],
                "identity": user,
                "token_id": None,
                "session_id": session,
                "device_id": noise_devices[user],
                "country": noise_geo[user],
                "geo": noise_geo[user],
                "timestamp": "2024-04-29T{:02d}:{:02d}:00Z".format(hour, minute),
                "resource": rng.choice(["crm", "email", "helpdeskpro"]),
                "rows": rng.randint(0, 50),
                "scopes": [],
                "new_device": False,
                "session_reuse": False,
                "privileged": False,
                "issued_by_session": None,
                "issued_by_token": None,
            })
            idx += 1

    return events


def main():
    events = build_events()
    out = {
        "synthetic": True,
        "description": "Nimbus synthetic event log (deterministic, random.seed(42)).",
        "events": events,
    }
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "events.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
        fh.write("\n")
    print("wrote {} events to {}".format(len(events), path))


if __name__ == "__main__":
    main()
