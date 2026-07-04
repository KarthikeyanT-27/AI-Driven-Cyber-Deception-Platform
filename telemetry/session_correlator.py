"""
telemetry/session_correlator.py  (NEW FILE)

Builds a correlated, timeline-based view of each honeypot session so the
SOC chatbot and dashboard can reason about *sessions* (an attacker's full
visit) instead of disconnected single events.

Storage model:
  - Redis holds the live working copy of each session (fast per-event
    read-modify-write; keyed by "sessioninfo:{honeypot}:{session_id}").
  - Elasticsearch index "sessions" holds a queryable snapshot, upserted by
    a stable document id ("{honeypot}:{session_id}") every time the
    session changes. The chatbot and dashboard should query THIS index,
    not raw honeypot-* events, when they need attack context.

Only "attack"-classified events (see event_classifier.py) contribute to
the timeline, MITRE techniques, and IOC list. "infra"/"system" events
still update last_seen/event counts (so session duration stays accurate)
but never pollute the evidence shown to the chatbot.
"""

import json
from datetime import datetime, timezone

SESSION_INDEX = "sessions"
MAX_TIMELINE_ENTRIES = 200
REDIS_KEY_PREFIX = "sessioninfo"
SESSION_TTL_SECONDS = 60 * 60 * 24 * 3  # working copy kept 3 days in Redis

# Rough MITRE kill-chain ordering, used only to pick a human-readable
# "furthest stage reached" label for a session — not a scoring input.
STAGE_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


def _redis_key(honeypot: str, session_id: str) -> str:
    return f"{REDIS_KEY_PREFIX}:{honeypot}:{session_id}"


def _derive_stage(tactics_seen: set) -> str:
    """Pick the furthest-progressed tactic observed using kill-chain order
    as a rough proxy for how far the attacker got."""
    for stage in reversed(STAGE_ORDER):
        if stage in tactics_seen:
            return stage
    return "Connection Only"


def _ioc_dedupe_key(ioc: dict) -> str:
    return ioc.get("ip") or ioc.get("domain") or ioc.get("url") or ioc.get("hash") or ""


async def _load(app, honeypot: str, session_id: str) -> dict:
    raw = await app.state.redis.get(_redis_key(honeypot, session_id))
    if raw:
        return json.loads(raw)
    now = datetime.now(timezone.utc).isoformat()
    return {
        "session_id": session_id,
        "honeypot": honeypot,
        "src_ip": None,
        "start_time": now,
        "last_seen": now,
        "total_event_count": 0,
        "attack_event_count": 0,
        "infra_event_count": 0,
        "timeline": [],
        "mitre_techniques": [],
        "iocs": [],
        "stage": "Connection Only",
        "risk_score": 0,
        "decision": "HOLD",
        "confidence": None,
    }


async def _save(app, session: dict) -> None:
    key = _redis_key(session["honeypot"], session["session_id"])
    await app.state.redis.set(key, json.dumps(session), ex=SESSION_TTL_SECONDS)
    try:
        doc_id = f"{session['honeypot']}:{session['session_id']}"
        await app.state.es.index(index=SESSION_INDEX, id=doc_id, document=session)
    except Exception:
        # Non-fatal — Redis remains the authoritative live copy even if a
        # snapshot write to ES fails (e.g. transient ES hiccup).
        pass


async def record_event(
    app,
    event_class: str,
    honeypot: str,
    session_id: str,
    src_ip: str | None,
    text_blob: str,
    iocs: list[dict],
    mitre: list[dict],
) -> dict:
    """Update (or create) the correlated session record for one event.
    Returns the updated session dict."""
    session = await _load(app, honeypot, session_id)

    now = datetime.now(timezone.utc).isoformat()
    session["last_seen"] = now
    session["total_event_count"] += 1
    if src_ip and not session.get("src_ip"):
        session["src_ip"] = src_ip

    if event_class == "attack":
        session["attack_event_count"] += 1

        session["timeline"].append({"timestamp": now, "summary": text_blob[:300]})
        session["timeline"] = session["timeline"][-MAX_TIMELINE_ENTRIES:]

        existing_ids = {m["technique_id"] for m in session["mitre_techniques"] if m.get("technique_id")}
        for m in mitre:
            tid = m.get("technique_id")
            if tid and tid not in existing_ids:
                session["mitre_techniques"].append(m)
                existing_ids.add(tid)

        existing_ioc_keys = {_ioc_dedupe_key(i) for i in session["iocs"]}
        existing_ioc_keys.discard("")
        for i in iocs:
            k = _ioc_dedupe_key(i)
            if k and k not in existing_ioc_keys:
                session["iocs"].append(i)
                existing_ioc_keys.add(k)

        tactics_seen = {m["tactic"] for m in session["mitre_techniques"] if m.get("tactic")}
        session["stage"] = _derive_stage(tactics_seen)
    else:
        session["infra_event_count"] += 1

    await _save(app, session)
    return session


async def update_risk(app, honeypot: str, session_id: str, risk_score: int, decision: str, confidence: float) -> None:
    """Patch in the escalation engine's latest verdict for this session,
    called right after /evaluate returns."""
    session = await _load(app, honeypot, session_id)
    session["risk_score"] = risk_score
    session["decision"] = decision
    session["confidence"] = confidence
    await _save(app, session)
