"""
telemetry/main.py

The Telemetry Layer. Responsibilities (per spec):
  - Poll Elasticsearch for new honeypot events (Cowrie/Dionaea/Elastichoney)
  - Classify each event as attack / infra / system (event_classifier.py)
  - For attack events only: extract IOCs, map MITRE techniques, track
    per-session command sequences in Redis, forward to the escalation
    engine, and update the correlated session record (session_correlator.py)
  - For infra/system events: update session bookkeeping (so session
    duration stays accurate) without feeding noise into IOC/MITRE/
    escalation/RAG

Exposes:
  GET  /health
  GET  /stats               -> quick counts for the dashboard
  POST /ingest               -> manual/test ingestion path (bypasses ES poll)

FIXES applied vs original:
  1. poll_once() used `match_all` on the very first poll, which re-processes
     ALL historical documents on every cold start (after `docker compose down`
     the in-memory `last_timestamp` is lost and ES still has all old events).
     Fix: on first start, initialise `last_timestamp` to "now minus one poll
     interval" so only documents that arrive *after* the service starts are
     processed automatically. Historical replay is still possible via /ingest.

  2. The original `last_timestamp` was updated from `doc.get("@timestamp")`
     which may be None if Logstash failed to set it (e.g. date parse failure).
     Fix: only advance the cursor when the field is actually present.

  3. poll_loop() swallowed all exceptions silently for NotFoundError but
     re-raised everything else. A transient ES connection error on startup
     crashed the task and it was never restarted.  Fix: catch all exceptions
     and keep the loop alive.

  4. ES client was not given a retry/sniff config.  It would fail fast on
     a brief ES hiccup and not recover.  Fix: use retry_on_timeout=True and
     a reasonable request timeout.

  5. The initial sleep(5) in poll_loop was too short when escalation-engine
     takes 60-90 s to become healthy.  The depends_on in docker-compose now
     handles ordering, but we also add a startup ES connectivity check here
     as belt-and-suspenders.

  6. AUDIT FIX (event separation): every document from honeypot-* — including
     Docker healthcheck connect/close noise from 127.0.0.1 — was previously
     processed identically to real attacker activity: IOC extraction, MITRE
     mapping, a Redis session-sequence entry, and a forward to the escalation
     engine. Now each event is classified first (event_classifier.py); only
     "attack" events go through that pipeline. "infra"/"system" events are
     still counted (for session duration / total event stats) but never
     generate IOCs, MITRE tags, escalation calls, or RAG evidence.

  7. AUDIT FIX (session correlation): added session_correlator.py, which
     maintains one structured record per session (start/end time, IOCs,
     real MITRE techniques, a bounded timeline, current risk verdict) in
     Redis + the "sessions" ES index. The chatbot and dashboard should read
     from that index for anything attack-related instead of raw honeypot-*
     events, which are disconnected single log lines with no timeline.
"""

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import httpx
import redis.asyncio as aioredis
from elasticsearch import AsyncElasticsearch, NotFoundError, ConnectionError as ESConnectionError
from fastapi import FastAPI
from pydantic import BaseModel

from ioc_extractor import extract_iocs_as_dicts
from mitre_mapper import map_command_as_dicts
from event_classifier import classify_event
import session_correlator

logging.basicConfig(level=logging.INFO, format="%(asctime)s [telemetry] %(levelname)s %(message)s")
log = logging.getLogger("telemetry")

ES_HOST = os.getenv("ELASTICSEARCH_HOST", "http://elasticsearch:9200")
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")
ESCALATION_URL = os.getenv("ESCALATION_URL", "http://escalation-engine:8001")
POLL_INTERVAL = int(os.getenv("TELEMETRY_POLL_INTERVAL_SECONDS", "10"))
SOURCE_INDEX_PATTERN = "honeypot-*"
IOC_INDEX_PREFIX = "iocs"
SEQUENCE_TTL_SECONDS = 60 * 60 * 6  # 6h rolling session window

_state = {
    "last_timestamp": None,
    "events_processed": 0,
    "attack_events": 0,
    "infra_events": 0,
    "system_events": 0,
    "iocs_found": 0,
    "escalations": 0,
}


def _get_text_blob(doc: dict) -> str:
    """Pull every plausible text field out of a honeypot event doc."""
    parts = []
    event_data = doc.get("event_data") or {}
    for key in ("input", "message", "url", "filename", "src_ip", "dst_ip"):
        val = event_data.get(key)
        if val:
            parts.append(str(val))
    if doc.get("message"):
        parts.append(str(doc["message"]))
    if doc.get("body"):
        parts.append(str(doc["body"]))
    return " ".join(parts)


def _session_id(doc: dict) -> str:
    """Bare session identifier (no honeypot prefix) — used by the session
    correlator, which keys on (honeypot, session_id) separately."""
    event_data = doc.get("event_data") or {}
    return event_data.get("session") or event_data.get("src_ip") or doc.get("src_ip") or "unknown"


def _session_key(doc: dict) -> str:
    honeypot = doc.get("honeypot", "unknown")
    return f"session:{honeypot}:{_session_id(doc)}"


def _src_ip(doc: dict) -> str | None:
    event_data = doc.get("event_data") or {}
    return event_data.get("src_ip") or event_data.get("src") or doc.get("src_ip")


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.es = AsyncElasticsearch(
        hosts=[ES_HOST],
        retry_on_timeout=True,
        max_retries=3,
        request_timeout=30,
    )
    app.state.redis = aioredis.Redis(
        host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD or None, decode_responses=True
    )
    app.state.http = httpx.AsyncClient(timeout=10.0)
    app.state.poll_task = asyncio.create_task(poll_loop(app))
    log.info("Telemetry service started. Polling %s every %ss", SOURCE_INDEX_PATTERN, POLL_INTERVAL)
    yield
    app.state.poll_task.cancel()
    try:
        await app.state.poll_task
    except asyncio.CancelledError:
        pass
    await app.state.es.close()
    await app.state.http.aclose()
    await app.state.redis.aclose()


app = FastAPI(title="Telemetry Layer", version="1.1.0", lifespan=lifespan)


class ManualIngest(BaseModel):
    honeypot: str
    text: str
    session: str | None = None
    src_ip: str | None = None


async def process_event(app: FastAPI, doc: dict) -> None:
    event_class = classify_event(doc)
    honeypot = doc.get("honeypot", "unknown")
    session_id = _session_id(doc)
    src_ip = _src_ip(doc)
    text_blob = _get_text_blob(doc)

    if event_class != "attack":
        # AUDIT FIX: infra/system noise still updates session bookkeeping
        # (so a session's duration/event count stays accurate) but never
        # generates IOCs, MITRE tags, or an escalation call.
        _state[f"{event_class}_events"] += 1
        if session_id and session_id != "unknown":
            await session_correlator.record_event(
                app, event_class=event_class, honeypot=honeypot, session_id=session_id,
                src_ip=src_ip, text_blob=text_blob, iocs=[], mitre=[],
            )
        _state["events_processed"] += 1
        return

    _state["attack_events"] += 1

    if not text_blob.strip():
        _state["events_processed"] += 1
        return

    iocs = extract_iocs_as_dicts(text_blob)
    mitre = map_command_as_dicts(text_blob)

    if iocs:
        _state["iocs_found"] += len(iocs)
        index_name = f"{IOC_INDEX_PREFIX}-{datetime.now(timezone.utc):%Y.%m.%d}"
        for ioc in iocs:
            ioc["timestamp"] = datetime.now(timezone.utc).isoformat()
            ioc["honeypot"] = honeypot
            ioc["mitre"] = mitre
            await app.state.es.index(index=index_name, document=ioc)

    # Track command sequence per session for the escalation engine's
    # sequence model (LSTM-style context window).
    sess_key = _session_key(doc)
    await app.state.redis.rpush(sess_key, text_blob[:500])
    await app.state.redis.ltrim(sess_key, -50, -1)  # keep last 50 commands
    await app.state.redis.expire(sess_key, SEQUENCE_TTL_SECONDS)
    sequence = await app.state.redis.lrange(sess_key, 0, -1)

    # Update the correlated session record with real evidence before we
    # know the escalation verdict; risk fields get patched in below.
    await session_correlator.record_event(
        app, event_class="attack", honeypot=honeypot, session_id=session_id,
        src_ip=src_ip, text_blob=text_blob, iocs=iocs, mitre=mitre,
    )

    # Forward to escalation engine for risk scoring.
    try:
        resp = await app.state.http.post(
            f"{ESCALATION_URL}/evaluate",
            json={
                "session_id": sess_key,
                "command": text_blob[:1000],
                "sequence": sequence,
                "mitre": mitre,
                "honeypot": honeypot,
            },
        )
        if resp.status_code == 200:
            result = resp.json()
            await session_correlator.update_risk(
                app, honeypot=honeypot, session_id=session_id,
                risk_score=result.get("risk_score", 0),
                decision=result.get("decision", "HOLD"),
                confidence=result.get("confidence"),
            )
            if result.get("decision") == "ESCALATE":
                _state["escalations"] += 1
                log.warning("ESCALATION for %s: %s", sess_key, result)
    except httpx.HTTPError as exc:
        log.error("Failed to reach escalation engine: %s", exc)

    _state["events_processed"] += 1


async def poll_loop(app: FastAPI) -> None:
    # FIX: initialise the cursor to "now" on first boot so we only process
    # events that arrive after this service started.  This prevents
    # reprocessing all historical data on every `docker compose down/up`.
    _state["last_timestamp"] = datetime.now(timezone.utc).isoformat()

    # Wait until ES is actually responding before issuing any queries.
    while True:
        try:
            await app.state.es.ping()
            log.info("Elasticsearch is reachable. Starting poll loop.")
            break
        except Exception:
            log.info("Waiting for Elasticsearch to be ready...")
            await asyncio.sleep(5)

    while True:
        try:
            await poll_once(app)
        except NotFoundError:
            log.info("No honeypot-* indices yet; waiting for first events.")
        except (ESConnectionError, Exception):
            log.exception("Poll cycle failed; will retry.")
        await asyncio.sleep(POLL_INTERVAL)


async def poll_once(app: FastAPI) -> None:
    # FIX: always use a range query on @timestamp so we never re-read
    # documents that were already processed (including all docs from before
    # this service started).
    query: dict = {
        "query": {"range": {"@timestamp": {"gt": _state["last_timestamp"]}}},
        "sort": [{"@timestamp": "asc"}],
        "size": 200,
    }

    result = await app.state.es.search(index=SOURCE_INDEX_PATTERN, body=query)
    hits = result.get("hits", {}).get("hits", [])
    for hit in hits:
        doc = hit["_source"]
        await process_event(app, doc)
        # FIX: only advance the cursor when @timestamp is actually present
        # in the document so we don't stall the cursor at None.
        ts = doc.get("@timestamp")
        if ts:
            _state["last_timestamp"] = ts


@app.get("/health")
async def health():
    return {"status": "ok", "service": "telemetry"}


@app.get("/stats")
async def stats():
    return _state


@app.post("/ingest")
async def manual_ingest(item: ManualIngest):
    """Test/manual ingestion path — useful for the attack simulation script
    without waiting on the full ES indexing pipeline."""
    doc = {
        "honeypot": item.honeypot,
        "event_data": {"input": item.text, "session": item.session, "src_ip": item.src_ip},
        "@timestamp": datetime.now(timezone.utc).isoformat(),
    }
    await process_event(app, doc)
    return {"status": "processed"}
